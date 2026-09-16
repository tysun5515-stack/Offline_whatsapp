import sys
import os
import csv
import argparse
from typing import List, Dict, Any, Tuple

# Ensure src is in the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.pcap_reader import read_packets
from src.packet_parser import parse_packet
from src.flow_builder import rebuild_flows
from src.whatsapp_filter import (
    check_domain_matching, check_cidr_matching, 
    check_inference_matching, check_port_matching,
    guess_media_type, resolve_timeout, ConfirmedServerRegistry,
    resolve_activity_labels, resolve_final_label
)
from src.os_fingerprint import detect_os_hint, OS_TIMEOUTS


def process_pcap_to_whatsapp_packets(
    pcap_path: str,
    keep_all_traffic: bool = False,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Runs the core parsing and filtering pipeline.
    Returns (stats_dict, all_classified_packets, all_flows).
    Designed to be called by the forensic web UI.
    """
    # 1. Parse packets
    packet_records = []
    packet_no = 0
    for ts, link, data in read_packets(pcap_path):
        packet_no += 1
        packet_records.append(parse_packet(packet_no, ts, link, data))
        
    # 2. OS Fingerprinting & OS-aware flow building
    os_hint, os_conf = detect_os_hint(packet_records)
    detected_os = f"{os_hint} — {os_conf} confidence" if os_hint != 'unknown' else "unknown"
    
    # New signature: rebuild_flows(packet_records, pcap_id, burst_threshold, os_hint)
    flows = rebuild_flows(
        packet_records, 
        pcap_id=os.path.basename(pcap_path),
        os_hint=os_hint,
        burst_threshold=1.0
    )
    
    # 3. Classify flows using the established evidence rules.
    registry = ConfirmedServerRegistry(pcap_id=os.path.basename(pcap_path))
    all_whatsapp_packets = []
    whatsapp_flow_count = 0
    
    for flow in flows:
        sni, dns = None, None
        for p in flow["packets"]:
            if p.get("sni"): sni = p["sni"]
            if p.get("dns_query"): dns = p["dns_query"]
            
        conf_domain, sig_domain, sub_activity_domain = check_domain_matching(sni, dns)
        conf_cidr, sig_cidr = check_cidr_matching(flow["server_ip"])
        conf_inf, sig_inf = check_inference_matching(flow["server_ip"], registry)
        conf_port, sig_port, port_activity = check_port_matching(flow["client_port"], flow["server_port"])
        
        signals = sig_domain + sig_cidr + sig_inf + sig_port
        
        # High confidence triggers
        if conf_domain == "high" or conf_cidr == "high" or conf_port == "high":
            flow["whatsapp_confidence"] = "high"
            registry.seed(flow["server_ip"])
        elif conf_domain == "low" or conf_inf == "medium" or conf_port == "medium":
            flow["whatsapp_confidence"] = "medium"
        else:
            flow["whatsapp_confidence"] = "none"
            
        flow["whatsapp_signals"] = ",".join(signals)
        
        # Sub-activity (prioritize domain over port)
        flow["sub_activity"] = sub_activity_domain or port_activity
        
        # Sub-classify media type with burst-aware logic
        flow_duration = (flow.get("last_seen", 0) - flow.get("first_seen", 0)) or 1.0
        cidr_confirmed = (conf_cidr == "high")
        flow["media_type"] = guess_media_type(
            flow["packets"], 
            flow["protocol_type"], 
            flow_duration,
            sni_sub_activity=sub_activity_domain,
            port_activity=port_activity,
            cidr_confirmed=cidr_confirmed
        )
        
        # Extract packets
        is_wa_flow = flow["whatsapp_confidence"] in ["high", "medium", "infrastructure"]
        if keep_all_traffic or is_wa_flow:
            whatsapp_flow_count += 1
            
            labels = resolve_activity_labels(sub_activity_domain, port_activity, flow["protocol_type"])
            
            final_media_guess = resolve_final_label(
                flow["media_type"], 
                port_activity, 
                flow["protocol_type"]
            )
            
            display_activity = labels.get("display_activity")
            if port_activity == "dns_resolution":
                dns_queries = [p["dns_query"] for p in flow["packets"] if p.get("dns_query")]
                from src.whatsapp_filter import STRONG_DOMAINS, _domain_matches_suffix
                wa_queries = [q for q in dns_queries if any(_domain_matches_suffix(q, d) for d in STRONG_DOMAINS)]
                display_activity = f"dns→{wa_queries[0]}" if wa_queries else "dns_resolution"
            
            for p in flow["packets"]:
                # Bypass retains non-WhatsApp traffic for manual review.  It must
                # not inherit labels produced by WA-only heuristics (ports,
                # bitrate, SNI inference, etc.).  Positively matched WA flows
                # keep their normal classification.
                if keep_all_traffic and not is_wa_flow:
                    p["whatsapp_confidence"] = "unclassified"
                    p["whatsapp_media_guess"] = "unclassified"
                    p["sub_activity"] = "generic_network_traffic"
                else:
                    p["whatsapp_confidence"] = flow["whatsapp_confidence"]
                    p["whatsapp_media_guess"] = final_media_guess
                    p["sub_activity"] = display_activity
                p["sub_activity_source"] = labels.get("display_activity_source")
                # DNS/infrastructure presentation is a WA pipeline concept;
                # never promote a bypass-retained, non-WA flow to it.
                if labels.get("is_infrastructure") and is_wa_flow:
                    p["is_infrastructure"] = True
                    p["whatsapp_confidence"] = "infrastructure"
                p["flow_id"] = str(flow["flow_id"])
                all_whatsapp_packets.append(p)

    # Flow reconstruction intentionally accepts only packets with an IP
    # source and destination.  In bypass mode that must not silently discard
    # ARP, malformed, unsupported-link, or other non-IP frames: retain them
    # as generic records for packet-level manual review.
    if keep_all_traffic:
        for packet in packet_records:
            if packet.get("src_ip") is not None and packet.get("dst_ip") is not None:
                continue
            packet["protocol"] = packet.get("protocol") or "NON-IP"
            packet["whatsapp_confidence"] = "unclassified"
            packet["whatsapp_media_guess"] = "unclassified"
            packet["sub_activity"] = "generic_network_traffic"
            packet["sub_activity_source"] = None
            packet["flow_id"] = None
            all_whatsapp_packets.append(packet)
                
    stats = {
        'packet_count': len(packet_records),
        'total_raw_packets': len(packet_records),
        'flow_count': len(flows),
        'whatsapp_flow_count': whatsapp_flow_count,
        # In bypass mode: whatsapp_count = all retained packets (all of them)
        # In normal mode: whatsapp_count = only WA-classified packets
        'whatsapp_count': len(all_whatsapp_packets),
        'detected_os': detected_os,
        'os_timeout_used': 'dynamic',
    }
    
    return stats, all_whatsapp_packets, flows


def run_pipeline(pcap_path, output_dir):
    """Legacy CLI pipeline entry point."""
    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        stats, all_whatsapp_packets, flows = process_pcap_to_whatsapp_packets(pcap_path)
        
        # We don't save CSVs or write to old DB in the new architecture,
        # but for legacy compatibility we can just print stats.
        print(f"Pipeline complete. Parsed {stats['packet_count']} packets -> {stats['flow_count']} flows.")
        print(f"Detected OS: {stats['detected_os']} (Timeout: {stats['os_timeout_used']}s)")
        print(f"Found {stats['whatsapp_count']} WhatsApp packets.")
        
    except Exception as e:
        print(f"Error processing {pcap_path}: {e}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WhatsApp Traffic Analysis Pipeline")
    parser.add_argument("pcap_file", help="Path to the input PCAP file")
    parser.add_argument("output_dir", nargs='?', default="results", help="Directory for CSV outputs (Legacy)")
    args = parser.parse_args()
    
    run_pipeline(args.pcap_file, args.output_dir)
