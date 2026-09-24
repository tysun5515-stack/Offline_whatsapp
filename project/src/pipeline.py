import sys
import os
import csv
import argparse
from typing import List, Dict, Any, Tuple, Optional

# Ensure src is in the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.pcap_reader import read_packets
from src.packet_parser import parse_packet
from src.flow_builder import rebuild_flows
from src.whatsapp_filter import (
    check_domain_matching, check_cidr_matching, 
    check_inference_matching, check_port_matching,
    guess_media_type, resolve_timeout, ConfirmedServerRegistry,
    resolve_activity_labels, resolve_final_label, STRONG_DOMAINS,
    _domain_matches_suffix, is_whatsapp_anchored,
)
from src.os_fingerprint import detect_os_hint, OS_TIMEOUTS


def _check_flow_cidr_matching(flow: Dict[str, Any]) -> Tuple[str, List[str], Any]:
    """Match both endpoints so a role-inference failure cannot hide a Meta peer."""
    for endpoint in (flow.get("server_ip"), flow.get("client_ip")):
        confidence, signals = check_cidr_matching(endpoint)
        if confidence == "high":
            return confidence, signals, endpoint
    return "none", [], None

def _dns_correlation_index(records: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    index: Dict[str, List[Dict[str, Any]]] = {}
    for packet in records:
        timestamp = packet.get("timestamp")
        for answer in packet.get("dns_answers", []):
            hostname = answer.get("question", "")
            if timestamp is None or not any(_domain_matches_suffix(hostname, suffix) for suffix in STRONG_DOMAINS):
                continue
            if answer.get("type") in (1, 28):
                index.setdefault(answer["value"], []).append({"hostname": hostname, "response_time": timestamp, "expires_at": timestamp + answer["ttl"]})
    return index


CLOCK_SKEW_TOLERANCE_S = 5.0

def _flow_dns_correlation(flow: Dict[str, Any], index: Dict[str, List[Dict[str, Any]]]) -> Any:
    for endpoint in (flow.get("server_ip"), flow.get("client_ip")):
        for record in index.get(endpoint, []):
            if (record["response_time"] - CLOCK_SKEW_TOLERANCE_S <= flow.get("first_seen", 0) <= record["expires_at"]):
                return {**record, "ip": endpoint}
    return None

def _emit_flow_packets(
    flow: Dict[str, Any],
    all_whatsapp_packets: List[Dict[str, Any]],
    keep_all_traffic: bool,
    labels: Dict[str, Any],
    final_media_guess: str,
    display_activity: Optional[str]
) -> None:
    is_wa_flow = flow.get("whatsapp_confidence") in ["high", "medium", "infrastructure"]
    for p in flow["packets"]:
        if keep_all_traffic and not is_wa_flow:
            p["whatsapp_confidence"] = "unclassified"
            p["whatsapp_media_guess"] = "unclassified"
            p["sub_activity"] = "generic_network_traffic"
        else:
            p["whatsapp_confidence"] = flow.get("whatsapp_confidence")
            p["whatsapp_media_guess"] = final_media_guess
            p["sub_activity"] = display_activity
        p["sub_activity_source"] = labels.get("display_activity_source")
        p["endpoint_role_source"] = flow.get("endpoint_role_source")
        p["matched_meta_ip"] = flow.get("matched_meta_ip")
        p["whatsapp_signals"] = flow.get("whatsapp_signals")
        p["acceptance_reason"] = flow.get("acceptance_reason")
        if flow.get("dns_correlation"):
            p["dns_correlated_hostname"] = flow["dns_correlation"]["hostname"]
            p["dns_correlated_ip"] = flow["dns_correlation"]["ip"]
            p["dns_response_timestamp"] = flow["dns_correlation"]["response_time"]
            p["dns_expires_at"] = flow["dns_correlation"]["expires_at"]
        if labels.get("is_infrastructure") and is_wa_flow:
            p["is_infrastructure"] = True
            p["whatsapp_confidence"] = "infrastructure"
        p["tls_cipher_suite"] = p.get("tls_cipher_suite")
        p["tls_crypto_info"] = p.get("tls_crypto_info")
        p["quic_version"] = p.get("quic_version")
        p["flow_id"] = str(flow["flow_id"])
        p["flow_instance"] = flow.get("flow_instance")
        p["capture_id"] = flow.get("pcap_id")
        p["endpoint_a_ip"] = flow.get("endpoint_a_ip")
        p["endpoint_a_port"] = flow.get("endpoint_a_port")
        p["endpoint_b_ip"] = flow.get("endpoint_b_ip")
        p["endpoint_b_port"] = flow.get("endpoint_b_port")
        p["local_subscriber_ip"] = flow.get("local_subscriber_ip")
        p["subscriber_resolution_source"] = flow.get("subscriber_resolution_source")
        p["subscriber_resolution_confidence"] = flow.get("subscriber_resolution_confidence")
        p["session_start_confirmed"] = flow.get("session_start_confirmed", False)
        all_whatsapp_packets.append(p)

def process_pcap_to_whatsapp_packets(
    pcap_path: str,
    keep_all_traffic: bool = False,
    capture_id: Optional[str] = None,
    explicit_subscriber_ips: Optional[List[str]] = None,
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
        try:
            packet_records.append(parse_packet(packet_no, ts, link, data))
        except Exception as e:
            # Error isolation: bad frame doesn't crash batch
            continue
        
    # 2. OS Fingerprinting & OS-aware flow building
    os_hint, os_conf = detect_os_hint(packet_records)
    detected_os = f"{os_hint} — {os_conf} confidence" if os_hint != 'unknown' else "unknown"
    
    # New signature: rebuild_flows(packet_records, pcap_id, burst_threshold, os_hint)
    flows = rebuild_flows(
        packet_records, 
        pcap_id=capture_id or os.path.basename(pcap_path),
        os_hint=os_hint,
        burst_threshold=1.0,
        explicit_subscriber_ips=explicit_subscriber_ips,
    )
    
    # 3. Classify flows using the established evidence rules.
    dns_index = _dns_correlation_index(packet_records)
    registry = ConfirmedServerRegistry(pcap_id=os.path.basename(pcap_path))
    all_whatsapp_packets = []
    whatsapp_flow_count = 0
    
    # PASS 1 (Reverification Step): Seed the registry with high-confidence matches
    for flow in flows:
        sni, dns = None, None
        for p in flow["packets"]:
            if p.get("sni"): sni = p["sni"]
            if p.get("dns_query"): dns = p["dns_query"]
            
        conf_domain, sig_domain, sub_activity_domain = check_domain_matching(sni, dns)
        conf_cidr, sig_cidr, matched_meta_ip = _check_flow_cidr_matching(flow)
        inference_ip = matched_meta_ip or flow["server_ip"]
        conf_port, sig_port, port_activity = check_port_matching(flow["server_port"], flow["protocol_type"])
        
        dns_correlation = _flow_dns_correlation(flow, dns_index)
        
        # High confidence triggers seed the registry
        if conf_domain == "high" or conf_cidr == "high" or conf_port == "high" or dns_correlation:
            registry.seed(inference_ip)
    all_whatsapp_packets = []
    whatsapp_flow_count = 0
    
    # PASS 2: Re-evaluate and extract all packets using fully seeded registry
    for flow in flows:
        sni, dns = None, None
        for p in flow["packets"]:
            if p.get("sni"): sni = p["sni"]
            if p.get("dns_query"): dns = p["dns_query"]
            
        conf_domain, sig_domain, sub_activity_domain = check_domain_matching(sni, dns)
        conf_cidr, sig_cidr, matched_meta_ip = _check_flow_cidr_matching(flow)
        inference_ip = matched_meta_ip or flow["server_ip"]
        conf_inf, sig_inf = check_inference_matching(inference_ip, registry)
        conf_port, sig_port, port_activity = check_port_matching(flow["server_port"], flow["protocol_type"])
        
        dns_correlation = _flow_dns_correlation(flow, dns_index)
        sig_dns_correlation = ["dns_correlated_whatsapp"] if dns_correlation else []
        signals = sig_domain + sig_cidr + sig_inf + sig_port + sig_dns_correlation
        
        # High confidence triggers
        if conf_domain == "high" or conf_cidr == "high" or conf_port == "high" or dns_correlation:
            flow["whatsapp_confidence"] = "high"
            registry.seed(inference_ip)
        elif conf_domain == "low" or conf_inf == "medium" or conf_port == "medium":
            flow["whatsapp_confidence"] = "medium"
        else:
            flow["whatsapp_confidence"] = "none"
            
        flow["whatsapp_signals"] = ",".join(signals)
        flow["matched_meta_ip"] = matched_meta_ip
        flow["dns_correlation"] = dns_correlation
        flow["acceptance_reason"] = "dns_correlated_whatsapp" if dns_correlation else ("cidr_strong" if conf_cidr == "high" else ("domain_strong" if conf_domain == "high" else ("port_strong" if conf_port == "high" else ("corroborating_signal" if flow["whatsapp_confidence"] == "medium" else "no_whatsapp_signal"))))

        
        # Sub-activity (prioritize domain over port)
        flow["sub_activity"] = sub_activity_domain or port_activity
        flow["sni_sub_activity"] = sub_activity_domain
        flow["port_activity"] = port_activity
        
        # Sub-classify media type with burst-aware logic.
        # Acceptance gate (Fix 6): only run guess_media_type() for flows
        # with a verified WhatsApp anchor. Unanchored flows are tagged
        # 'unclassified' without reaching the media-guessing layer.
        flow_duration = (flow.get("last_seen", 0) - flow.get("first_seen", 0)) or 1.0
        cidr_confirmed = (conf_cidr == "high")

        if is_whatsapp_anchored(sub_activity_domain, port_activity, cidr_confirmed):
            flow["media_type"] = guess_media_type(
                flow["packets"],
                flow["protocol_type"],
                flow_duration,
                sni_sub_activity=sub_activity_domain,
                port_activity=port_activity,
                cidr_confirmed=cidr_confirmed
            )
        else:
            flow["media_type"] = "unclassified"
        
        # Extract packets
        is_wa_flow = flow["whatsapp_confidence"] in ["high", "medium", "infrastructure"]
        if keep_all_traffic or is_wa_flow:
            whatsapp_flow_count += 1
            
            labels = resolve_activity_labels(sub_activity_domain, port_activity, flow["protocol_type"])
            
            # Fix F: pass sni_sub_activity so resolve_final_label can
            # correctly handle xmpp_multiplex flows that have SNI decoration.
            final_media_guess = resolve_final_label(
                flow["media_type"],
                port_activity,
                flow["protocol_type"],
                sni_sub_activity=sub_activity_domain,
            )
            
            display_activity = labels.get("display_activity")

            # Fix E: DNS flows emitted ONLY if they contain a WhatsApp domain
            # query. Non-WhatsApp DNS (Google, Apple, etc.) is not WA evidence.
            if port_activity == "dns_resolution":
                dns_queries = [p["dns_query"] for p in flow["packets"] if p.get("dns_query")]
                wa_queries = [q for q in dns_queries
                              if any(_domain_matches_suffix(q, d) for d in STRONG_DOMAINS)]
                if not wa_queries and not keep_all_traffic:
                    # Not a WhatsApp DNS query — skip emission entirely
                    continue
                display_activity = f"dns→{wa_queries[0]}" if wa_queries else "dns_resolution"

            # Fix H: strip transient internal state labels before DB write.
            # 'call_media_candidate' is a port-heuristic hint, not a
            # classification verdict. Analysts must never see it in reports.
            if display_activity == "call_media_candidate":
                display_activity = "call_signaling"
            if final_media_guess == "call_media_candidate":
                final_media_guess = "call_signaling"
            
            _emit_flow_packets(
                flow,
                all_whatsapp_packets,
                keep_all_traffic,
                labels,
                final_media_guess,
                display_activity
            )
    pass1_accepted_count = len(all_whatsapp_packets)
    
    # PASS 2: DNS rescue sweep — only for flows rejected in Pass 1
    rejected_flows = [f for f in flows if f.get("whatsapp_confidence") == "none"]
    for flow in rejected_flows:
        dns_correlation = _flow_dns_correlation(flow, dns_index)
        if not dns_correlation:
            continue
            
        flow["whatsapp_confidence"] = "high"
        flow["whatsapp_signals"] = "dns_correlated_whatsapp"
        flow["acceptance_reason"] = "dns_correlated_whatsapp_pass2"
        flow["dns_correlation"] = dns_correlation
        
        whatsapp_flow_count += 1
        
        labels = resolve_activity_labels(flow.get("sni_sub_activity"), flow.get("port_activity"), flow["protocol_type"])
        final_media_guess = resolve_final_label(flow.get("media_type"), flow.get("port_activity"), flow["protocol_type"])
        display_activity = labels.get("display_activity")
        
        _emit_flow_packets(
            flow,
            all_whatsapp_packets,
            keep_all_traffic,
            labels,
            final_media_guess,
            display_activity
        )
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
                
    pass2_accepted_count = len(all_whatsapp_packets) - pass1_accepted_count
    
    non_ip_count = len(packet_records) - len([p for p in packet_records if p.get("src_ip") is not None and p.get("dst_ip") is not None])
    ip_packets_with_no_flow = len(packet_records) - non_ip_count - sum(len(f["packets"]) for f in flows)
    
    rejected_no_signal_count = len(packet_records) - len(all_whatsapp_packets) - non_ip_count - ip_packets_with_no_flow
    reconciliation_ok = (pass1_accepted_count + pass2_accepted_count + rejected_no_signal_count + non_ip_count + ip_packets_with_no_flow == len(packet_records))
    
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
        'pass1_accepted': pass1_accepted_count,
        'pass2_dns_accepted': pass2_accepted_count,
        'rejected_no_signal': rejected_no_signal_count,
        'non_ip_count': non_ip_count,
        'reconciliation_ok': reconciliation_ok,
    }
    
    return stats, all_whatsapp_packets, flows


def run_pipeline(pcap_path, output_dir):
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
