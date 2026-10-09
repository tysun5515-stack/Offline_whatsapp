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
            hostname = answer.get("name", "")
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
    job_id: Optional[str] = None,
) -> Tuple[Dict[str, Any], Any, List[Dict[str, Any]], Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]]:
    import os
    from src.flow_builder import rebuild_flows_stream
    
    stats = {
        'packet_count': 0, 'total_raw_packets': 0, 'flow_count': 0, 'whatsapp_flow_count': 0,
        'whatsapp_count': 0, 'detected_os': 'unknown', 'os_timeout_used': 'dynamic',
        'pass1_accepted': 0, 'pass2_dns_accepted': 0, 'rejected_no_signal': 0,
        'non_ip_count': 0, 'reconciliation_ok': True,
    }
    crypto_data_container = ([], [])
    flows_container = []
    
    def packet_generator():
        nonlocal stats
        dns_index = {}
        registry = ConfirmedServerRegistry(pcap_id=capture_id or os.path.basename(pcap_path))
        os_packets_sample = []
        os_hint = 'unknown'
        
        packet_no = 0
        def inner_stream():
            nonlocal packet_no, os_hint
            for ts, link, data in read_packets(pcap_path):
                packet_no += 1
                if job_id and packet_no % 100000 == 0:
                    try:
                        from src.webapp.job_queue import get_job_status, _write_job
                        job = get_job_status(job_id)
                        if job:
                            job['stats']['total_raw_packets'] = packet_no
                            job['stats']['packet_count'] = packet_no
                            _write_job(job_id, job)
                    except Exception:
                        pass
                try:
                    packet = parse_packet(packet_no, ts, link, data)
                except Exception as exc:
                    stats['parse_errors'] = stats.get('parse_errors', 0) + 1
                    if stats.get('parse_errors', 0) <= 5:
                        import logging
                        logging.warning(f"Frame {packet_no} parse error in {pcap_path}: {exc}")
                    continue
                    
                if not packet.get('src_ip'):
                    stats['non_ip_count'] += 1
                    if keep_all_traffic:
                        packet["protocol"] = packet.get("protocol") or "NON-IP"
                        packet["whatsapp_confidence"] = "unclassified"
                        packet["whatsapp_media_guess"] = "unclassified"
                        packet["sub_activity"] = "generic_network_traffic"
                        packet["sub_activity_source"] = None
                        packet["flow_id"] = None
                        stats['whatsapp_count'] += 1
                        yield packet
                    continue
                    
                if packet_no < 50000:
                    os_packets_sample.append(packet)
                elif packet_no == 50000:
                    os_hint, os_conf = detect_os_hint(os_packets_sample)
                    stats['detected_os'] = f"{os_hint} — {os_conf} confidence" if os_hint != 'unknown' else "unknown"
                    
                for answer in packet.get("dns_answers", []):
                    hostname = answer.get("name", "")
                    if any(_domain_matches_suffix(hostname, suffix) for suffix in STRONG_DOMAINS):
                        if answer.get("type") in (1, 28):
                            dns_index.setdefault(answer["value"], []).append({"hostname": hostname, "response_time": ts, "expires_at": ts + answer["ttl"]})
                
                yield packet
                
        for flow in rebuild_flows_stream(inner_stream(), pcap_id=capture_id or os.path.basename(pcap_path), burst_threshold=1.0, os_hint=os_hint, explicit_subscriber_ips=explicit_subscriber_ips):
            stats['flow_count'] += 1
            
            sni, dns = None, None
            for p in flow["packets"]:
                if p.get("sni"): sni = p["sni"]
                if p.get("dns_query"): dns = p["dns_query"]
                
            conf_domain, sig_domain, sub_activity_domain = check_domain_matching(sni, dns)
            conf_cidr, sig_cidr, matched_meta_ip = _check_flow_cidr_matching(flow)
            inference_ip = matched_meta_ip or flow["server_ip"]
            conf_port, sig_port, port_activity = check_port_matching(flow["server_port"], flow["protocol_type"])
            
            dns_correlation = _flow_dns_correlation(flow, dns_index)
            if dns_correlation:
                sig_dns_correlation = ["dns_correlated_whatsapp"]
            else:
                sig_dns_correlation = []
                
            conf_inf, sig_inf = check_inference_matching(inference_ip, registry)
            signals = sig_domain + sig_cidr + sig_inf + sig_port + sig_dns_correlation
            
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
            
            flow["sub_activity"] = sub_activity_domain or port_activity
            flow["sni_sub_activity"] = sub_activity_domain
            flow["port_activity"] = port_activity
            
            flow_duration = (flow.get("last_seen", 0) - flow.get("first_seen", 0)) or 1.0
            cidr_confirmed = (conf_cidr == "high")
            
            if is_whatsapp_anchored(sub_activity_domain, port_activity, cidr_confirmed):
                flow["media_type"] = guess_media_type(flow["packets"], flow["protocol_type"], flow_duration, sni_sub_activity=sub_activity_domain, port_activity=port_activity, cidr_confirmed=cidr_confirmed, client_ip=flow.get('client_ip'))
            else:
                flow["media_type"] = "unclassified"
                
            is_wa_flow = flow["whatsapp_confidence"] in ["high", "medium", "infrastructure"]
            
            if keep_all_traffic or is_wa_flow:
                if is_wa_flow:
                    stats['whatsapp_flow_count'] += 1
                    
                labels = resolve_activity_labels(sub_activity_domain, port_activity, flow["protocol_type"], media_guess=flow.get("media_type"))
                final_media_guess = resolve_final_label(flow["media_type"], port_activity, flow["protocol_type"], sni_sub_activity=sub_activity_domain)
                display_activity = labels.get("display_activity")
                
                if port_activity == "dns_resolution":
                    dns_queries = [p["dns_query"] for p in flow["packets"] if p.get("dns_query")]
                    wa_queries = [q for q in dns_queries if any(_domain_matches_suffix(q, d) for d in STRONG_DOMAINS)]
                    if not wa_queries and not keep_all_traffic:
                        continue
                    display_activity = f"dns→{wa_queries[0]}" if wa_queries else "dns_resolution"
                    
                if display_activity == "call_media_candidate":
                    display_activity = "call_signaling"
                if final_media_guess == "call_media_candidate":
                    final_media_guess = "call_signaling"
                    
                emitted_packets = []
                _emit_flow_packets(flow, emitted_packets, keep_all_traffic, labels, final_media_guess, display_activity)
                stats['whatsapp_count'] += len(emitted_packets)
                stats['pass1_accepted'] += len(emitted_packets)
                for p in emitted_packets:
                    yield p
                    
                try:
                    from src.tls_crypto_analyzer import extract_crypto_flows
                    c_flows, c_events = extract_crypto_flows([flow], upload_id=capture_id or os.path.basename(pcap_path))
                    crypto_data_container[0].extend(c_flows)
                    crypto_data_container[1].extend(c_events)
                except Exception:
                    pass
                
        stats['packet_count'] = packet_no
        stats['total_raw_packets'] = packet_no

    return stats, packet_generator(), flows_container, crypto_data_container

def run_pipeline(pcap_path, output_dir):
    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        stats, all_whatsapp_packets, flows, crypto_data = process_pcap_to_whatsapp_packets(pcap_path)
        all_packets_list = list(all_whatsapp_packets)
        
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
