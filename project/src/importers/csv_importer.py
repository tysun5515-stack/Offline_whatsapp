import csv
import os
from typing import Tuple, Dict, Any, List
from src.pipeline import rebuild_flows

def process_csv_to_whatsapp_packets(csv_path: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    packet_records = []
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = 0.0
            if 'Time' in row:
                try:
                    ts = float(row['Time'])
                except ValueError:
                    pass
            
            record = {
                "packet_no": int(row.get('No.', 0) or 0),
                "timestamp": ts,
                "src_ip": row.get('Source') or row.get('src_ip') or '',
                "dst_ip": row.get('Destination') or row.get('dst_ip') or '',
                "src_port": int(row.get('Source Port') or row.get('src_port') or row.get('Sport') or 0),
                "dst_port": int(row.get('Destination Port') or row.get('dst_port') or row.get('Dport') or 0),
                "protocol": row.get('Protocol'),
                "length": int(row.get('Length', 0) or 0),
                "tcp_udp_flags": None,
                "is_tls": False,
                "is_quic": False,
                "dns_query": None,
                "sni": None,
                "direction": None,
                "ip_ttl": None,
                "is_stun_binding": False,
                "stun_mapped_address": None,
                "tcp_window_size": None
            }
            packet_records.append(record)
            
    os_hint = "unknown"
    
    flows = rebuild_flows(
        packet_records,
        pcap_id=os.path.basename(csv_path),
        os_hint=os_hint,
        burst_threshold=1.0
    )
    
    # Bug 6 fix: Enrich CSV packets with classification fields so insert succeeds
    for flow in flows:
        for p in flow["packets"]:
            p["whatsapp_confidence"] = "imported"
            p["whatsapp_media_guess"] = "unknown"
            p["sub_activity"] = "imported_csv"
            p["flow_id"] = str(flow.get("flow_id", ""))
            
    # Also enrich any packets that didn't make it into a flow
    for p in packet_records:
        if "whatsapp_confidence" not in p:
            p["whatsapp_confidence"] = "imported"
            p["whatsapp_media_guess"] = "unknown"
            p["sub_activity"] = "imported_csv"
            p["flow_id"] = ""

    stats = {
        'packet_count': len(packet_records),
        'flow_count': len(flows),
        'whatsapp_count': len(packet_records),
        'detected_os': os_hint
    }
    
    return stats, packet_records, flows
