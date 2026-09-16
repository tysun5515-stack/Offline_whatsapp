import json
import os
from typing import Tuple, Dict, Any, List
from src.pipeline import rebuild_flows

def process_json_to_whatsapp_packets(json_path: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Bug 6 fix: Support wrapped dictionary JSON formats (e.g. {"packets": [...]})
    if isinstance(data, dict):
        if "packets" in data:
            packet_records = data["packets"]
        elif "data" in data:
            packet_records = data["data"]
        else:
            packet_records = [data]
    else:
        packet_records = data
    
    os_hint = "unknown"
    
    flows = rebuild_flows(
        packet_records,
        pcap_id=os.path.basename(json_path),
        os_hint=os_hint,
        burst_threshold=1.0
    )
    
    # Bug 6 fix: Enrich packets with classification fields so insert succeeds
    for flow in flows:
        for p in flow["packets"]:
            if "whatsapp_confidence" not in p:
                p["whatsapp_confidence"] = "imported"
            if "whatsapp_media_guess" not in p:
                p["whatsapp_media_guess"] = "unknown"
            if "sub_activity" not in p:
                p["sub_activity"] = "imported_json"
            p["flow_id"] = str(flow.get("flow_id", ""))
            
    # Also enrich any packets that didn't make it into a flow
    for p in packet_records:
        if "whatsapp_confidence" not in p:
            p["whatsapp_confidence"] = "imported"
            p["whatsapp_media_guess"] = "unknown"
            p["sub_activity"] = "imported_json"
            p["flow_id"] = ""

    stats = {
        'packet_count': len(packet_records),
        'flow_count': len(flows),
        'whatsapp_count': len(packet_records),
        'detected_os': os_hint
    }
    
    return stats, packet_records, flows
