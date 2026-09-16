"""
flow_builder.py: Reconstructs network flows from packet records and calculates flow summary statistics.

Fix log (this revision):
  1. Flow-inactivity timeout is now resolved per-flow via
     whatsapp_filter.resolve_timeout(os_hint, is_media_flow), not a single
     hardcoded 120s applied to every flow regardless of OS or media type.
  2. `is_media_flow` is inferred from the flow's server-side port.
  3. Added `session_start_confirmed`: True only if the flow's first
     captured packet looks like a genuine session start.
  4. burst_count now comes from the SAME extract_bursts() function
     that whatsapp_filter.py uses (via traffic_utils.py).
"""

import ipaddress
from typing import Any, Dict, List, Optional, Tuple

from src import whatsapp_filter as wf
from src.traffic_utils import extract_bursts, extract_bursts_with_duration
from src.os_fingerprint import detect_os_hint


def is_private(ip_str: Optional[str]) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except (ValueError, TypeError):
        return False


def _looks_like_session_start(packet: Dict[str, Any]) -> bool:
    """True if this packet looks like a genuine session-start artifact."""
    flags = packet.get("tcp_udp_flags") or ""
    is_bare_syn = "SYN" in flags and "ACK" not in flags
    has_sni = bool(packet.get("sni"))
    return is_bare_syn or has_sni


def create_new_flow(packet: Dict[str, Any], key: Tuple) -> Dict[str, Any]:
    """Helper to initialize a new active flow dictionary."""
    src_ip = packet["src_ip"]
    dst_ip = packet["dst_ip"]
    src_port = packet["src_port"]
    dst_port = packet["dst_port"]

    if is_private(src_ip) and not is_private(dst_ip):
        client_ip, server_ip = src_ip, dst_ip
        client_port, server_port = src_port, dst_port
    elif not is_private(src_ip) and is_private(dst_ip):
        client_ip, server_ip = dst_ip, src_ip
        client_port, server_port = dst_port, src_port
    else:
        client_ip, server_ip = src_ip, dst_ip
        client_port, server_port = src_port, dst_port

    return {
        "key": key,
        "client_ip": client_ip,
        "client_port": client_port,
        "server_ip": server_ip,
        "server_port": server_port,
        "protocol_type": packet["protocol"],
        "start_time": packet["timestamp"],
        "session_start_confirmed": _looks_like_session_start(packet),
        "packets": [packet],
    }


def _is_media_flow(server_port: Optional[int]) -> bool:
    """Port-based heuristic for whether a flow is media traffic."""
    if server_port in wf.WHATSAPP_MEDIA_PORTS:
        return True
    return False


def rebuild_flows(
    packet_records: List[Dict[str, Any]],
    pcap_id: str,
    burst_threshold: float = 1.0,
    os_hint: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Groups packet records into flows and computes statistics.
    """
    ip_packets = [p for p in packet_records if p["src_ip"] is not None and p["dst_ip"] is not None]
    ip_packets.sort(key=lambda x: x["timestamp"])

    if os_hint is None:
        os_hint, _ = detect_os_hint(ip_packets)

    active_flows: Dict[Tuple, Dict[str, Any]] = {}
    completed_flows: List[Dict[str, Any]] = []

    for packet in ip_packets:
        src_ip = packet["src_ip"]
        dst_ip = packet["dst_ip"]
        src_port = packet["src_port"]
        dst_port = packet["dst_port"]
        protocol = packet["protocol"]

        # Bug 13 fix: coalesce None ports to 0 so tuple comparison never raises
        # TypeError on non-TCP/UDP traffic (ICMP, IGMP, etc.) where ports are None.
        if (src_ip, src_port or 0) < (dst_ip, dst_port or 0):
            key = (src_ip, src_port, dst_ip, dst_port, protocol)
        else:
            key = (dst_ip, dst_port, src_ip, src_port, protocol)

        if key in active_flows:
            flow = active_flows[key]
            last_pkt = flow["packets"][-1]
            gap = packet["timestamp"] - last_pkt["timestamp"]

            # Per-flow, media-aware, OS-aware timeout
            is_media = _is_media_flow(flow["server_port"])
            timeout = wf.resolve_timeout(os_hint, is_media_flow=is_media)

            if gap > timeout:
                completed_flows.append(flow)
                new_flow = create_new_flow(packet, key)
                active_flows[key] = new_flow
            else:
                flow["packets"].append(packet)
        else:
            new_flow = create_new_flow(packet, key)
            active_flows[key] = new_flow

    completed_flows.extend(active_flows.values())
    completed_flows.sort(key=lambda x: x["start_time"])

    for idx, flow in enumerate(completed_flows, start=1):
        packets = flow["packets"]
        packet_count = len(packets)

        # Bug 1 fix: compute first_seen, last_seen, duration_s from packet timestamps
        # so that pipeline.py gets accurate flow_duration (was always 1.0s before).
        timestamps = [p["timestamp"] for p in packets if p.get("timestamp") is not None]
        first_seen = min(timestamps) if timestamps else 0.0
        last_seen = max(timestamps) if timestamps else 0.0
        duration_s = max(0.0, last_seen - first_seen)

        # Statistics computation
        lengths = [p["length"] for p in packets]
        flow.update({
            "flow_id": idx,
            "pcap_id": pcap_id,
            "packet_count": packet_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "duration_s": duration_s,
            "average_packet_size": sum(lengths) / packet_count if packet_count > 0 else 0.0,
            "maximum_packet_size": max(lengths) if packet_count > 0 else 0,
            "minimum_packet_size": min(lengths) if packet_count > 0 else 0,
        })

        flow["burst_count"] = len(extract_bursts(packets, threshold=burst_threshold))

    return completed_flows
