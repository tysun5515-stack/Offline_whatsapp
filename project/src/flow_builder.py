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

import hashlib
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


def _endpoint_sort_key(endpoint: Tuple[str, Optional[int]]) -> Tuple[int, int, int]:
    """Stable numeric ordering for IPv4/IPv6 endpoints."""
    ip_str, port = endpoint
    ip_obj = ipaddress.ip_address(ip_str)
    return ip_obj.version, int(ip_obj), int(port or 0)


def canonical_endpoints(packet: Dict[str, Any]) -> Tuple[Tuple[str, Optional[int]], Tuple[str, Optional[int]]]:
    """Return a direction-independent endpoint pair for an IP packet."""
    endpoints = [
        (packet["src_ip"], packet.get("src_port")),
        (packet["dst_ip"], packet.get("dst_port")),
    ]
    endpoints.sort(key=_endpoint_sort_key)
    return endpoints[0], endpoints[1]


def _is_cgnat(ip_str: Optional[str]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.version == 4 and ip_obj in ipaddress.ip_network("100.64.0.0/10")
    except (ValueError, TypeError):
        return False


def _is_local_scope(ip_str: Optional[str]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or _is_cgnat(ip_str)
    except (ValueError, TypeError):
        return False


def _looks_like_session_start(packet: Dict[str, Any]) -> bool:
    """True if this packet looks like a genuine session-start artifact."""
    flags = packet.get("tcp_udp_flags") or ""
    is_bare_syn = "SYN" in flags and "ACK" not in flags
    has_sni = bool(packet.get("sni"))
    return is_bare_syn or has_sni


def _is_meta_endpoint(ip_str: Optional[str]) -> bool:
    """Return whether an endpoint belongs to a configured Meta CIDR."""
    confidence, _signals = wf.check_cidr_matching(ip_str)
    return confidence == "high"


def _is_recognized_server_port(port: Optional[int]) -> bool:
    """Return whether a port is a known service port, not merely a high port."""
    return port in (wf.WHATSAPP_CHAT_PORTS | wf.WHATSAPP_STUN_PORTS | wf.WHATSAPP_MEDIA_PORTS | wf.DNS_PORTS)


def _resolve_flow_roles(packet: Dict[str, Any]) -> Tuple[str, Optional[int], str, Optional[int], str]:
    """Infer roles without treating a server-first capture as client-first."""
    src_ip, dst_ip = packet["src_ip"], packet["dst_ip"]
    src_port, dst_port = packet["src_port"], packet["dst_port"]
    src_meta, dst_meta = _is_meta_endpoint(src_ip), _is_meta_endpoint(dst_ip)
    if src_meta != dst_meta:
        return (dst_ip, dst_port, src_ip, src_port, "meta_cidr") if src_meta else (src_ip, src_port, dst_ip, dst_port, "meta_cidr")
    src_private, dst_private = is_private(src_ip), is_private(dst_ip)
    if src_private != dst_private:
        return (src_ip, src_port, dst_ip, dst_port, "private_public") if src_private else (dst_ip, dst_port, src_ip, src_port, "private_public")
    flags = packet.get("tcp_udp_flags") or ""
    if packet.get("protocol") == "TCP" and "SYN" in flags and "ACK" not in flags:
        return src_ip, src_port, dst_ip, dst_port, "tcp_syn"
    src_service, dst_service = _is_recognized_server_port(src_port), _is_recognized_server_port(dst_port)
    if src_service != dst_service:
        return (dst_ip, dst_port, src_ip, src_port, "service_port") if src_service else (src_ip, src_port, dst_ip, dst_port, "service_port")
    return src_ip, src_port, dst_ip, dst_port, "first_packet_fallback"


def _resolve_subscriber(
    packet: Dict[str, Any], explicit_subscriber_ips: Optional[set] = None
) -> Tuple[Optional[str], str, str]:
    """Resolve a capture-scoped subscriber without guessing ambiguous public pairs."""
    src_ip, dst_ip = packet["src_ip"], packet["dst_ip"]
    explicit = explicit_subscriber_ips or set()
    explicit_matches = [ip for ip in (src_ip, dst_ip) if ip in explicit]
    if len(explicit_matches) == 1:
        return explicit_matches[0], "capture_metadata", "high"
    src_local, dst_local = _is_local_scope(src_ip), _is_local_scope(dst_ip)
    if src_local != dst_local:
        return (src_ip if src_local else dst_ip), "private_public", "high"
    client_ip, _cp, _server_ip, _sp, role_source = _resolve_flow_roles(packet)
    if role_source in ("tcp_syn", "meta_cidr", "service_port"):
        confidence = "high" if role_source == "tcp_syn" else "medium"
        return client_ip, role_source, confidence
    return None, "unresolved", "none"


def create_new_flow(
    packet: Dict[str, Any], key: Tuple, explicit_subscriber_ips: Optional[set] = None
) -> Dict[str, Any]:
    """Helper to initialize a new active flow dictionary."""
    client_ip, client_port, server_ip, server_port, role_source = _resolve_flow_roles(packet)
    endpoint_a, endpoint_b = canonical_endpoints(packet)
    subscriber_ip, subscriber_source, subscriber_confidence = _resolve_subscriber(
        packet, explicit_subscriber_ips
    )
    return {
        "key": key,
        "client_ip": client_ip,
        "client_port": client_port,
        "server_ip": server_ip,
        "server_port": server_port,
        "endpoint_role_source": role_source,
        "endpoint_a_ip": endpoint_a[0],
        "endpoint_a_port": endpoint_a[1],
        "endpoint_b_ip": endpoint_b[0],
        "endpoint_b_port": endpoint_b[1],
        "local_subscriber_ip": subscriber_ip,
        "subscriber_resolution_source": subscriber_source,
        "subscriber_resolution_confidence": subscriber_confidence,
        "protocol_type": packet["protocol"],
        "start_time": packet["timestamp"],
        "session_start_confirmed": _looks_like_session_start(packet),
        "packets": [packet],
        "fin_endpoints": set(),
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
    explicit_subscriber_ips: Optional[List[str]] = None,
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
    explicit_subscribers = set(explicit_subscriber_ips or [])

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

            flags = packet.get("tcp_udp_flags") or ""
            is_bare_syn = protocol == "TCP" and "SYN" in flags and "ACK" not in flags
            if is_bare_syn:
                completed_flows.append(flow)
                active_flows[key] = create_new_flow(packet, key, explicit_subscribers)
                continue

            # Per-flow, media-aware, OS-aware timeout
            is_media = _is_media_flow(flow["server_port"])
            if protocol == "UDP":
                ports = {src_port, dst_port}
                if 443 in ports:
                    timeout = 30.0  # QUIC CDN session — give it a long timeout
                elif any(p is not None and 1024 <= p <= 65535 for p in ports):
                    timeout = 10.0
                else:
                    timeout = 30.0
            else:
                timeout = wf.resolve_timeout(os_hint, is_media_flow=is_media)

            if gap > timeout:
                completed_flows.append(flow)
                new_flow = create_new_flow(packet, key, explicit_subscribers)
                active_flows[key] = new_flow
            else:
                flow["packets"].append(packet)
                if protocol == "TCP":
                    if "RST" in flags:
                        completed_flows.append(flow)
                        del active_flows[key]
                    elif "FIN" in flags:
                        flow["fin_endpoints"].add((src_ip, src_port))
                        # Retain the final ACK. A later bare SYN or timeout
                        # starts the next instance of this reused tuple.
        else:
            new_flow = create_new_flow(packet, key, explicit_subscribers)
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
        capture_flow_id = hashlib.sha256(
            f"{pcap_id}|{idx}|{first_seen:.9f}|{flow['key']}".encode("utf-8")
        ).hexdigest()[:24]
        endpoint_a_ip = flow["endpoint_a_ip"]
        a_to_b_packets = [p for p in packets if p.get("src_ip") == endpoint_a_ip]
        b_to_a_packets = [p for p in packets if p.get("src_ip") != endpoint_a_ip]
        flow.update({
            "flow_id": f"{pcap_id}:{capture_flow_id}",
            "flow_instance": idx,
            "pcap_id": pcap_id,
            "packet_count": packet_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "duration_s": duration_s,
            "average_packet_size": sum(lengths) / packet_count if packet_count > 0 else 0.0,
            "maximum_packet_size": max(lengths) if packet_count > 0 else 0,
            "minimum_packet_size": min(lengths) if packet_count > 0 else 0,
            "a_to_b_packets": len(a_to_b_packets),
            "b_to_a_packets": len(b_to_a_packets),
            "a_to_b_bytes": sum(p.get("length", 0) for p in a_to_b_packets),
            "b_to_a_bytes": sum(p.get("length", 0) for p in b_to_a_packets),
        })

        flow.pop("fin_endpoints", None)

        flow["burst_count"] = len(extract_bursts(packets, threshold=burst_threshold))

    return completed_flows
