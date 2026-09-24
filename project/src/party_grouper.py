"""Capture-scoped endpoint-pair relationship aggregation.

Parties are geographic/network relationships, not transport flows or calls.
Call reconstruction is owned by ``session_engine``.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from src.whatsapp_filter import check_cidr_matching


def _ip_key(ip_str: str) -> Tuple[int, int]:
    ip_obj = ipaddress.ip_address(ip_str)
    return ip_obj.version, int(ip_obj)


def _canonical_pair(packet: Dict[str, Any]) -> Tuple[str, str]:
    a, b = packet.get("endpoint_a_ip"), packet.get("endpoint_b_ip")
    if a and b:
        return a, b
    src, dst = packet.get("src_ip"), packet.get("dst_ip")
    if not src or not dst:
        return "Non-IP / link-layer traffic", "Non-IP / link-layer traffic"
    ordered = sorted((src, dst), key=_ip_key)
    return ordered[0], ordered[1]


def get_entity_key(packet: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """Return the party-v2 identity: capture, endpoint pair, protocol."""
    endpoint_a, endpoint_b = _canonical_pair(packet)
    capture_id = str(packet.get("upload_id") or packet.get("capture_id") or "unknown-capture")
    return capture_id, endpoint_a, endpoint_b, str(packet.get("protocol") or "NON-IP").upper()


def _endpoint_scope(ip_str: str) -> str:
    if ip_str.startswith("Non-IP"):
        return "non_ip"
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return "invalid"
    if ip_obj.version == 4 and ip_obj in ipaddress.ip_network("100.64.0.0/10"):
        return "cgnat"
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        return "local"
    if ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved:
        return "non_routable"
    return "public"


def _legacy_local_remote(a: str, b: str, subscriber: Optional[str]) -> Tuple[str, str]:
    """Populate compatibility fields without affecting relationship identity."""
    if subscriber == a:
        return a, b
    if subscriber == b:
        return b, a
    a_scope, b_scope = _endpoint_scope(a), _endpoint_scope(b)
    if a_scope != "public" and b_scope == "public":
        return a, b
    if b_scope != "public" and a_scope == "public":
        return b, a
    a_meta = check_cidr_matching(a)[0] == "high"
    b_meta = check_cidr_matching(b)[0] == "high"
    if a_meta != b_meta:
        return (b, a) if a_meta else (a, b)
    return a, b


def _aggregate_crypto(packets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Return counts and flow references; never select a party-wide handshake."""
    counts = Counter()
    flow_refs, quic_versions = set(), set()
    for packet in packets:
        if packet.get("quic_version"):
            quic_versions.add(str(packet["quic_version"]))
        raw = packet.get("tls_crypto_info")
        if not raw:
            continue
        try:
            info = json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(info, dict):
            continue
        kind = info.get("type")
        counts[kind] += 1
        counts["pqc_offer"] += int(bool(info.get("pqc") and kind == "client_hello"))
        counts["pqc_selection"] += int(bool(info.get("pqc") and kind == "server_hello"))
        if packet.get("flow_id"):
            flow_refs.add(str(packet["flow_id"]))
    if not counts and not quic_versions:
        return None
    return {
        "client_hello_count": counts["client_hello"],
        "server_hello_count": counts["server_hello"],
        "pqc_offer_count": counts["pqc_offer"],
        "pqc_selection_count": counts["pqc_selection"],
        "quic_versions": sorted(quic_versions),
        "flow_refs": sorted(flow_refs),
    }


def _ports_for(ip: str, packets: List[Dict[str, Any]]) -> List[int]:
    ports = set()
    for packet in packets:
        if packet.get("src_ip") == ip and packet.get("src_port") is not None:
            ports.add(int(packet["src_port"]))
        if packet.get("dst_ip") == ip and packet.get("dst_port") is not None:
            ports.add(int(packet["dst_port"]))
    return sorted(ports)


def group_into_entities(
    packets: List[Dict[str, Any]], upload_id: str, os_hint: str = "unknown"
) -> List[Dict[str, Any]]:
    """Build endpoint-pair parties while retaining legacy output fields."""
    grouped: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    for packet in packets:
        grouped[get_entity_key(packet)].append(packet)

    parties: List[Dict[str, Any]] = []
    for (capture_id, endpoint_a, endpoint_b, protocol), members in grouped.items():
        pkts = sorted(members, key=lambda p: p.get("timestamp") or 0.0)
        timestamps = [p["timestamp"] for p in pkts if p.get("timestamp") is not None]
        subscriber_votes = Counter(p.get("local_subscriber_ip") for p in pkts if p.get("local_subscriber_ip"))
        subscriber = subscriber_votes.most_common(1)[0][0] if subscriber_votes else None
        source_votes = Counter(p.get("subscriber_resolution_source") for p in pkts if p.get("subscriber_resolution_source"))
        subscriber_source = source_votes.most_common(1)[0][0] if source_votes else "unresolved"
        subscriber_levels = [p.get("subscriber_resolution_confidence") for p in pkts]
        subscriber_confidence = "high" if "high" in subscriber_levels else "medium" if "medium" in subscriber_levels else "none"
        local_ip, remote_ip = _legacy_local_remote(endpoint_a, endpoint_b, subscriber)

        a_packets = [p for p in pkts if p.get("src_ip") == endpoint_a]
        b_packets = [p for p in pkts if p.get("src_ip") == endpoint_b]
        a_ports, b_ports = _ports_for(endpoint_a, pkts), _ports_for(endpoint_b, pkts)
        remote_ports = b_ports if remote_ip == endpoint_b else a_ports
        flow_ids = sorted({str(p.get("flow_id")) for p in pkts if p.get("flow_id")})
        labels = [p.get("whatsapp_media_guess") for p in pkts if p.get("whatsapp_media_guess")]
        activities = [p.get("sub_activity") for p in pkts if p.get("sub_activity")]
        confidences = [str(p.get("whatsapp_confidence") or "none").lower() for p in pkts]
        
        _ACTIVITY_PRIORITY = [
            'video_call', 'voice_call', 'call_stream_unresolved',
            'call_signaling', 'media_transfer', 'photo', 'audio',
            'video', 'message', 'xmpp_multiplex', 'unclassified',
        ]
        
        def _dominant(candidates: List[str]) -> Optional[str]:
            c_set = set(candidates)
            for prio in _ACTIVITY_PRIORITY:
                if prio in c_set:
                    return prio
            return Counter(candidates).most_common(1)[0][0] if candidates else None

        media_guess = _dominant(labels)
        sub_activity = _dominant(activities)
        traffic_class = "unclassified" if all(c == "unclassified" for c in confidences) else "confirmed_whatsapp"
        confidence = next((c for c in ("high", "medium", "infrastructure", "unclassified", "none") if c in confidences), "none")
        filenames = sorted({str(p.get("filename")) for p in pkts if p.get("filename")})
        breakdown = Counter(labels or activities)
        seed = f"{capture_id}|{endpoint_a}|{endpoint_b}|{protocol}"
        party_id = "party-v2-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]

        parties.append({
            "schema_version": "party-relationship-v2",
            "party_id": party_id,
            "upload_id": capture_id,
            "analysis_scope_id": upload_id,
            "endpoint_a_ip": endpoint_a,
            "endpoint_b_ip": endpoint_b,
            "endpoint_a_scope": _endpoint_scope(endpoint_a),
            "endpoint_b_scope": _endpoint_scope(endpoint_b),
            "endpoint_a_ports": a_ports,
            "endpoint_b_ports": b_ports,
            "protocol": protocol,
            "flow_ids": flow_ids,
            "a_to_b_packets": len(a_packets),
            "b_to_a_packets": len(b_packets),
            "a_to_b_bytes": sum(p.get("length", 0) for p in a_packets),
            "b_to_a_bytes": sum(p.get("length", 0) for p in b_packets),
            "local_subscriber_ip": subscriber,
            "subscriber_resolution_source": subscriber_source,
            "subscriber_resolution_confidence": subscriber_confidence,
            # Compatibility fields consumed by existing templates/API clients.
            "remote_ip": remote_ip,
            "remote_port": remote_ports[0] if len(remote_ports) == 1 else None,
            "local_ips": local_ip or "",
            "public_local_ip": None,
            "packet_count": len(pkts),
            "total_bytes": sum(p.get("length", 0) for p in pkts),
            "first_seen": min(timestamps) if timestamps else 0.0,
            "last_seen": max(timestamps) if timestamps else 0.0,
            "duration_s": max(timestamps) - min(timestamps) if timestamps else 0.0,
            "party_type": (
                "peer_to_peer" if sub_activity in ('voice_call', 'video_call', 'call_stream_unresolved', 'call_signaling') else
                "client_to_server" if sub_activity in ('message', 'photo', 'audio', 'video', 'media_transfer', 'xmpp_multiplex') or (remote_ports and remote_ports[0] in {443, 80, 5222, 5223, 5228}) else
                "unknown"
            ),
            "sub_activity": sub_activity,
            "media_type": media_guess,
            "confidence": confidence,
            "traffic_class": traffic_class,
            "os_hint": os_hint,
            "is_p2p": sub_activity in ('voice_call', 'video_call', 'call_stream_unresolved', 'call_signaling'),
            "session_start_confirmed": any(p.get("session_start_confirmed") for p in pkts),
            "media_breakdown": " · ".join(f"{count} {label}" for label, count in breakdown.most_common()) or None,
            "source_file": filenames[0] if len(filenames) == 1 else "Multiple captures",
            "source_files": json.dumps(filenames),
            "crypto_summary": _aggregate_crypto(pkts),
            "call_duration_s": 0.0,
            "longest_call_s": 0.0,
            "call_window_count": 0,
            "sessions": [],
            "voice_call_count": 0,
            "video_call_count": 0,
            "unresolved_call_count": 0,
            "voice_duration_s": 0.0,
            "video_duration_s": 0.0,
        })
    return sorted(parties, key=lambda party: party["packet_count"], reverse=True)
