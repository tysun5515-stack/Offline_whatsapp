"""
forensic_evidence.py — Forensic evidence trail builder for packet-level classification.
Reconstructs human-readable explanations, corroborating signals, and exclusion rules
for classified WhatsApp packets.
"""

from typing import Dict, Any, List, Optional
import ipaddress

# Import Meta CIDR ranges from whatsapp_filter if available
try:
    from src.whatsapp_filter import (
        META_IP_RANGES,
        WHATSAPP_CHAT_PORTS,
        WHATSAPP_STUN_PORTS,
        WHATSAPP_MEDIA_PORTS,
        is_likely_call_media_port,
    )
except ImportError:
    META_IP_RANGES = []
    WHATSAPP_CHAT_PORTS = {5222, 5223, 5228, 4244, 5242}
    WHATSAPP_STUN_PORTS = {3478}
    WHATSAPP_MEDIA_PORTS = {443}

    def is_likely_call_media_port(port: Optional[int], protocol_type: Optional[str]) -> bool:
        return port is not None and (protocol_type or "").upper() == "UDP" and 1024 <= port <= 65535


def check_ip_in_meta_ranges(ip_str: Optional[str]) -> bool:
    if not ip_str:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in META_IP_RANGES:
            if ip_obj in net:
                return True
    except ValueError:
        pass
    return False


def build_evidence_trail(packet: Dict[str, Any]) -> Dict[str, Any]:
    """
    Given a packet dict (from whatsapp_packets table), reconstructs:
    1. verdict: { confidence, media_guess, sub_activity, protocol }
    2. evidence: list of { signal, label, explanation, strength, status ('passed'|'neutral'|'warning') }
    3. exclusions: list of { target, reason } explaining why other traffic types were ruled out
    4. summary_narrative: clear, forensic summary explanation
    """
    src_ip = packet.get("src_ip") or ""
    dst_ip = packet.get("dst_ip") or ""
    src_port = packet.get("src_port")
    dst_port = packet.get("dst_port")
    proto = (packet.get("protocol") or "UNKNOWN").upper()
    length = packet.get("length") or 0
    confidence = (packet.get("whatsapp_confidence") or "low").lower()
    raw_media_guess = packet.get("whatsapp_media_guess") or "unclassified"
    raw_sub_activity = packet.get("sub_activity") or "unknown"
    is_stun = bool(packet.get("is_stun_binding"))
    ip_ttl = packet.get("ip_ttl")
    flow_id = packet.get("flow_id") or ""

    # Bypass mode keeps traffic which did not satisfy a WhatsApp rule so an
    # analyst can inspect its raw network facts.  Do not reconstruct WA
    # evidence from a port, address, or packet shape for these packets.
    if confidence == "unclassified":
        evidence = [
            {
                "signal": "bypass_retained",
                "label": "Retained by WA Filter Bypass",
                "explanation": "This packet did not meet the WhatsApp classifier threshold and was retained for manual review because bypass mode is active.",
                "strength": "NEUTRAL",
                "status": "neutral",
            },
            {
                "signal": "network_tuple",
                "label": "Network Transport Facts",
                "explanation": f"{proto} packet {src_ip}:{src_port or '—'} → {dst_ip}:{dst_port or '—'}, {length} bytes.",
                "strength": "NEUTRAL",
                "status": "neutral",
            },
        ]
        if ip_ttl is not None:
            evidence.append({
                "signal": "ip_ttl",
                "label": f"IP Time-To-Live (TTL = {ip_ttl})",
                "explanation": "Observed directly in the packet IP header.",
                "strength": "NEUTRAL",
                "status": "neutral",
            })
        return {
            "verdict": {
                "confidence": "unclassified",
                "media_guess": "unclassified",
                "sub_activity": "generic_network_traffic",
                "protocol": proto,
                "is_stun": False,
                "length": length,
                "flow_id": flow_id,
            },
            "evidence": evidence,
            "exclusions": [],
            "summary_narrative": "Unclassified network traffic retained by WA Filter Bypass for manual packet inspection. No WhatsApp-specific conclusion has been made.",
        }

    ports = {p for p in (src_port, dst_port) if p is not None}
    chat_port_matched = list(ports & WHATSAPP_CHAT_PORTS)
    has_chat_port = bool(chat_port_matched) or raw_sub_activity == "xmpp_multiplex"
    has_stun_port = bool(ports & WHATSAPP_STUN_PORTS) or is_stun
    has_media_port = bool(ports & WHATSAPP_MEDIA_PORTS)
    has_dynamic_udp = proto == "UDP" and any(is_likely_call_media_port(p, proto) for p in ports)

    # -------------------------------------------------------------
    # Forensic Reconciliation: Enforce physical transport truth
    # -------------------------------------------------------------
    # Rule 1: Chat daemon ports (5222, 5223, 4244) carry multiplexed FunXMPP (Chat + Signaling)
    # WhatsApp CDN media uploads/downloads strictly require TLS/443 to mmg.whatsapp.net.
    if has_chat_port:
        # Without SNI, conservatively assume call signaling for all FunXMPP packets
        media_guess = "call_signaling"
        sub_activity = "xmpp_multiplex"
    # Rule 2: UDP cannot carry TLS-terminated CDN transfers
    elif proto == "UDP" and raw_media_guess in ("photo", "video", "audio"):
        if has_stun_port:
            media_guess = "call_signaling"
            sub_activity = "call_signaling"
        elif has_dynamic_udp:
            media_guess = "call_media_candidate"
            sub_activity = "call_media_candidate"
        else:
            media_guess = "call_signaling"
            sub_activity = "call_signaling"
    else:
        media_guess = raw_media_guess
        sub_activity = raw_sub_activity

    # 1. CIDR Inspection
    src_meta = check_ip_in_meta_ranges(src_ip)
    dst_meta = check_ip_in_meta_ranges(dst_ip)
    meta_matched_ip = dst_ip if dst_meta else (src_ip if src_meta else None)

    evidence: List[Dict[str, Any]] = []
    exclusions: List[Dict[str, Any]] = []

    endpoint_role_source = packet.get("endpoint_role_source")
    matched_meta_ip = packet.get("matched_meta_ip")
    acceptance_reason = packet.get("acceptance_reason")
    if endpoint_role_source:
        evidence.append({"signal": "endpoint_role_resolution", "label": "Endpoint Role Resolution", "explanation": f"Roles resolved using {endpoint_role_source.replace('_', ' ')}" + (f"; matched Meta endpoint {matched_meta_ip}." if matched_meta_ip else "."), "strength": "HIGH" if endpoint_role_source == "meta_cidr" else "NEUTRAL", "status": "passed" if endpoint_role_source == "meta_cidr" else "neutral"})
    if acceptance_reason:
        evidence.append({"signal": "acceptance_reason", "label": "Filter Acceptance Decision", "explanation": f"Flow retained because of {acceptance_reason.replace('_', ' ')}.", "strength": "HIGH" if acceptance_reason == "cidr_strong" else "MEDIUM", "status": "passed"})
    # Evidence 1: IP & Infrastructure Match
    if meta_matched_ip:
        evidence.append({
            "signal": "cidr_strong",
            "label": "Meta / WhatsApp ASN Infrastructure Match",
            "explanation": f"Endpoint IP ({meta_matched_ip}) belongs to verified Meta Platforms / WhatsApp CIDR allocation (AS32934).",
            "strength": "HIGH",
            "status": "passed"
        })
    else:
        evidence.append({
            "signal": "inferred_or_peer",
            "label": "Direct Peer / Inferred Route",
            "explanation": f"Endpoints ({src_ip} -> {dst_ip}) do not directly match public Meta CIDR blocks; classified via flow inference or peer-to-peer relay.",
            "strength": "MEDIUM" if confidence in ("high", "medium") else "LOW",
            "status": "neutral"
        })

    # Evidence 2: Transport Protocol & Port Rules
    if has_chat_port:
        active_port = chat_port_matched[0] if chat_port_matched else (dst_port or src_port)
        evidence.append({
            "signal": "port_chat",
            "label": f"WhatsApp Chat Daemon Port ({active_port})",
            "explanation": f"Port {active_port} is the registered WhatsApp chat & notification daemon (Noise/XMPP protocol). Media downloads strictly bypass this port and use HTTPS/443.",
            "strength": "HIGH",
            "status": "passed"
        })
    elif has_stun_port:
        evidence.append({
            "signal": "port_stun",
            "label": "STUN NAT Traversal / Call Initiation",
            "explanation": "Port 3478 or RFC 5389 STUN Binding detected — initiates P2P/relay media connectivity for WhatsApp voice/video calls.",
            "strength": "HIGH",
            "status": "passed"
        })
    elif has_dynamic_udp:
        dyn_port = next(p for p in ports if is_likely_call_media_port(p, proto))
        evidence.append({
            "signal": "port_dynamic_udp",
            "label": "Dynamic UDP VoIP / SRTP Media Port",
            "explanation": f"UDP traffic on high port {dyn_port} associated with negotiated WhatsApp VoIP audio/video RTP/SRTP streams.",
            "strength": "HIGH" if meta_matched_ip else "MEDIUM",
            "status": "passed"
        })
    elif has_media_port:
        evidence.append({
            "signal": "port_https",
            "label": "TLS / HTTPS Media CDN Channel (Port 443)",
            "explanation": "Port 443 TCP transport used for encrypted WhatsApp media transfers (images, voice notes, documents, video) via CDN servers.",
            "strength": "MEDIUM",
            "status": "passed"
        })
    else:
        evidence.append({
            "signal": "port_general",
            "label": f"Transport {proto}",
            "explanation": f"Traffic routed via port {dst_port or src_port} using {proto}.",
            "strength": "LOW",
            "status": "neutral"
        })

    # Evidence 3: STUN Protocol Inspection
    if is_stun:
        evidence.append({
            "signal": "stun_binding",
            "label": "STUN Binding Magic Cookie Validated",
            "explanation": "Packet payload validated with STUN Magic Cookie (0x2112A442) or 86-byte STUN keepalive signature.",
            "strength": "HIGH",
            "status": "passed"
        })

    # Evidence 4: Payload Dissection & Packet Characterization
    if has_chat_port:
        if length <= 64 and proto == "TCP":
            evidence.append({
                "signal": "tcp_ack_control",
                "label": f"TCP Transport Control / ACK ({length} bytes)",
                "explanation": f"Packet length of {length} bytes corresponds to a TCP acknowledgement (ACK), window update, or keepalive handshake on the active chat connection.",
                "strength": "HIGH",
                "status": "passed"
            })
        else:
            evidence.append({
                "signal": "chat_message_payload",
                "label": f"Encrypted Chat Frame ({length} bytes)",
                "explanation": f"Payload transmitted over WhatsApp chat port carrying end-to-end encrypted message, delivery receipt, or presence notification.",
                "strength": "HIGH",
                "status": "passed"
            })
    elif media_guess in ("voice_call", "video_call"):
        evidence.append({
            "signal": "voip_stream",
            "label": "Sustained RTP/SRTP Bitrate Window",
            "explanation": f"Packet length of {length} bytes is part of flow with sustained UDP stream characteristics exceeding the 12 kbps VoIP voice threshold.",
            "strength": "HIGH",
            "status": "passed"
        })
    elif media_guess in ("call_signaling", "call_media_candidate"):
        evidence.append({
            "signal": "call_signaling",
            "label": "Call Control / Low-Bitrate Signaling",
            "explanation": f"Packet length {length} bytes represents call setup, handshake or keep-alive heartbeat signaling.",
            "strength": "MEDIUM",
            "status": "passed"
        })
    elif media_guess in ("photo", "audio", "video") and has_media_port:
        evidence.append({
            "signal": "burst_transfer",
            "label": f"Media CDN Transfer ({media_guess.upper()})",
            "explanation": f"Packet of {length} bytes part of a TLS/HTTPS transfer over Port 443 matching {media_guess.upper()} download/upload payload profile.",
            "strength": "MEDIUM",
            "status": "passed"
        })
    else:
        evidence.append({
            "signal": "payload_generic",
            "label": f"Packet Length: {length} bytes",
            "explanation": f"Discrete packet containing {length} bytes of encrypted application payload.",
            "strength": "LOW",
            "status": "neutral"
        })

    # Evidence 5: Network Hop / TTL Characteristics
    if ip_ttl is not None and ip_ttl > 0:
        hops = 64 - ip_ttl if ip_ttl <= 64 else (128 - ip_ttl if ip_ttl <= 128 else 255 - ip_ttl)
        evidence.append({
            "signal": "ip_ttl",
            "label": f"IP Time-To-Live (TTL = {ip_ttl})",
            "explanation": f"IP packet header has TTL {ip_ttl}, indicating approximately {hops} network routing hops.",
            "strength": "LOW",
            "status": "neutral"
        })

    # -------------------------------------------------------------
    # Forensic Exclusions ("Why NOT other traffic types?")
    # -------------------------------------------------------------
    if has_chat_port:
        # A chat packet is NOT a CDN photo download
        exclusions.append({
            "target": "WhatsApp CDN Media Download (Photo / Video)",
            "reason": f"Port {dst_port or src_port} is the WhatsApp chat daemon. Media files (photos, videos, docs) strictly download via TLS/443 to WhatsApp CDN servers (mmg.whatsapp.net), never over chat signaling ports."
        })
        exclusions.append({
            "target": "VoIP SRTP Voice / Video Stream",
            "reason": "WhatsApp voice and video calls stream real-time audio/video over UDP/SRTP. This packet is a TCP chat signaling connection."
        })
    elif proto == "UDP":
        exclusions.append({
            "target": "WhatsApp CDN Media Download (Photo / Video)",
            "reason": "WhatsApp CDN downloads strictly operate over TCP/443 TLS to mmg.whatsapp.net. UDP cannot physically carry TLS-terminated CDN transfers."
        })
        exclusions.append({
            "target": "Chat Text Messaging (XMPP/Noise)",
            "reason": "Text messaging and presence updates require persistent TCP connections (ports 5222, 5223, 4244), whereas this packet is UDP."
        })
    else:  # TCP non-chat port (e.g. port 443)
        exclusions.append({
            "target": "VoIP SRTP Voice / Video Stream",
            "reason": "WhatsApp voice and video calls transmit real-time media streams over UDP/SRTP for low latency. TCP/443 is used for CDN downloads or fallback signaling."
        })
        exclusions.append({
            "target": "Chat Daemon Signaling",
            "reason": "Direct chat messaging and presence updates route through ports 5222/5223/4244, whereas this connection uses port 443."
        })

    # -------------------------------------------------------------
    # Narrative Summary
    # -------------------------------------------------------------
    narrative_parts = []
    if has_chat_port:
        narrative_parts.append(
            f"Classified as **Chat Signaling / Message** with **{confidence.upper()} confidence**."
        )
        narrative_parts.append(
            f"Transported via **{proto}** ({length} bytes) through WhatsApp chat daemon port **{dst_port or src_port}**."
        )
        if meta_matched_ip:
            narrative_parts.append(
                f"The remote endpoint **{meta_matched_ip}** belongs to Meta's verified network (AS32934)."
            )
        narrative_parts.append(
            "Directly matches official WhatsApp chat protocol architecture (Noise/XMPP). Photo transfers are excluded as they strictly require separate TLS/443 CDN connections."
        )
    elif media_guess in ("voice_call", "video_call"):
        narrative_parts.append(
            f"Classified as **{media_guess.replace('_', ' ').title()}** with **{confidence.upper()} confidence**."
        )
        narrative_parts.append(
            f"The packet was transmitted over **{proto}** via port **{dst_port or src_port}**."
        )
        if meta_matched_ip:
            narrative_parts.append(
                f"The remote endpoint **{meta_matched_ip}** belongs to Meta's verified network (AS32934)."
            )
        narrative_parts.append(
            "The flow displays high-intensity sustained streaming exceeding the Opus VoIP threshold."
        )
    elif media_guess in ("photo", "video", "audio"):
        narrative_parts.append(
            f"Classified as **{media_guess.replace('_', ' ').title()} Transfer** with **{confidence.upper()} confidence**."
        )
        narrative_parts.append(
            f"Transported via **{proto}** ({length} bytes) over CDN port **{dst_port or src_port}**."
        )
    else:
        narrative_parts.append(
            f"Classified as **{media_guess.replace('_', ' ').title()}** ({sub_activity}) with **{confidence.upper()} confidence**."
        )
        narrative_parts.append(
            f"Transported via **{proto}** ({length} bytes) through port **{dst_port or src_port}**."
        )

    summary_narrative = " ".join(narrative_parts)

    return {
        "verdict": {
            "confidence": confidence,
            "media_guess": media_guess,
            "sub_activity": sub_activity,
            "protocol": proto,
            "is_stun": is_stun,
            "length": length,
            "flow_id": flow_id
        },
        "evidence": evidence,
        "exclusions": exclusions,
        "summary_narrative": summary_narrative
    }
