"""
party_grouper.py: Hierarchical 5-level party aggregation.

Level 1: Transport flow partitioning (handled by flow_builder.py)
Level 2: Entity-level aggregation — group by (remote_ip, remote_port, protocol),
         ignoring ephemeral source port. Prevents one server from appearing as
         dozens of parties due to port recycling.
Level 3: Protocol session linking — TLS session ID (falls back to entity key)
Level 4: Behavioral termination — OS-aware inactivity timeout (in flow_builder.py)
Level 5: Temporal burst partitioning — 1-second gap threshold
"""

import os
import sys
from collections import defaultdict, Counter
from typing import Dict, Any, List, Tuple, Optional

# Need to import check_cidr_matching to classify Relays vs P2P
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.whatsapp_filter import check_cidr_matching

WELL_KNOWN_PORTS = {
    443, 80, 53, 5222, 5223, 5228, 4244, 5242,  # WhatsApp
    3478,                                          # STUN
    8080, 8443, 993, 465, 587, 25,               # Other common
}


def get_entity_key(packet: Dict[str, Any]) -> Tuple:
    """
    Level 2: Entity-level aggregation key.
    Groups by (remote_ip, remote_port, protocol), ignoring ephemeral source port.
    'Remote' = whichever side is on a well-known port; if neither, use lower IP.
    """
    src_ip   = packet.get("src_ip", "")
    dst_ip   = packet.get("dst_ip", "")
    src_port = packet.get("src_port") or 0
    dst_port = packet.get("dst_port") or 0
    protocol = packet.get("protocol", "UNKNOWN")

    traffic_class = (
        'unclassified'
        if (packet.get('whatsapp_confidence') or '').lower() == 'unclassified'
        else 'confirmed_whatsapp'
    )

    # Non-IP frames retained by bypass have no addressable remote endpoint.
    # Keep them as one explicit aggregate rather than presenting a blank IP.
    if not src_ip or not dst_ip:
        return ('Non-IP / link-layer traffic', None, protocol or 'NON-IP', traffic_class)

    if dst_port in WELL_KNOWN_PORTS:
        return (dst_ip, dst_port, protocol, traffic_class)
    elif src_port in WELL_KNOWN_PORTS:
        return (src_ip, src_port, protocol, traffic_class)
    else:
        # Neither side is well-known; pick the "server" by lower IP string
        if src_ip <= dst_ip:
            return (dst_ip, dst_port, protocol, traffic_class)
        else:
            return (src_ip, src_port, protocol, traffic_class)


def classify_party_type(
    remote_port: Optional[int],
    protocol: str,
    media_guess: Optional[str]
) -> str:
    """Classify the entity as client_to_server, peer_to_peer, or unknown."""
    server_ports = {443, 80, 5222, 5223, 5228, 4244, 5242}
    p2p_ports    = {3478}

    if remote_port in server_ports or media_guess in ('message', 'photo', 'audio', 'video'):
        return 'client_to_server'
    if remote_port in p2p_ports or media_guess in ('voice_call', 'video_call', 'call_signaling'):
        return 'peer_to_peer'
    return 'unknown'


def group_into_entities(
    packets: List[Dict[str, Any]],
    upload_id: str,
    os_hint: str = 'unknown',
) -> List[Dict[str, Any]]:
    """
    Level 2 + 5: Group packets into entity-level parties with burst analysis.
    Returns a list of party dicts ready for db_analysis.insert_parties().
    """
    # Level 2: entity grouping
    entity_packets: Dict[Tuple, List[Dict[str, Any]]] = defaultdict(list)
    for pkt in packets:
        key = get_entity_key(pkt)
        entity_packets[key].append(pkt)

    parties = []
    for (remote_ip, remote_port, protocol, traffic_class), pkts in entity_packets.items():
        pkts_sorted = sorted(pkts, key=lambda p: p.get('timestamp', 0))

        timestamps  = [p['timestamp'] for p in pkts_sorted if p.get('timestamp') is not None]
        first_seen  = min(timestamps) if timestamps else 0.0
        last_seen   = max(timestamps) if timestamps else 0.0
        duration_s  = last_seen - first_seen

        total_bytes  = sum(p.get('length', 0) for p in pkts_sorted)
        packet_count = len(pkts_sorted)

        filenames = [p.get('filename') for p in pkts_sorted if p.get('filename')]
        source_file = Counter(filenames).most_common(1)[0][0] if filenames else 'Unknown'
        import json
        source_files = json.dumps(list(set(filenames))) if filenames else "[]"

        # Local IPs observed talking to this entity
        local_ips = set()
        for p in pkts_sorted:
            src, dst = p.get('src_ip'), p.get('dst_ip')
            if src and src != remote_ip:
                local_ips.add(src)
            if dst and dst != remote_ip:
                local_ips.add(dst)

        # Derive dominant media / sub_activity
        media_guesses = [p.get('whatsapp_media_guess') for p in pkts_sorted if p.get('whatsapp_media_guess')]
        sub_activities = [p.get('sub_activity') for p in pkts_sorted if p.get('sub_activity')]

        media_guess  = Counter(media_guesses).most_common(1)[0][0] if media_guesses else None
        sub_activity = Counter(sub_activities).most_common(1)[0][0] if sub_activities else None

        # Detailed breakdown of individual packet classifications within this entity flow
        raw_labels = [p.get('whatsapp_media_guess') or p.get('sub_activity') for p in pkts_sorted if (p.get('whatsapp_media_guess') or p.get('sub_activity'))]
        norm_counts = defaultdict(int)
        for raw in raw_labels:
            rl = (raw or '').lower()
            if 'audio' in rl or 'voice' in rl or 'voip' in rl or 'call' in rl:
                cat = 'VoIP'
            elif 'video' in rl or 'image' in rl or 'media' in rl or 'photo' in rl:
                cat = 'Media'
            elif 'chat' in rl or 'text' in rl or 'message' in rl or 'signal' in rl:
                cat = 'Chat'
            else:
                cat = 'Other'
            norm_counts[cat] += 1
        
        media_breakdown = ' · '.join(f"{cnt} {cat}" for cat, cnt in sorted(norm_counts.items(), key=lambda x: -x[1])) if norm_counts else None

        # Confidence: highest observed
        confidences = [p.get('whatsapp_confidence', 'none') for p in pkts_sorted]
        if traffic_class == 'unclassified':
            confidence = 'unclassified'
            media_guess = 'unclassified'
            sub_activity = 'generic_network_traffic'
            media_breakdown = 'Unclassified Traffic'
        elif 'high' in confidences:
            confidence = 'high'
        elif 'medium' in confidences:
            confidence = 'medium'
        elif 'infrastructure' in confidences:
            confidence = 'infrastructure'
        else:
            confidence = 'none'

        party_type = (
            'unclassified_endpoint'
            if traffic_class == 'unclassified'
            else classify_party_type(remote_port, protocol, media_guess)
        )

        # 3. Determine session start confirmation (OR logic across packets)
        session_start_confirmed = any(p.get('session_start_confirmed', False) for p in pkts_sorted)

        # 4. Look for STUN mapped address (public local IP)
        public_local_ip = None
        for p in pkts_sorted:
            if p.get('stun_mapped_address'):
                addr = p['stun_mapped_address']
                if addr.startswith('['):
                    public_local_ip = addr.split(']')[0].lstrip('[')
                else:
                    public_local_ip = addr.rsplit(':', 1)[0]
                break

        # 5. Determine Relay vs P2P for calls (relying on geo_mapping later, defaulting to party_type here)
        is_p2p = False
        if traffic_class != 'unclassified' and (party_type == 'peer_to_peer' or media_guess in ('voice_call', 'video_call')):
            is_p2p = True

        party_id = f"{upload_id}_{traffic_class}_{remote_ip}_{remote_port}_{protocol}"

        parties.append({
            'party_id':     party_id,
            'upload_id':    upload_id,
            'remote_ip':    remote_ip,
            'remote_port':  remote_port,
            'protocol':     protocol,
            'local_ips':    ','.join(sorted(local_ips)),
            'public_local_ip': public_local_ip,
            'packet_count': packet_count,
            'total_bytes':  total_bytes,
            'first_seen':   first_seen,
            'last_seen':    last_seen,
            'duration_s':   duration_s,
            'party_type':   party_type,
            'sub_activity': sub_activity,
            'media_type':   media_guess,
            'confidence':   confidence,
            'traffic_class': traffic_class,
            'os_hint':      os_hint,
            'is_p2p':       is_p2p,
            'session_start_confirmed': session_start_confirmed,
            'media_breakdown': media_breakdown,
            'source_file': source_file,
            'source_files': source_files,
        })

    return sorted(parties, key=lambda p: p['packet_count'], reverse=True)
