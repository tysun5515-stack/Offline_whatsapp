"""
os_fingerprint.py — Passive OS detection from unencrypted packet headers.
No decryption required. Uses TTL, inter-packet gap, and TCP window heuristics.
"""
from collections import Counter
from typing import List, Dict, Any, Tuple

OS_TIMEOUTS = {
    'ios':     180,    # 3 minutes — aggressive iOS keepalive termination
    'android': 600,    # 10 minutes — conservative Android step
    'windows': 600,    # 10 minutes
    'whatsapp_web': 600, # 10 minutes
    'unknown': 300,    # 5 minutes — safe default
}

# Known iOS TTL = 64, Android TTL = 64, Windows TTL = 128
# (Both iOS and Android start at 64 so TTL alone only eliminates Windows)
_WINDOWS_TTL = 128
_UNIX_TTL    = 64

# iOS inactivity timeout: ~180s (+/- 30s tolerance)
_IOS_GAP_LOW, _IOS_GAP_HIGH         = 150, 210
# Android inactivity timeouts: 10min, 15min, 24min
_ANDROID_GAPS = [(550, 650), (850, 950), (1380, 1500)]

# TCP initial window sizes (common heuristics)
_WINDOWS_TCP_WIN = 8192      # Windows default
_ANDROID_TCP_WIN = 65535     # Android / Linux default
_IOS_TCP_WIN     = 65535     # iOS also uses 65535 but with window scaling


def detect_os_hint(packet_records: List[Dict[str, Any]]) -> Tuple[str, str]:
    """
    Returns an (os_hint, confidence) tuple based on TTL, TCP Window, and gap clustering.
    """
    windows_votes = 0
    unix_votes = 0
    android_gap = False
    ios_gap = False

    # 1. TTL Vote
    ttls = [p['ip_ttl'] for p in packet_records if p.get('ip_ttl') is not None]
    if ttls:
        # Most common TTL
        c_ttl = Counter(ttls).most_common(1)[0][0]
        if c_ttl >= 112:
            windows_votes += 1
        elif c_ttl <= 70:
            unix_votes += 1
            
    # 2. TCP Window Size Vote
    syn_wins = [p['tcp_window_size'] for p in packet_records if p.get('tcp_window_size') is not None and 'SYN' in (p.get('tcp_udp_flags') or '') and 'ACK' not in (p.get('tcp_udp_flags') or '')]
    if syn_wins:
        c_win = Counter(syn_wins).most_common(1)[0][0]
        if c_win == _WINDOWS_TCP_WIN:
            windows_votes += 1
        elif c_win == _ANDROID_TCP_WIN: # 65535, same for iOS
            unix_votes += 1
            
    # 3. Gap Vote
    # Calculate gaps per IP
    ips = set(p['src_ip'] for p in packet_records if p.get('src_ip'))
    for ip in ips:
        ip_pkts = [p for p in packet_records if p.get('src_ip') == ip]
        ip_pkts.sort(key=lambda x: x['timestamp'])
        gaps = []
        for i in range(1, len(ip_pkts)):
            gaps.append(ip_pkts[i]['timestamp'] - ip_pkts[i-1]['timestamp'])
        
        # Check against iOS gap
        if any(_IOS_GAP_LOW <= g <= _IOS_GAP_HIGH for g in gaps):
            ios_gap = True
        
        # Check against Android gaps
        for low, high in _ANDROID_GAPS:
            if any(low <= g <= high for g in gaps):
                android_gap = True
                
    # 4. Port Vote (Web vs Mobile)
    # WhatsApp Web exclusively uses 443, mobile heavily uses 5222 for auth/signaling
    ports = set(p['src_port'] for p in packet_records if p.get('src_port')) | set(p['dst_port'] for p in packet_records if p.get('dst_port'))
    has_443 = 443 in ports
    has_5222 = 5222 in ports
    
    # Tally
    if windows_votes >= 2:
        return ('whatsapp_web', 'high') if (has_443 and not has_5222) else ('windows', 'high')
    elif windows_votes == 1 and unix_votes == 0:
        return ('whatsapp_web', 'medium') if (has_443 and not has_5222) else ('windows', 'medium')
    
    if unix_votes >= 1:
        if has_443 and not has_5222 and not ios_gap and not android_gap:
            return ('whatsapp_web', 'medium') # Could be Mac WhatsApp Web
        if ios_gap and not android_gap:
            return ('ios', 'medium' if unix_votes == 1 else 'high')
        if android_gap and not ios_gap:
            return ('android', 'medium' if unix_votes == 1 else 'high')
        return ('android_or_ios', 'low' if unix_votes == 1 else 'medium')
        
    return ('unknown', 'low')


def os_inactivity_timeout(packet_records: List[Dict[str, Any]]) -> float:
    """Returns the appropriate inactivity timeout (seconds) for detected OS."""
    detected, _ = detect_os_hint(packet_records)
    if detected == 'android_or_ios':
        detected = 'android'
    return float(OS_TIMEOUTS.get(detected, OS_TIMEOUTS['unknown']))
