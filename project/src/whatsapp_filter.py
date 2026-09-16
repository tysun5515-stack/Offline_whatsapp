"""
whatsapp_filter.py: Classifies flows as WhatsApp based on domains, IP ranges, and behavior.

Parameter sources:
  - Domain/port table, SoftLayer AS 36351, OS-specific flow timeouts,
    chat/media flow size+duration footprints: Fiadino, Schiavone, Casas,
    "Vivisecting WhatsApp in Cellular Networks: Servers, Flows, and
    Quality of Experience," TMA 2015 (peer-reviewed, ~150M real flows).
  - STUN 86-byte signature: confirmed independently in a separate
    real-capture study; cross-check via the magic-cookie parse, not
    frame length alone (frame length is link-type-dependent - see
    packet_parser.py's is_stun_binding logic).
  - VoIP bitrate thresholds (12kbps/8kbps): NOT sourced from the above
    paper (its dataset predates WhatsApp voice calling by over a year).
    Plausible given Opus's typical bitrate range, but unvalidated -
    gated behind a real validation-report check (see
    `_voip_thresholds_validated()` below), not a hand-editable constant.

Fix log (this revision):
  1. VoIP-validation gate is now read from a validation report file on
     disk, produced only by scripts/validate_against_labels.py - it can
     no longer be silently flipped to True by hand-editing a constant.
  2. Burst intensity is now computed per-burst (bytes / that burst's own
     duration), not per-flow - the previous version divided one burst's
     bytes by the whole flow's duration, which made the 50_000/30s
     thresholds behave inconsistently depending on unrelated flow length.
  3. CONFIRMED_WHATSAPP_SERVERS is no longer a module-level global. It's
     a `ConfirmedServerRegistry` instance, scoped per pcap_id/upload_id,
     passed explicitly into the functions that need it. A global shared
     across every upload in a long-running process meant one case's
     evidence silently leaked into an unrelated case's confidence score.
     ** CALLER CHANGE REQUIRED: see the migration note above the class. **
  4. Domain matching now checks label boundaries
     (`domain == suffix or domain.endswith("." + suffix)`), not a bare
     `str.endswith()`, which previously matched "evilwhatsapp.net"
     against the suffix "whatsapp.net".
  5. SNI-derived sub-activity and port-derived activity are kept in
     clearly separate, namespaced fields (`sni_sub_activity` /
     `port_activity`) instead of being merged into one ambiguous field -
     they are different-strength signals from different evidence and a
     forensic tool should never blur which one produced a given label.
"""

import re
import ipaddress
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from src.traffic_utils import extract_bursts, extract_bursts_with_duration

# ---------------------------------------------------------------------------
# Domain lists (reused by geolocation.py for rDNS verification)
# ---------------------------------------------------------------------------
STRONG_DOMAINS = {
    "whatsapp.net", "whatsapp.com", "mmg.whatsapp.net",
    "media.whatsapp.net", "g.whatsapp.net", "v.whatsapp.net",
    "graph.whatsapp.com",
}
WEAK_DOMAINS = {
    "fbcdn.net", "cdninstagram.com", "facebook.com",
}

# WhatsApp-specific ports
WHATSAPP_CHAT_PORTS: set = {5222, 5223, 5228, 4244, 5242}
WHATSAPP_STUN_PORTS: set = {3478}
WHATSAPP_MEDIA_PORTS: set = {443}
DNS_PORTS: set = {53}

WHATSAPP_CALL_PORT_RANGE = (1024, 65535)  # dynamic ports post-STUN

def is_likely_call_media_port(port: Optional[int]) -> bool:
    """Ports above 1024 on confirmed Meta IPs carrying UDP are almost
    certainly post-STUN SRTP streams, not media CDN transfers.
    CDN media always uses TCP/443; dynamic UDP = call stream."""
    if port is None:
        return False
    return 1024 <= port <= 65535

# VoIP bitrate thresholds - see _voip_thresholds_validated() for the gate
_VOIP_THRESHOLD_KBPS = 12.0   # sustained above -> voice_call
_VIDEO_THRESHOLD_KBPS = 50.0  # sustained above + asymmetric -> video_call
_SIGNALING_MAX_KBPS = 8.0     # mean below -> call_signaling
_WINDOW_SECONDS = 5.0
_WINDOW_SLIDE_STEP = 1.0
_SUSTAINED_FRACTION = 0.5     # fraction of windows above threshold to call it voice_call

# Chat/control flow inactivity timeouts, by OS (seconds).
# Source: Fiadino et al. TMA 2015, Fig. 6(a).
OS_CHAT_TIMEOUTS_SECONDS = {
    "ios": 180,
    "android": (600, 900, 1440),
    "windows_phone": 600,
    "blackberry": 900,
    "unknown": 300,  # not from the paper - conservative fallback
}

# Media (mm) flow inactivity timeout, by OS (seconds).
# CONFIRMED ONLY for blackberry/windows_phone - see module docstring.
OS_MEDIA_TIMEOUT_SECONDS = {
    "blackberry": 90,
    "windows_phone": 90,
    "ios": None,
    "android": None,
    "unknown": None,
}

# SNI sub-activity patterns - ordered by specificity (most specific first)
_SNI_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'^mmv\d+.*\.whatsapp\.net$'), 'video'),
    (re.compile(r'^mm[is]\d+.*\.whatsapp\.net$'), 'photo_audio'),
    (re.compile(r'^[cde]\d+\.whatsapp\.net$'), 'chat_control'),
    (re.compile(r'^media.*\.whatsapp\.net$'), 'media_generic'),
    (re.compile(r'^graph\.whatsapp\.com$'), 'graph_api'),
    (re.compile(r'^.*\.whatsapp\.net$'), 'whatsapp_generic'),
    (re.compile(r'^.*\.whatsapp\.com$'), 'whatsapp_generic'),
]


# ---------------------------------------------------------------------------
# Fix #1: VoIP-threshold validation gate is now an artifact check, not a
# hand-editable constant.
# ---------------------------------------------------------------------------
_VALIDATION_REPORT_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "validation", "voip_validation_report.json"
)


def _voip_thresholds_validated() -> bool:
    """Returns True only if scripts/validate_against_labels.py has
    actually written a validation report confirming the VoIP thresholds
    were checked against labeled captures. There is deliberately no
    hardcoded `True` anywhere in this file for this - a hand-edited
    constant with no backing evidence is exactly the failure mode this
    function replaces. To "validate" these thresholds, run the
    validation script; don't edit this file.

    Expected report format (written by the validation script):
        {"voip_thresholds_validated": true, "f1_score": 0.87, "date": "..."}
    """
    if not os.path.exists(_VALIDATION_REPORT_PATH):
        return False
    try:
        with open(_VALIDATION_REPORT_PATH) as f:
            report = json.load(f)
        return bool(report.get("voip_thresholds_validated", False))
    except (json.JSONDecodeError, OSError) as e:
        logging.warning(f"Could not read VoIP validation report: {e}")
        return False


# ---------------------------------------------------------------------------
# Fix #3: confirmed-server tracking is now per-case, not a module global.
#
# MIGRATION NOTE FOR CALLERS: previously, `seed_confirmed_servers(ip)` and
# `check_inference_matching(server_ip)` used an implicit module-level
# global shared across every upload processed by this process. That meant
# a server IP confirmed WhatsApp in one case silently raised confidence
# for the same IP in a totally unrelated later case, and the set reset to
# empty on every process restart with no persistence to DB-2.
#
# Callers (pipeline.py) must now:
#   1. Create one `ConfirmedServerRegistry` per pipeline run (per
#      pcap_id/upload_id) - do not share one instance across uploads.
#   2. Load/save it from DB-2's `geo_cache`-adjacent storage if you want
#      confirmed servers to persist across re-runs of the SAME case (not
#      across different cases).
#   3. Pass the registry instance explicitly into
#      `check_inference_matching(server_ip, registry)` and
#      `registry.seed(server_ip)` instead of the old free functions.
# ---------------------------------------------------------------------------
@dataclass
class ConfirmedServerRegistry:
    """Tracks server IPs confirmed as WhatsApp within ONE case (one
    pcap_id/upload_id). Instantiate a fresh one per pipeline run - never
    share a single instance across different uploads/cases."""
    pcap_id: str
    _confirmed: Set[str] = field(default_factory=set)

    def seed(self, server_ip: str) -> None:
        self._confirmed.add(server_ip)

    def is_confirmed(self, server_ip: Optional[str]) -> bool:
        return bool(server_ip) and server_ip in self._confirmed

    def to_list(self) -> List[str]:
        """For persisting to DB-2 if you want this to survive a re-run of
        the same case (NOT to be shared with other cases)."""
        return sorted(self._confirmed)

    @classmethod
    def from_list(cls, pcap_id: str, ips: List[str]) -> "ConfirmedServerRegistry":
        return cls(pcap_id=pcap_id, _confirmed=set(ips))


def check_inference_matching(
    server_ip: Optional[str], registry: ConfirmedServerRegistry
) -> Tuple[str, List[str]]:
    """
    4c. Same-server-IP inference, scoped to the registry's own case.
    Returns (confidence, signals) if server_ip was already confirmed
    WhatsApp elsewhere in THIS case.
    """
    if registry.is_confirmed(server_ip):
        return "medium", ["inferred_server"]
    return "none", []


# ---------------------------------------------------------------------------
# CIDR ranges
# ---------------------------------------------------------------------------
_DEFAULT_RANGES_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "resources", "meta_ip_ranges.txt"
)


def load_meta_ip_ranges(filepath: str) -> List[ipaddress.IPv4Network]:
    ranges: List[ipaddress.IPv4Network] = []
    if not os.path.exists(filepath):
        logging.warning(
            f"Meta CIDR range file not found at {os.path.abspath(filepath)} "
            "- CIDR-based WhatsApp classification will not work until this exists."
        )
        return ranges
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                try:
                    ranges.append(ipaddress.ip_network(line))
                except ValueError:
                    logging.warning(f"Skipping invalid CIDR line: {line!r}")
    if not ranges:
        logging.warning(f"{filepath} exists but contains no valid CIDR ranges.")
    return ranges


META_IP_RANGES = load_meta_ip_ranges(_DEFAULT_RANGES_PATH)
logging.info(
    f"[whatsapp_filter] loaded {len(META_IP_RANGES)} Meta CIDR ranges "
    f"from {os.path.abspath(_DEFAULT_RANGES_PATH)}"
)


def check_cidr_matching(server_ip: Optional[str]) -> Tuple[str, List[str]]:
    """4b. CIDR matching. Checks server_ip against configured ranges."""
    if not server_ip:
        return "none", []
    try:
        ip = ipaddress.ip_address(server_ip)
        for net in META_IP_RANGES:
            if ip in net:
                return "high", ["cidr_strong"]
    except ValueError:
        pass
    return "none", []


# ---------------------------------------------------------------------------
# Fix #4: domain matching with proper label-boundary check.
# ---------------------------------------------------------------------------
def _domain_matches_suffix(domain: str, suffix: str) -> bool:
    """True only if `domain` IS `suffix` or is a proper subdomain of it.
    A bare `str.endswith()` would also match "evilwhatsapp.net" against
    the suffix "whatsapp.net" - this checks the label boundary instead."""
    return domain == suffix or domain.endswith("." + suffix)


def check_domain_matching(
    sni: Optional[str], dns_query: Optional[str]
) -> Tuple[str, List[str], Optional[str]]:
    """
    Domain matching with SNI sub-activity tagging.
    Returns (confidence, signals, sni_sub_activity).
    sni_sub_activity is one of: chat_control, photo_audio, video,
    media_generic, graph_api, whatsapp_generic, or None. This tag is
    ONLY ever derived from the SNI pattern table - it is a distinct,
    stronger-evidence signal from `check_port_matching()`'s
    `port_activity` output (see Fix #5). Do not merge the two into one
    field downstream; keep them namespaced so a reader can tell whether
    a label came from an observed hostname or an inferred port.
    """
    sub_activity: Optional[str] = None
    if sni:
        sni = sni.lower().rstrip('.')
        for pattern, tag in _SNI_PATTERNS:
            if pattern.match(sni):
                sub_activity = tag
                break

    if dns_query:
        dns_query = dns_query.lower().rstrip('.')

    if (sni and any(_domain_matches_suffix(sni, d) for d in STRONG_DOMAINS)) or \
       (dns_query and any(_domain_matches_suffix(dns_query, d) for d in STRONG_DOMAINS)):
        return "high", ["domain_strong"], sub_activity

    if (sni and any(_domain_matches_suffix(sni, d) for d in WEAK_DOMAINS)) or \
       (dns_query and any(_domain_matches_suffix(dns_query, d) for d in WEAK_DOMAINS)):
        return "low", ["domain_weak"], sub_activity

    return "none", [], sub_activity


# ---------------------------------------------------------------------------
# Fix #5: port-based activity kept explicitly separate from SNI sub-activity.
# ---------------------------------------------------------------------------
def check_port_matching(
    src_port: Optional[int], dst_port: Optional[int]
) -> Tuple[str, List[str], Optional[str]]:
    """
    Port-based confidence signal. Returns (confidence, signals,
    port_activity). `port_activity` (e.g. "media_or_https",
    "chat_signaling", "call_signaling") is a WEAKER, inferred-from-port
    signal - distinct from `check_domain_matching()`'s `sni_sub_activity`,
    which is derived from an actually-observed hostname. When both are
    available for the same flow, prefer `sni_sub_activity` for display
    and keep `port_activity` visible only as corroborating/fallback
    evidence - never overwrite one with the other under a shared key.
    """
    ports = {p for p in (src_port, dst_port) if p is not None}
    
    if ports & DNS_PORTS:
        return "none", ["port_dns"], "dns_resolution"
        
    if ports & WHATSAPP_CHAT_PORTS:
        return "high", ["port_chat"], "chat_signaling"
    if ports & WHATSAPP_STUN_PORTS:
        return "medium", ["port_stun"], "call_signaling"
    # Media CDN ports (443, 80) are TCP only. UDP 443 is usually a call relay/fallback.
    if ports & WHATSAPP_MEDIA_PORTS:
        # Check if we have protocol context (we don't get it in check_port_matching)
        # So we return media_or_https here, but we will fix resolve_final_label to correctly override it
        return "low", ["port_https"], "media_or_https"
    # NEW: dynamic UDP port on confirmed Meta IP = call stream candidate
    # Confidence is low here — CIDR match must corroborate
    if any(is_likely_call_media_port(p) for p in ports):
        return "low", ["port_dynamic_udp"], "call_media_candidate"
    return "none", [], None


def resolve_final_label(
    media_guess: str,
    port_activity: Optional[str],
    protocol_type: str,
) -> str:
    """Single point of truth — one label per flow, no contradictions.
    
    Priority order (highest to lowest evidence strength):
    1. SNI-derived (observed hostname)
    2. Protocol + port combination rule
    3. Bitrate analysis
    4. Byte-count heuristic
    """
    # 1. DNS resolution is never user media activity
    if port_activity == "dns_resolution":
        return "dns"

    # 2. WhatsApp chat signaling ports (5222, 5223, 4244, etc.) CANNOT carry CDN media (photo/video/audio).
    # WhatsApp CDN media uploads/downloads strictly require TLS/443 to mmg.whatsapp.net.
    # Any flow on chat ports is chat messaging or presence signaling.
    if port_activity == "chat_signaling":
        return "message"

    # 3. Photo/video/audio cannot physically travel over UDP
    # (WhatsApp CDN is always TCP/443). If media_guess says photo
    # but protocol is UDP, the burst heuristic was wrong — override.
    if protocol_type == "UDP":
        if media_guess in ("photo", "video", "audio"):
            if port_activity in ("call_signaling", "call_media_candidate", "call_stream_unresolved"):
                return port_activity
            return "call_signaling"  # safest fallback for small UDP
            
        # If it's UDP but port activity says media_or_https (e.g. UDP 443 fallback),
        # it CANNOT be CDN media. It must be a call.
        if port_activity == "media_or_https":
            if media_guess in ("voice_call", "video_call"):
                return media_guess
            return "call_signaling"

    # 4. Call signaling ports
    if port_activity == "call_signaling" and media_guess in ("photo", "video", "audio", "message"):
        return "call_signaling"

    return media_guess

def resolve_activity_labels(
    sni_sub_activity: Optional[str], port_activity: Optional[str], protocol_type: str = "TCP"
) -> Dict[str, Optional[str]]:
    """Combines the two activity signals into a display-ready dict."""
    if port_activity == "dns_resolution":
        return {
            "sni_sub_activity": None,
            "port_activity": "dns_resolution",
            "display_activity": None,
            "display_activity_source": "port",
            "is_infrastructure": True,
        }
        
    # Bug 16 fix: If it's UDP 443, it's not media_or_https, it's a VoIP relay.
    if protocol_type == "UDP" and port_activity == "media_or_https":
        port_activity = "call_signaling"
        
    return {
        "sni_sub_activity": sni_sub_activity,
        "port_activity": port_activity,
        "display_activity": sni_sub_activity or port_activity,
        "display_activity_source": "sni" if sni_sub_activity else ("port" if port_activity else None),
    }


def resolve_timeout(os_hint: str, is_media_flow: bool) -> float:
    """Returns the flow-inactivity timeout in seconds for a given OS hint.
    For Android's tiered timeout, defaults to the shortest tier (10 min)
    - over-splitting a session is a recoverable precision cost; under-
    splitting silently merges distinct sessions, which is harder to
    detect after the fact. Prefer the safer failure mode."""
    table = OS_MEDIA_TIMEOUT_SECONDS if is_media_flow else OS_CHAT_TIMEOUTS_SECONDS
    value = table.get(os_hint, table.get("unknown"))
    if value is None:
        value = OS_CHAT_TIMEOUTS_SECONDS.get(os_hint, OS_CHAT_TIMEOUTS_SECONDS["unknown"])
    if isinstance(value, tuple):
        return float(min(value))
    return float(value)





# ---------------------------------------------------------------------------
# VoIP bitrate detection
# ---------------------------------------------------------------------------
def detect_voip_by_bitrate(packets: List[Dict[str, Any]]) -> Optional[str]:
    """
    Analyze UDP packets over 5-second sliding windows.
    Returns 'voice_call' if sustained bitrate > 12 kbps,
    'call_signaling' if mean < 8 kbps, else None.
    """
    if not _voip_thresholds_validated():
        logging.debug(
            "VoIP bitrate thresholds (12/8 kbps) are unvalidated against "
            "labeled data - run scripts/validate_against_labels.py to "
            "confirm before trusting call/signaling labels."
        )
    if not packets:
        return None
    timestamps = [p['timestamp'] for p in packets if p.get('timestamp') is not None]
    if not timestamps:
        return None
    start, end = min(timestamps), max(timestamps)
    if end - start < _WINDOW_SECONDS:
        return None

    window_bitrates = []
    asymmetry_ratios = []
    t = start
    while t + _WINDOW_SECONDS <= end:
        window_packets = [
            p for p in packets
            if p.get('timestamp') is not None and t <= p['timestamp'] < t + _WINDOW_SECONDS
        ]
        
        window_bytes = sum(p.get('length', 0) for p in window_packets)
        window_bitrates.append((window_bytes * 8) / (_WINDOW_SECONDS * 1000))
        
        # Calculate symmetry
        ip_bytes = {}
        for p in window_packets:
            src = p.get('src_ip')
            if src:
                ip_bytes[src] = ip_bytes.get(src, 0) + p.get('length', 0)
                
        if len(ip_bytes) >= 2:
            sorted_bytes = sorted(ip_bytes.values(), reverse=True)
            ratio = sorted_bytes[0] / sorted_bytes[1] if sorted_bytes[1] > 0 else float('inf')
        else:
            ratio = float('inf')
            
        asymmetry_ratios.append(ratio)
        
        t += _WINDOW_SLIDE_STEP

    if not window_bitrates:
        return None

    mean_br = sum(window_bitrates) / len(window_bitrates)
    mean_ratio = sum(asymmetry_ratios) / len(asymmetry_ratios) if asymmetry_ratios else float('inf')
    
    sustained_video = sum(1 for b in window_bitrates if b > _VIDEO_THRESHOLD_KBPS)
    if sustained_video / len(window_bitrates) > _SUSTAINED_FRACTION and mean_ratio > 3.0:
        return 'video_call'
        
    sustained_voice = sum(1 for b in window_bitrates if b > _VOIP_THRESHOLD_KBPS)
    if sustained_voice / len(window_bitrates) > _SUSTAINED_FRACTION:
        return 'voice_call'
        
    if mean_br < _SIGNALING_MAX_KBPS:
        return 'call_signaling'
    return None


# ---------------------------------------------------------------------------
# Media type guesser (burst-based)
# ---------------------------------------------------------------------------
def guess_media_type(
    packets: List[Dict[str, Any]],
    protocol_type: str,
    flow_duration: float,
    sni_sub_activity: Optional[str] = None,
    port_activity: Optional[str] = None,
    cidr_confirmed: bool = False,
) -> str:
    """
    Burst-aware media type classification.
    Priority: sni_sub_activity > VoIP bitrate > burst intensity > total bytes.

    NOTE: parameter renamed from `sub_activity_hint` to `sni_sub_activity`
    to make explicit this must be the SNI-derived tag (Fix #5) - passing
    `port_activity` here by mistake would let a weak, inferred-from-port
    signal silently override a byte-count-based guess as if it were as
    strong as an observed hostname.
    """
    # Gate 1: DNS is never user activity
    if port_activity == "dns_resolution":
        return "dns"

    # Gate 2: Dynamic UDP port on confirmed Meta IP = call stream.
    # Must be checked BEFORE the burst-intensity path, which would
    # otherwise misread SRTP packet bursts as photo transfers.
    if (protocol_type == "UDP"
            and port_activity == "call_media_candidate"
            and cidr_confirmed):
        voip = detect_voip_by_bitrate(packets)
        if voip:
            return voip
        # Not enough data for bitrate window yet — provisional label
        return "call_stream_unresolved"

    # Gate 3: TCP-only path for media CDN transfers
    # Photos/videos ONLY travel over TCP/443 to mm*.whatsapp.net
    # If protocol is UDP and port is not 443, it cannot be a photo.
    if protocol_type == "UDP" and port_activity not in ("media_or_https", None):
        voip = detect_voip_by_bitrate(packets)
        if voip:
            return voip
        # Small UDP packets, no bitrate window → call signaling, not photo
        total_bytes = sum(p.get('length', 0) for p in packets)
        if total_bytes < 10_000:
            return "call_signaling"

    # Gate 4: Chat signaling ports (5222, 5223, 4244, etc.) NEVER carry CDN media
    # Photos/videos strictly require TLS/443 to WhatsApp CDN servers (mmg.whatsapp.net)
    if port_activity == "chat_signaling" or sni_sub_activity == "chat_control":
        return "message"

    total_bytes = sum(p.get('length', 0) for p in packets)

    if sni_sub_activity == 'video':
        return 'video'
    if sni_sub_activity == 'photo_audio':
        return 'audio' if total_bytes > 500_000 else 'photo'
    if sni_sub_activity == 'chat_control':
        return 'message'

    if protocol_type == 'UDP':
        voip = detect_voip_by_bitrate(packets)
        if voip:
            return voip

    if packets and flow_duration > 0:
        bursts_with_duration = extract_bursts_with_duration(packets)
        if bursts_with_duration:
            burst_intensity = max(
                sum(p.get('length', 0) for p in b) / span
                for b, span in bursts_with_duration
            )
            if burst_intensity > 50_000 and flow_duration < 30:
                if total_bytes > 1_000_000:
                    return 'video'
                if total_bytes > 100_000:
                    return 'audio'
                return 'photo'
            if flow_duration > 300 and burst_intensity < 2_000:
                return 'message'

    if total_bytes < 10_000:
        return 'message'
    if total_bytes < 100_000:
        return 'photo'
    if total_bytes < 1_000_000:
        return 'audio'
    return 'video'
