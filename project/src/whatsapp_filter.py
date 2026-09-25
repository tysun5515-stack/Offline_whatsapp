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

Fix log (this revision — permanent fix pass):
  1. VoIP-validation gate is now read from a validation report file on
     disk, produced only by scripts/validate_against_labels.py.
  2. Burst intensity is now computed per-burst, not per-flow.
  3. ConfirmedServerRegistry is scoped per pcap_id/upload_id.
  4. Domain matching now checks label boundaries.
  5. SNI-derived sub-activity and port-derived activity are namespaced.
  6. [NEW] Acceptance gate: is_whatsapp_anchored() must be satisfied before
     guess_media_type() is invoked. Unanchored flows → 'unclassified'.
  7. [NEW] video_call detection removes the >3x asymmetry requirement.
     Detection now relies on sustained high bitrate + median packet size.
  8. [NEW] mmi*/mms* CDN flows classified as 'media_transfer' (unified)
     instead of forcing an arbitrary 500 KB audio/photo split. mmv* stays
     video. Only flows where mmv* SNI is present are labelled 'video'.
  9. [NEW] TCP 5222 port activity renamed 'xmpp_multiplex' to reflect that
     the FunXMPP stream carries both text chat AND call setup signaling.
     resolve_final_label() respects this and defaults to 'call_signaling'
     for undecorated xmpp_multiplex flows.
  10.[NEW] Size-based fallback (< 10 KB → 'message', etc.) is ONLY applied
     when cidr_confirmed=True. Non-Meta, non-SNI flows → 'unclassified'.
  11.[NEW] chat_signaling 'message' return requires a domain or CIDR anchor;
     unanchored TCP 5222 noise → 'unclassified'.
  12.[NEW] call_stream_unresolved is preserved as a valid forensic state.
     It surfaces in the UI with the badge 'Encrypted Call (Unanchored)'.
     It is NOT force-resolved to voice_call based on duration alone.
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

def is_likely_call_media_port(port: Optional[int], protocol_type: Optional[str]) -> bool:
    """True only for a server-side dynamic UDP call-media port."""
    if port is None or (protocol_type or "").upper() != "UDP":
        return False
    # Port 443 is a dedicated media port (QUIC CDN uploads); it is NOT a
    # dynamic call-media port. Exclude it explicitly so callers cannot
    # accidentally classify QUIC media traffic as VoIP.
    if port in WHATSAPP_MEDIA_PORTS:
        return False
    return 1024 <= port <= 65535

# VoIP bitrate thresholds - see _voip_thresholds_validated() for the gate
_VOIP_THRESHOLD_KBPS = 12.0   # sustained above → voice_call
_VIDEO_THRESHOLD_KBPS = 50.0  # sustained above + large packets → video_call
_SIGNALING_MAX_KBPS = 8.0     # mean below → call_signaling
_WINDOW_SECONDS = 5.0
_WINDOW_SLIDE_STEP = 1.0
_SUSTAINED_FRACTION = 0.5     # fraction of windows above threshold

# Fix A: Video detection by packet size, not asymmetry ratio.
# SRTP-wrapped video frames: 500–1400 bytes.
# Opus voice payloads: 20–120 bytes.
# A median > 400 bytes in sustained high-bitrate flows = video.
_VIDEO_PACKET_SIZE_MEDIAN_BYTES = 400

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

# SNI sub-activity patterns - ordered by specificity (most specific first).
#
# DESIGN NOTE (Fix C / Fix 8):
#   mmv*.whatsapp.net  → 'video'          (video CDN — unambiguous)
#   mmi*/mms*.whatsapp.net → 'media_transfer'  (photos, voice notes, docs;
#       cannot be distinguished by size alone — unified label prevents the
#       old 500 KB audio/photo split from misclassifying HD photos as audio)
#   c/d/e*.whatsapp.net  → 'chat_control' (FunXMPP/XMPP control plane)
_SNI_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'^mmv\d+.*\.whatsapp\.net$'),    'video'),
    (re.compile(r'^mm[is]\d+.*\.whatsapp\.net$'), 'media_transfer'),
    (re.compile(r'^[cde]\d+\.whatsapp\.net$'),    'chat_control'),
    (re.compile(r'^media.*\.whatsapp\.net$'),      'media_generic'),
    (re.compile(r'^graph\.whatsapp\.com$'),        'graph_api'),
    (re.compile(r'^.*\.whatsapp\.net$'),           'whatsapp_generic'),
    (re.compile(r'^.*\.whatsapp\.com$'),           'whatsapp_generic'),
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
    server_port: Optional[int], protocol_type: Optional[str]
) -> Tuple[str, List[str], Optional[str]]:
    """Return protocol-aware confidence from the normalized server port only.

    Port activity labels (Fix F / Fix 9):
      'dns_resolution'   — Port 53; infrastructure only.
      'xmpp_multiplex'   — TCP 5222/5223/5228/4244/5242; FunXMPP stream
                           carries BOTH text chat and call setup. Not
                           collapsed to 'message' — see resolve_final_label().
      'call_signaling'   — UDP 3478 STUN; call ICE/TURN signaling.
      'media_or_https'   — TCP 443; could be CDN media or generic HTTPS.
      'call_media_candidate' — Dynamic UDP (1024–65535); candidate call media
                               port, requires CIDR confirmation to escalate.
    """
    protocol = (protocol_type or "").upper()
    if server_port in DNS_PORTS:
        return "none", ["port_dns"], "dns_resolution"
    if server_port in WHATSAPP_CHAT_PORTS:
        # Fix F: renamed from 'chat_signaling' to 'xmpp_multiplex'.
        # TCP 5222 carries FunXMPP which multiplexes text chat, call
        # setup offers, STUN candidates, and presence — not text-only.
        return "high", ["port_chat"], "xmpp_multiplex"
    if server_port in WHATSAPP_STUN_PORTS:
        return "medium", ["port_stun"], "call_signaling"
    if server_port in WHATSAPP_MEDIA_PORTS:
        if protocol == "TCP":
            return "low", ["port_https"], "media_or_https"
        else:
            # UDP/443 = QUIC. Could be CDN media upload OR a TURN relay on 443.
            # Label separately; downstream uses SNI + CIDR + directionality to resolve.
            return "low", ["port_quic"], "quic_media_or_relay"
    # Only truly dynamic ports (>1024, NOT 443) are call media candidates.
    # is_likely_call_media_port() now also excludes 443 internally (Change 1).
    if is_likely_call_media_port(server_port, protocol):
        return "low", ["port_dynamic_udp"], "call_media_candidate"
    return "none", [], None


def resolve_final_label(
    media_guess: str,
    port_activity: Optional[str],
    protocol_type: str,
    sni_sub_activity: Optional[str] = None,
) -> str:
    """Single point of truth — one label per flow, no contradictions.

    Priority order (highest to lowest evidence strength):
    1. DNS infrastructure (always wins)
    2. Protocol + port combination rules
    3. Bitrate / burst analysis result (media_guess)
    4. Unclassified fallthrough

    Fix F / Fix 9: xmpp_multiplex replaces the old 'chat_signaling' port_activity.
    The FunXMPP stream on TCP 5222/5223 carries both text chat AND call
    setup offers (<call><offer>). Without decryption we cannot split the two,
    so the conservative label is 'call_signaling' (superset). Only when the
    SNI confirms a text-only CDN (sni_sub_activity='chat_control') do we
    label it 'message'.
    """
    # 1. DNS resolution is never user media activity
    if port_activity == "dns_resolution":
        return "dns"

    # 2. xmpp_multiplex (TCP 5222/5223/5228/4244/5242) — Fix F
    # FunXMPP is a multiplexed channel: text chat + call signaling.
    # Cannot collapse to 'message' without payload inspection.
    if port_activity == "xmpp_multiplex":
        if sni_sub_activity == "chat_control":
            return "message"    # SNI explicitly confirms text CDN
        return "call_signaling" # conservative: could be call setup

    # QUIC CDN / TURN-relay on UDP/443 — must be handled BEFORE the generic
    # UDP override below, which would downgrade a correct "photo" label to
    # "call_stream_unresolved".
    if port_activity == "quic_media_or_relay":
        if media_guess in ("photo", "audio", "video", "media_transfer", "media_generic"):
            return media_guess   # Media label confirmed — preserve it.
        if media_guess == "message":
            return "message"    # QUIC chat/control channel correctly identified
        if media_guess in ("voice_call", "video_call", "call_signaling",
                           "call_stream_unresolved"):
            return media_guess   # Call-via-TURN confirmed by bitrate analysis.
        return "call_stream_unresolved"  # Unknown QUIC flow to Meta IP — uncertain, not absent.

    # 3. Photo/video/audio cannot physically travel over UDP
    # (WhatsApp CDN is always TCP/443). If media_guess says photo
    # but protocol is UDP, the burst heuristic was wrong — override.
    if protocol_type == "UDP":
        if media_guess in ("photo", "video", "audio", "message", "media_transfer"):
            if port_activity in ("call_signaling", "call_media_candidate", "call_stream_unresolved"):
                if media_guess == "message":
                    return "call_signaling"  # Small UDP: just signaling
                return "call_stream_unresolved"  # Large UDP: call media, not CDN files
            return "call_signaling"  # safest fallback for small UDP

        # UDP 443 fallback — cannot be CDN media, must be a call relay
        if port_activity == "media_or_https":
            if media_guess in ("voice_call", "video_call"):
                return media_guess
            return "call_stream_unresolved" if media_guess in ("photo", "video", "audio", "media_transfer") else "call_signaling"

    # 4. STUN / call signaling port overrides spurious media guesses
    if port_activity == "call_signaling" and media_guess in ("photo", "video", "audio", "message", "media_transfer"):
        return "call_signaling"

    return media_guess

def resolve_activity_labels(
    sni_sub_activity: Optional[str], 
    port_activity: Optional[str], 
    protocol_type: str = "TCP",
    media_guess: Optional[str] = None,
) -> Dict[str, Optional[str]]:
    """Combines the two activity signals into a display-ready dict.

    Fix F: xmpp_multiplex is a valid port_activity value (replaces old
    'chat_signaling'). Kept as-is here so the DB stores the accurate
    technical value. UI label mapping is in app.py's _MEDIA_LABEL_MAP.
    """
    if port_activity == "dns_resolution":
        return {
            "sni_sub_activity": None,
            "port_activity": "dns_resolution",
            "display_activity": None,
            "display_activity_source": "port",
            "is_infrastructure": True,
        }

    # UDP 443 is never CDN media — it's a VoIP relay port.
    if protocol_type == "UDP" and port_activity == "media_or_https":
        port_activity = "call_signaling"

    # QUIC (UDP/443): map internal token to analyst-readable display label.
    # The technical port_activity is preserved for DB storage; display_activity
    # uses the human-readable form for the UI layer.
    if port_activity == "quic_media_or_relay" and media_guess == "message":
        _QUIC_DISPLAY_LABEL = "chat_control"
    else:
        _QUIC_DISPLAY_LABEL = "media_cdn_upload"

    return {
        "sni_sub_activity": sni_sub_activity,
        "port_activity": port_activity,
        "display_activity": (
            sni_sub_activity
            or (_QUIC_DISPLAY_LABEL if port_activity == "quic_media_or_relay" else None)
            or port_activity
        ),
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
def _median_packet_size(packets: List[Dict[str, Any]]) -> float:
    """Median payload length across packets. Used to separate video_call
    (large SRTP frames 500–1400 B) from voice_call (Opus 20–120 B).
    Fix A: replaces the unreliable >3x directional asymmetry ratio."""
    sizes = sorted(p.get('length', 0) for p in packets if p.get('length'))
    if not sizes:
        return 0.0
    mid = len(sizes) // 2
    return float(sizes[mid] if len(sizes) % 2 else (sizes[mid - 1] + sizes[mid]) / 2.0)


def is_whatsapp_anchored(
    sni_sub_activity: Optional[str],
    port_activity: Optional[str],
    cidr_confirmed: bool,
) -> bool:
    """Acceptance gate (Fix 6): returns True only if this flow has at least
    one verified WhatsApp anchor BEFORE media guessing is attempted.

    Anchors (in descending evidence strength):
      1. WhatsApp SNI observed (sni_sub_activity is not None)
      2. Remote IP in a confirmed Meta/WhatsApp CIDR block
      3. Dedicated WhatsApp port (chat ports, STUN, dynamic UDP candidate)

    Flows that pass none of these tests are returned as 'unclassified'
    without reaching the media-guessing layer. This prevents generic HTTPS
    traffic (banking apps, CDNs, OS updates) from being labelled as
    WhatsApp photos/audio/video based solely on transfer size.
    """
    if sni_sub_activity is not None:
        return True
    if cidr_confirmed:
        return True
    # Dedicated WhatsApp ports are strong anchors; generic 443 is not
    if port_activity in (
        "xmpp_multiplex",    # TCP 5222/5223/5228/4244/5242
        "call_signaling",    # UDP 3478 STUN
        "call_media_candidate",  # dynamic UDP post-STUN
        "quic_media_or_relay",
    ):
        return True
    return False


def detect_voip_by_bitrate(packets: List[Dict[str, Any]]) -> Optional[str]:
    """
    Analyze UDP packets over 5-second sliding windows.

    Returns:
      'video_call'      — sustained > 50 kbps AND median packet > 400 B
      'voice_call'      — sustained > 12 kbps (and not video)
      'call_signaling'  — mean < 8 kbps
      None              — insufficient data (flow < 5 s)

    Fix A: video_call detection no longer requires a >3x directional
    asymmetry ratio.  In a normal 2-way video call both participants
    transmit video simultaneously (ratio ≈ 1.0–1.5).  The asymmetry
    requirement was correctly identifying 1-way screen shares, but
    failing every standard 2-way video call.  Median packet size
    (SRTP video frames ≫ Opus voice payloads) is the replacement
    discriminator and applies equally to symmetric and asymmetric calls.
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
    
    _MIN_WINDOW_SECONDS = 1.0   # Minimum flow duration to attempt any bitrate analysis
    if end - start < _MIN_WINDOW_SECONDS:
        # Too short for any meaningful bitrate analysis.
        return None

    # Short flows (between _MIN_WINDOW and _WINDOW_SECONDS):
    # Compute a single whole-flow bitrate. Avoids partial-window division errors
    # that occur when the sliding window overshoots the flow's end timestamp.
    if end - start < _WINDOW_SECONDS:
        flow_bytes = sum(p.get("length", 0) for p in packets)
        flow_duration_local = end - start
        single_bitrate_kbps = (flow_bytes * 8) / (flow_duration_local * 1000)
        if single_bitrate_kbps > _VIDEO_THRESHOLD_KBPS:
            median_pkt = _median_packet_size(packets)
            if median_pkt > _VIDEO_PACKET_SIZE_MEDIAN_BYTES:
                return "video_call"
            return "voice_call"
        if single_bitrate_kbps > _VOIP_THRESHOLD_KBPS:
            return "voice_call"
        if single_bitrate_kbps < _SIGNALING_MAX_KBPS:
            return "call_signaling"
        return None  # Ambiguous short flow

    window_bitrates: List[float] = []
    t = start
    while t + _WINDOW_SECONDS <= end:
        window_packets = [
            p for p in packets
            if p.get('timestamp') is not None and t <= p['timestamp'] < t + _WINDOW_SECONDS
        ]
        window_bytes = sum(p.get('length', 0) for p in window_packets)
        window_bitrates.append((window_bytes * 8) / (_WINDOW_SECONDS * 1000))
        t += _WINDOW_SLIDE_STEP

    if not window_bitrates:
        return None

    mean_br = sum(window_bitrates) / len(window_bitrates)

    # Fix A: video detection — sustained high bitrate + large median packet size.
    # No asymmetry ratio: symmetric 2-way calls are correctly classified.
    sustained_video = sum(1 for b in window_bitrates if b > _VIDEO_THRESHOLD_KBPS)
    if sustained_video / len(window_bitrates) > _SUSTAINED_FRACTION:
        median_pkt = _median_packet_size(packets)
        if median_pkt > _VIDEO_PACKET_SIZE_MEDIAN_BYTES:
            return 'video_call'
        # High bitrate but small packets → aggressive voice codec, not video
        return 'voice_call'

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
    client_ip: Optional[str] = None,
) -> str:
    """
    Burst-aware media type classification.

    ACCEPTANCE GATE (Fix 6): This function must ONLY be called for flows
    that satisfy is_whatsapp_anchored(). The pipeline enforces this; the
    gate is also re-checked internally for defense in depth.

    Priority order:
      1. DNS infrastructure signal → 'dns'
      2. is_whatsapp_anchored() gate → 'unclassified' if fails
      3. SNI-derived sub-activity (strongest per-flow evidence)
      4. xmpp_multiplex port handling (Fix F)
      5. UDP call-media paths (CIDR-confirmed, bitrate-gated)
      6. Burst intensity heuristic (TCP CDN transfers)
      7. CIDR-gated size fallback (Fix B) — only if cidr_confirmed

    Fix C: 'photo_audio' SNI replaced by 'media_transfer' (unified CDN label
    for mmi*/mms* servers). No 500 KB audio/photo split — that threshold
    misclassified HD photos and PDF documents as voice notes.

    Fix D: 'message' fallback now requires a domain or CIDR anchor.
    """
    # ── Gate 1: DNS infrastructure — never user activity ──────────────────
    if port_activity == "dns_resolution":
        return "dns"

    # ── Gate 2: Acceptance gate — defense in depth ────────────────────────
    # pipeline.py is the primary enforcer; this catches any caller that
    # skips the gate and passes an unanchored flow directly.
    if not is_whatsapp_anchored(sni_sub_activity, port_activity, cidr_confirmed):
        return "unclassified"

    total_bytes = sum(p.get('length', 0) for p in packets)

    # ── Gate 3: SNI sub-activity (strongest signal) ───────────────────────
    if sni_sub_activity == 'video':
        # mmv*.whatsapp.net — dedicated video CDN, unambiguous.
        return 'video'

    if sni_sub_activity == 'media_transfer':
        # Fix C: mmi*/mms* CDN carries photos, voice notes, and documents.
        # Cannot be split by size alone — use burst shape as discriminator.
        # Voice notes (Opus ~32 kbps): uniform low-rate stream, small total.
        # Photos / PDFs: burst-heavy, potentially very large.
        bursts_with_duration = extract_bursts_with_duration(packets)
        if bursts_with_duration:
            burst_intensity = max(
                sum(p.get('length', 0) for p in b) / span
                for b, span in bursts_with_duration
            )
            # High burst intensity = large file sent fast = photo or document
            if burst_intensity > 30_000:
                return 'photo'
        # Low burst + small total → likely voice note/audio attachment.
        # 200 KB threshold: 30-second Opus voice note ≈ 120 KB at 32 kbps.
        # Validated range for audio: < 200 KB. Larger = ambiguous → photo.
        return 'audio' if total_bytes < 200_000 else 'photo'

    if sni_sub_activity == 'chat_control':
        # c/d/e*.whatsapp.net — text CDN. Fix D: anchor confirmed via SNI.
        return 'message'

    # ── Gate 4: xmpp_multiplex (TCP 5222/5223/5228/4244/5242) ─────────────
    # Fix F: FunXMPP carries both text chat and call setup.
    # Handled in resolve_final_label(); return conservative placeholder.
    if port_activity == "xmpp_multiplex":
        # Fix D: only tag as 'message' if we have a CIDR or SNI anchor.
        # Unanchored TCP 5222 could be any XMPP client (Jabber, IoT, etc.).
        if cidr_confirmed or sni_sub_activity is not None:
            return "message"    # will be re-evaluated in resolve_final_label
        return "unclassified"

    # ── Gate 5: Dynamic UDP on confirmed Meta IP = call stream ────────────
    # Must be checked BEFORE the burst-intensity path, which would
    # misread SRTP packet bursts as photo transfers.
    if protocol_type == "UDP" and port_activity in ("call_media_candidate", "quic_media_or_relay"):
        if port_activity == "quic_media_or_relay":
            # UDP/443 QUIC: could be CDN media upload OR TURN relay.
            # Priority 1: SNI is the strongest signal — trust it directly.
            if sni_sub_activity in ("video", "media_transfer", "media_generic"):
                return sni_sub_activity
            
            # Priority 2: Directionality — uploads are >70% outbound bytes.
            # Use explicit client_ip; do NOT infer from packet order.
            if client_ip:
                outbound_bytes = sum(p.get("length", 0) for p in packets
                                     if p.get("src_ip") == client_ip)
                total_b = sum(p.get("length", 0) for p in packets) or 1
                outbound_ratio = outbound_bytes / total_b
            else:
                outbound_ratio = 0.5  # unknown — treat as symmetric
                
            bursts_with_duration = extract_bursts_with_duration(packets)
            if bursts_with_duration:
                burst_intensity = max(
                    sum(p.get("length", 0) for p in b) / span
                    for b, span in bursts_with_duration
                )
                if burst_intensity > 30_000 and outbound_ratio > 0.70:
                    # High burst + outbound dominant = CDN upload, NOT a call.
                    # Use the same 1_000_000 byte threshold as Gate 7 for consistency.
                    total_bytes_local = sum(p.get("length", 0) for p in packets)
                    if total_bytes_local > 1_000_000:
                        return "video"
                    return "photo"
                if outbound_ratio > 0.70:
                    # Mostly outbound without extreme burst: photo or audio attachment.
                    return "media_transfer"
                    
            # Check 3: Low-intensity short QUIC flow on confirmed Meta IP = chat/control.
            # Characteristics of QUIC chat/control:
            #   - Small total size (< 50 KB)
            #   - Short duration (< 60 seconds)
            #   - Roughly balanced send/receive (not upload-dominant)
            #   - No STUN/ICE patterns
            total_b_quic = sum(p.get("length", 0) for p in packets)
            quic_duration = (
                max(p.get("timestamp", 0) for p in packets)
                - min(p.get("timestamp", 0) for p in packets)
            ) or 1.0
            quic_rate_bps = total_b_quic / quic_duration

            if (cidr_confirmed
                    and total_b_quic < 50_000   # small flow
                    and quic_duration < 60.0    # brief channel
                    and quic_rate_bps < 20_000  # low sustained rate (handshakes can be fast)
                    and outbound_ratio < 0.70): # not upload-dominant
                # Small, brief, balanced QUIC on Meta IP = secondary chat/control channel
                return "message"

            # Bidirectional on UDP/443 with CIDR confirmed → likely TURN relay (call).
            # Fall through to VoIP bitrate check.
            if cidr_confirmed:
                voip = detect_voip_by_bitrate(packets)
                if voip:
                    return voip
            return "call_stream_unresolved"

        # Standard call_media_candidate path (truly dynamic UDP ports, NOT 443).
        if cidr_confirmed:
            voip = detect_voip_by_bitrate(packets)
            if voip:
                return voip
        return "call_stream_unresolved"

    # ── Gate 6: TCP-only CDN path ─────────────────────────────────────────
    # Photos/videos ONLY travel over TCP/443 to mm*.whatsapp.net.
    # If protocol is UDP and port is not media_or_https, it cannot be a photo.
    if protocol_type == "UDP" and port_activity not in ("media_or_https", None):
        voip = detect_voip_by_bitrate(packets)
        if voip:
            return voip
        # Small UDP packets, no bitrate window → call signaling
        if total_bytes < 10_000:
            return "call_signaling"
        # Larger unresolved UDP on WhatsApp CIDR = unknown call stream
        return "call_stream_unresolved"

    # ── Gate 7: Burst-intensity heuristic (TCP CDN transfers) ─────────────
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
                
            # Use median burst intensity, not max. The 'max' is contaminated by the
            # initial TLS handshake + message sync burst present in every chat session.
            # Median reflects the dominant (sustained) traffic pattern.
            sorted_intensities = sorted(
                sum(p.get('length', 0) for p in b) / span
                for b, span in bursts_with_duration
            )
            median_burst_intensity = sorted_intensities[len(sorted_intensities) // 2]
        else:
            median_burst_intensity = 0.0
            
        # >= 300 (not >300): 5-minute captures are exactly 300.0s
        if flow_duration >= 300 and median_burst_intensity < 2_000:
            return 'message'

    # ── Gate 8: Size-based fallback — ONLY if Meta CIDR confirmed ─────────
    # Fix B: Generic HTTPS traffic (banking, CDNs, OS updates) spans the
    # same 10 KB–1 MB range as WhatsApp media. Without a CIDR anchor,
    # applying size heuristics floods forensic reports with false positives.
    if not cidr_confirmed:
        # No SNI + no CIDR + no dedicated port = cannot classify as WA media
        return 'unclassified'

    # Gate 8 Pre-check: Compute effective byte rate (bytes/second).
    # A text chat accumulating 79 KB over 5 minutes ≈ 263 B/s.
    # A photo upload delivering 79 KB in 1.6 seconds ≈ 49,375 B/s.
    # This single value separates long-lived chat from short media bursts.
    effective_rate_bps = total_bytes / max(flow_duration, 1.0)

    # Long-lived, low-rate TCP flow on confirmed Meta IP = persistent chat session.
    # Threshold anchors:
    #   - WhatsApp voice note streaming: ~4,000 B/s (32 kbps Opus)
    #   - Text chat keepalive regime: < 500 B/s
    #   - Small photo upload: > 10,000 B/s even for a 100 KB photo over 10s
    if protocol_type == "TCP" and flow_duration >= 60 and effective_rate_bps < 5_000:
        return 'message'

    if total_bytes < 10_000:
        # Fix D: small flow on confirmed Meta IP — could be keep-alive or
        # tiny control message. Label 'message' only when CIDR-anchored.
        return 'message'
    if total_bytes < 100_000:
        return 'photo'
    if total_bytes < 1_000_000:
        return 'audio'
    return 'video'
