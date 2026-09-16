"""
traffic_utils.py: Shared burst-extraction logic used by BOTH
flow_builder.py (for flow_summary.burst_count) and whatsapp_filter.py
(for guess_media_type()'s burst-intensity calculation).

This module exists specifically because those two files previously had
TWO DIFFERENT, DISAGREEING definitions of "burst":
  - flow_builder.py only incremented burst_count on the transition into
    a run of 2+ consecutive packets with gap < threshold - a flow where
    every packet was isolated (all gaps >= threshold, e.g. a slow
    back-and-forth chat) reported burst_count=0, even though that flow
    clearly had N distinct message-sending events.
  - whatsapp_filter.py's version grouped EVERY packet into some burst,
    including isolated single-packet ones, using gap <= threshold
    (inclusive, not strict less-than).
Both files now import from here, so there is exactly one definition and
one boundary convention (<=, inclusive), and every packet belongs to some
burst - a lone packet is its own single-packet burst, not "no burst."
"""

from typing import Any, Dict, List, Tuple


def extract_bursts(
    packets: List[Dict[str, Any]], threshold: float = 1.0
) -> List[List[Dict[str, Any]]]:
    """Groups packets into bursts: consecutive packets with inter-packet
    gap <= threshold belong to the same burst. Every packet belongs to
    SOME burst - a lone packet with large gaps on both sides is its own
    single-packet burst, not excluded from the count."""
    if not packets:
        return []
    sorted_pkts = sorted(packets, key=lambda p: p.get('timestamp', 0))
    bursts: List[List[Dict[str, Any]]] = [[sorted_pkts[0]]]
    for pkt in sorted_pkts[1:]:
        gap = pkt.get('timestamp', 0) - bursts[-1][-1].get('timestamp', 0)
        if gap <= threshold:
            bursts[-1].append(pkt)
        else:
            bursts.append([pkt])
    return bursts


def extract_bursts_with_duration(
    packets: List[Dict[str, Any]], threshold: float = 1.0
) -> List[Tuple[List[Dict[str, Any]], float]]:
    """Same grouping as extract_bursts, but pairs each burst with its OWN
    duration (not the surrounding flow's duration - burst intensity must
    be bytes over THAT burst's own span, not the whole flow's). A
    single-packet burst gets a small nonzero floor (0.001s) to avoid
    divide-by-zero."""
    bursts = extract_bursts(packets, threshold)
    result = []
    for b in bursts:
        span = b[-1].get('timestamp', 0) - b[0].get('timestamp', 0)
        result.append((b, max(span, 0.001)))
    return result
