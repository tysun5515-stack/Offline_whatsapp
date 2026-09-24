"""Call-session reconstruction from capture-scoped flow evidence."""
from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

GAP_THRESHOLD = 10.0
STUN_LOOKBACK = 5.0
LONG_SESSION_WARNING_SECONDS = 3600.0
CALL_MEDIA_LABELS = frozenset({"voice_call", "video_call", "call_stream_unresolved"})


def is_call_media(packet: Dict[str, Any]) -> bool:
    return (packet.get("whatsapp_media_guess") or "") in CALL_MEDIA_LABELS


def is_stun(packet: Dict[str, Any]) -> bool:
    return bool(packet.get("is_stun_binding"))


def _flow_records(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for index, packet in enumerate(packets):
        capture_id = str(packet.get("upload_id") or packet.get("capture_id") or "unknown-capture")
        flow_id = str(packet.get("flow_id") or f"unassigned-{index}")
        grouped[(capture_id, flow_id)].append(packet)

    records = []
    for (capture_id, flow_id), members in grouped.items():
        members.sort(key=lambda p: p.get("timestamp") or 0.0)
        timestamps = [p["timestamp"] for p in members if p.get("timestamp") is not None]
        if not timestamps:
            continue
        labels = Counter(p.get("whatsapp_media_guess") for p in members if p.get("whatsapp_media_guess"))
        subscriber_votes = Counter(p.get("local_subscriber_ip") for p in members if p.get("local_subscriber_ip"))
        subscriber = subscriber_votes.most_common(1)[0][0] if subscriber_votes else None
        endpoint_a = next((p.get("endpoint_a_ip") for p in members if p.get("endpoint_a_ip")), None)
        endpoint_b = next((p.get("endpoint_b_ip") for p in members if p.get("endpoint_b_ip")), None)
        if not endpoint_a or not endpoint_b:
            ips = sorted({ip for p in members for ip in (p.get("src_ip"), p.get("dst_ip")) if ip})
            endpoint_a = ips[0] if ips else None
            endpoint_b = ips[1] if len(ips) > 1 else None
        remote_endpoints = sorted({ip for ip in (endpoint_a, endpoint_b) if ip and ip != subscriber})
        records.append({
            "capture_id": capture_id,
            "flow_id": flow_id,
            "packets": members,
            "start_ts": min(timestamps),
            "end_ts": max(timestamps),
            "protocol": str(members[0].get("protocol") or "").upper(),
            "subscriber": subscriber,
            "labels": labels,
            "has_stun": any(is_stun(p) for p in members),
            "remote_endpoints": remote_endpoints,
            "total_bytes": sum(p.get("length", 0) for p in members),
            "total_packets": len(members),
        })
    return records


def _qualify_call_flows(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    stun_times: Dict[Tuple[str, Optional[str]], List[float]] = defaultdict(list)
    for record in records:
        key = (record["capture_id"], record["subscriber"])
        stun_times[key].extend(
            p["timestamp"] for p in record["packets"]
            if is_stun(p) and p.get("timestamp") is not None
        )

    qualified = []
    for record in records:
        labels = record["labels"]
        has_voice = labels["voice_call"] > 0
        has_video = labels["video_call"] > 0
        unresolved = labels["call_stream_unresolved"] > 0
        nearby_stun = record["has_stun"] or any(
            record["start_ts"] - STUN_LOOKBACK <= ts <= record["end_ts"] + STUN_LOOKBACK
            for ts in stun_times[(record["capture_id"], record["subscriber"])]
        )
        if has_video:
            evidence_type = "video"
        elif has_voice:
            evidence_type = "voice"
        elif record["protocol"] == "UDP" and unresolved and nearby_stun:
            evidence_type = "unresolved"
        else:
            continue
        record = dict(record)
        record["evidence_type"] = evidence_type
        record["stun_anchored"] = nearby_stun
        qualified.append(record)
    return qualified


def _union_duration(intervals: List[Tuple[float, float]]) -> float:
    if not intervals:
        return 0.0
    merged = []
    for start, end in sorted(intervals):
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return sum(end - start for start, end in merged)


def reconstruct_flow_sessions(
    packets: List[Dict[str, Any]], parties: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Join independently qualified call flows within one capture/subscriber."""
    records = _qualify_call_flows(_flow_records(packets))
    party_by_flow = {
        flow_id: party["party_id"]
        for party in parties for flow_id in party.get("flow_ids", [])
    }
    groups: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for record in records:
        # Unresolved subscriber identity deliberately prevents cross-flow joining.
        subscriber_key = record["subscriber"] or f"unresolved:{record['flow_id']}"
        groups[(record["capture_id"], subscriber_key)].append(record)

    sessions: List[Dict[str, Any]] = []
    for (capture_id, subscriber_key), candidates in groups.items():
        candidates.sort(key=lambda r: (r["start_ts"], r["end_ts"], r["flow_id"]))
        windows: List[List[Dict[str, Any]]] = []
        for record in candidates:
            current = windows[-1] if windows else []
            latest_end = max((r["end_ts"] for r in current), default=float("-inf"))
            overlapping_disjoint = any(
                record["start_ts"] < prior["end_ts"]
                and set(record["remote_endpoints"]).isdisjoint(prior["remote_endpoints"])
                for prior in current
            )
            if not current or record["start_ts"] - latest_end > GAP_THRESHOLD or overlapping_disjoint:
                windows.append([record])
            else:
                windows[-1].append(record)

        for index, window in enumerate(windows, 1):
            start_ts = min(r["start_ts"] for r in window)
            end_ts = max(r["end_ts"] for r in window)
            intervals = [(r["start_ts"], r["end_ts"]) for r in window]
            ordered_intervals = sorted(intervals)
            transition_gap_s = sum(
                max(0.0, ordered_intervals[i][0] - ordered_intervals[i - 1][1])
                for i in range(1, len(ordered_intervals))
            )
            evidence_types = {r["evidence_type"] for r in window}
            call_type = "video" if "video" in evidence_types else "voice" if "voice" in evidence_types else "unresolved"
            flow_ids = [r["flow_id"] for r in window]
            party_ids = sorted({party_by_flow[f] for f in flow_ids if f in party_by_flow})
            remote_endpoints = sorted({ip for r in window for ip in r["remote_endpoints"]})
            seed = f"{capture_id}|{subscriber_key}|{start_ts:.9f}|{'|'.join(flow_ids)}"
            observed_span = max(0.0, end_ts - start_ts)
            sessions.append({
                "schema_version": "session-statistics-v2",
                "session_id": "session-v2-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24],
                "capture_id": capture_id,
                "local_subscriber_ip": None if subscriber_key.startswith("unresolved:") else subscriber_key,
                "start_ts": start_ts,
                "end_ts": end_ts,
                "duration_s": round(observed_span, 3),
                "call_duration_s": round(_union_duration(intervals), 3),
                "observed_span_s": round(observed_span, 3),
                "active_media_duration_s": round(_union_duration(intervals), 3),
                "transition_gap_s": round(transition_gap_s, 3),
                "call_type": call_type,
                "flow_ids": flow_ids,
                "party_ids": party_ids,
                "remote_endpoints": remote_endpoints,
                "total_bytes": sum(r["total_bytes"] for r in window),
                "total_packets": sum(r["total_packets"] for r in window),
                "stun_anchored": any(r["stun_anchored"] for r in window),
                "confidence": "medium" if any(r["stun_anchored"] for r in window) else "low",
                "duration_anomaly": observed_span > LONG_SESSION_WARNING_SECONDS,
                "signals_detected": sorted({
                    "strict_stun_seen" if r["stun_anchored"] else "classified_call_media"
                    for r in window
                }),
            })
    return sorted(sessions, key=lambda session: (session["start_ts"], session["session_id"]))


def attach_session_metrics(parties: List[Dict[str, Any]], sessions: List[Dict[str, Any]]) -> None:
    """Attach compatibility summaries without making parties own session logic."""
    by_party: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for session in sessions:
        for party_id in session.get("party_ids", []):
            by_party[party_id].append(session)
    for party in parties:
        linked = by_party.get(party["party_id"], [])
        durations = [s["observed_span_s"] for s in linked]
        party["sessions"] = linked
        party["call_duration_s"] = round(sum(durations), 3)
        party["longest_call_s"] = round(max(durations), 3) if durations else 0.0
        party["call_window_count"] = len(linked)
        party["voice_call_count"] = sum(s["call_type"] == "voice" for s in linked)
        party["video_call_count"] = sum(s["call_type"] == "video" for s in linked)
        party["unresolved_call_count"] = sum(s["call_type"] == "unresolved" for s in linked)
        party["voice_duration_s"] = round(sum(s["observed_span_s"] for s in linked if s["call_type"] == "voice"), 3)
        party["video_duration_s"] = round(sum(s["observed_span_s"] for s in linked if s["call_type"] == "video"), 3)


def reconstruct_sessions(pkts_sorted: List[Dict[str, Any]], party_id: str) -> List[Dict[str, Any]]:
    """Compatibility wrapper for legacy callers and focused tests."""
    flow_ids = sorted({str(p.get("flow_id") or "legacy-flow") for p in pkts_sorted})
    party = {"party_id": party_id, "flow_ids": flow_ids}
    return reconstruct_flow_sessions(pkts_sorted, [party])


def build_call_metrics(pkts_sorted: List[Dict[str, Any]], party_id: str) -> Dict[str, Any]:
    sessions = reconstruct_sessions(pkts_sorted, party_id)
    durations = [s["observed_span_s"] for s in sessions]
    return {
        "call_duration_s": round(sum(durations), 3),
        "longest_call_s": round(max(durations), 3) if durations else 0.0,
        "call_window_count": len(sessions),
        "sessions": sessions,
        "voice_call_count": sum(s["call_type"] == "voice" for s in sessions),
        "video_call_count": sum(s["call_type"] == "video" for s in sessions),
        "unresolved_call_count": sum(s["call_type"] == "unresolved" for s in sessions),
        "voice_duration_s": round(sum(s["observed_span_s"] for s in sessions if s["call_type"] == "voice"), 3),
        "video_duration_s": round(sum(s["observed_span_s"] for s in sessions if s["call_type"] == "video"), 3),
        "high_confidence_calls": 0,
        "medium_confidence_calls": sum(s["confidence"] == "medium" for s in sessions),
        "low_confidence_calls": sum(s["confidence"] == "low" for s in sessions),
    }
