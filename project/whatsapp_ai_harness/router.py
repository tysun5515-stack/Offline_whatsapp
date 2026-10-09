from __future__ import annotations

import re
import uuid
from typing import Any, Dict, Optional, Tuple

from .types import AnalysisScope, PlanStep, QueryIntent, QueryPlan


IP_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
BLOCKED_PATTERNS = (
    (re.compile(r"\b(decrypt|plaintext|message content|read (?:the )?messages?|count (?:the )?(?:text )?messages?)\b", re.I),
     "Encrypted network evidence cannot provide decrypted content or a reliable individual message count."),
    (re.compile(r"\b(contact name|phone number|account owner|real name)\b", re.I),
     "The forensic network database does not establish contact identity."),
    (re.compile(r"\bwho (?:started|initiated|called whom)|caller|callee\b", re.I),
     "Caller/callee direction is unavailable unless explicit role evidence exists."),
    (re.compile(r"\b(raw pcap|payload bytes|packet payload)\b", re.I),
     "The user harness intentionally has no raw-PCAP or payload access."),
)


def _limit(text: str, default: int, hard: int) -> int:
    match = re.search(r"\b(?:top|first|last|show|list)\s+(\d{1,4})\b", text, re.I)
    return min(int(match.group(1)), hard) if match else default


def route_question(question: str, scope: AnalysisScope, default_limit: int, hard_limit: int,
                   ) -> Tuple[str, QueryIntent, Optional[QueryPlan], Optional[str]]:
    normalized = " ".join(question.strip().split()); lowered = normalized.lower()
    for pattern, message in BLOCKED_PATTERNS:
        if pattern.search(normalized): return "C", QueryIntent("unsupported"), None, message
    if re.search(r"\bunique entries\b", normalized, re.I):
        return "C", QueryIntent("ambiguous", ambiguity_status="unique_entries"), None, (
            "Please specify unique captures, IP addresses, packets, flows, parties, calls, or crypto flows."
        )
    common: Dict[str, Any] = {"limit": _limit(normalized, default_limit, hard_limit)}
    if scope.upload_ids: common["upload_ids"] = scope.upload_ids
    if scope.batch_ids: common["batch_ids"] = scope.batch_ids
    if scope.start_time is not None: common["start_time"] = scope.start_time
    if scope.end_time is not None: common["end_time"] = scope.end_time
    if scope.endpoint_filters: common["endpoint_filters"] = scope.endpoint_filters
    ips = IP_RE.findall(normalized)
    if ips: common["endpoint"] = ips[0]
    operator = None; intent = ""; params = dict(common)
    if any(word in lowered for word in ("quality", "warning", "failed", "readiness")):
        operator, intent = "quality_summary", "quality"
    elif any(word in lowered for word in ("rule", "methodology", "why classified", "what does")):
        operator, intent, params = "rule_search", "rules", {"query": normalized, "limit": common["limit"]}
    elif any(word in lowered for word in ("correlation", "correlate")):
        operator, intent = "correlation_summary", "correlations"
    elif any(word in lowered for word in ("metric", "admission", "rejected", "reconciliation", "filtering")):
        operator, intent = "metrics_summary", "metrics"
    elif any(word in lowered for word in ("country", "asn", "geolocation", "geographic", "geo")):
        operator, intent = "geo_summary", "geo"
    elif any(word in lowered for word in ("pqc", "crypto", "cipher", "tls", "quic")):
        operator, intent = "crypto_summary", "crypto"
        if "evidence" in lowered and re.search(r"(?:flow[-:\w]+)", lowered):
            operator = "crypto_evidence"; params["flow_id"] = re.search(r"(?:flow[-:\w]+)", lowered).group(0)
        elif "detail" in lowered: operator = "crypto_detail"
    elif "call" in lowered or "session" in lowered:
        if re.search(r"session-v2-[a-f0-9]+", lowered):
            operator, intent = "call_detail", "call_detail"; params["session_id"] = re.search(r"session-v2-[a-f0-9]+", lowered).group(0)
        elif any(word in lowered for word in ("how many", "count", "number", "total")):
            operator, intent = "count_calls", "call_count"
        else:
            operator, intent = "list_calls", "call_list"
            params["order"] = "shortest" if "shortest" in lowered else "longest" if "longest" in lowered else "latest"
        if "video" in lowered: params["call_type"] = "video"
        elif "voice" in lowered: params["call_type"] = "voice"
        elif "unresolved" in lowered or "candidate" in lowered:
            params["call_type"] = "unresolved"; params["include_candidates"] = True
    elif any(word in lowered for word in ("party", "parties", "peer", "relay", "infrastructure")):
        operator, intent = ("party_summary", "party_summary") if any(w in lowered for w in ("summary", "count", "how many")) else ("list_parties", "party_list")
    elif ("compare" in lowered or "comparison" in lowered) and "traffic" in lowered and "capture" in lowered:
        operator, intent = "traffic_by_capture", "traffic_comparison"
        for protocol in ("udp", "tcp"):
            if protocol in lowered: params["protocol"] = protocol
    elif "flow" in lowered:
        match = re.search(r"[\w-]+:flow-[\w-]+|flow-v?\d*-[\w-]+", lowered)
        if match: operator, intent = "flow_detail", "flow_detail"; params["flow_id"] = match.group(0)
        else: operator, intent = ("flow_summary", "flow_summary") if any(w in lowered for w in ("summary", "count", "protocol")) else ("list_flows", "flow_list")
    elif "packet" in lowered:
        number = re.search(r"\b(?:packet\s*)#?(\d+)\b", lowered)
        if number: operator, intent = "packet_detail", "packet_detail"; params["packet_no"] = int(number.group(1))
        else: operator, intent = ("packet_summary", "packet_summary") if any(w in lowered for w in ("summary", "count", "protocol", "activity")) else ("list_packets", "packet_list")
    elif (any(phrase in lowered for phrase in ("most used", "most active", "busiest", "top ip", "top endpoint", "frequent"))
          and any(w in lowered for w in ("ip", "endpoint", "address"))):
        operator, intent = "rank_endpoints", "endpoint_ranking"
        params["order_by"] = "total_packets" if "packet" in lowered or "frequent" in lowered else "total_bytes"
    elif "unique" in lowered and any(w in lowered for w in ("ip", "endpoint", "address")):
        operator, intent = "list_unique_endpoints", "endpoints"
    elif ips and any(w in lowered for w in ("history", "communicat", "associated", "traffic")):
        operator, intent = "endpoint_history", "endpoint_history"
    elif any(w in lowered for w in ("capture", "upload", "file")):
        operator, intent = ("capture_summary", "capture_summary") if any(w in lowered for w in ("summary", "count", "status")) else ("list_captures", "capture_list")
    elif any(w in lowered for w in ("overview", "database", "what data")):
        operator, intent = "dataset_overview", "database_overview"
    query_intent = QueryIntent(intent or "novel", requested_evidence_depth="summary")
    if not operator: return "B", query_intent, None, None
    steps = [PlanStep(operator, parameters=params)]
    if intent == "call_count" and re.search(r"\b(?:which|list|show)\b.*\b(?:endpoints?|ips?|addresses?)\b", lowered):
        steps.append(PlanStep("list_calls", parameters={**params, "order": "latest"}))
    return "A", query_intent, QueryPlan(str(uuid.uuid4()), "A", scope, steps,
        required_evidence=[s.operator for s in steps], complexity_score=len(steps)), None
