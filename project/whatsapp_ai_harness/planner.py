from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List

from .types import AnalysisScope, PlanStep, QueryPlan


COMMON = ["upload_ids", "batch_ids", "start_time", "end_time", "endpoint_filters", "limit"]
OPERATOR_SPEC: Dict[str, Dict[str, Any]] = {
    "dataset_overview": {"parameters": []},
    "capture_summary": {"parameters": COMMON}, "list_captures": {"parameters": COMMON},
    "packet_summary": {"parameters": COMMON + ["endpoint", "protocol", "confidence", "activity"]},
    "list_packets": {"parameters": COMMON + ["endpoint", "protocol", "confidence", "activity"]},
    "packet_detail": {"required": ["packet_no"], "parameters": COMMON + ["packet_no"]},
    "flow_summary": {"parameters": COMMON + ["endpoint", "protocol", "media_type", "confidence"],
                     "output_fields": ["protocol", "media_type", "confidence", "flow_count", "total_packets", "total_bytes"]},
    "traffic_by_capture": {"parameters": COMMON + ["protocol"],
                           "output_fields": ["upload_id", "batch_id", "protocol", "flow_count", "total_packets", "total_bytes"]},
    "list_flows": {"parameters": COMMON + ["endpoint", "protocol", "media_type", "confidence"]},
    "flow_detail": {"required": ["flow_id"], "parameters": COMMON + ["flow_id"]},
    "party_summary": {"parameters": COMMON + ["endpoint", "role", "confidence"]},
    "list_parties": {"parameters": COMMON + ["endpoint", "role", "confidence"]},
    "party_detail": {"required": ["party_id"], "parameters": COMMON + ["party_id"]},
    "count_calls": {"parameters": COMMON + ["endpoint", "call_type", "confidence", "include_candidates"]},
    "list_calls": {"parameters": COMMON + ["endpoint", "call_type", "confidence", "include_candidates", "order"]},
    "call_detail": {"required": ["session_id"], "parameters": COMMON + ["session_id", "include_candidates"]},
    "list_unique_endpoints": {"parameters": COMMON},
    "rank_endpoints": {"parameters": COMMON + ["order_by"]},
    "endpoint_history": {"required": ["endpoint"], "parameters": COMMON + ["endpoint", "protocol", "media_type"]},
    "crypto_summary": {"parameters": COMMON + ["endpoint", "flow_id"]},
    "crypto_detail": {"parameters": COMMON + ["endpoint", "flow_id"]},
    "crypto_evidence": {"required": ["flow_id"], "parameters": COMMON + ["flow_id"]},
    "geo_summary": {"parameters": COMMON}, "metrics_summary": {"parameters": COMMON},
    "correlation_summary": {"parameters": COMMON}, "quality_summary": {"parameters": COMMON},
    "rule_search": {"required": ["query"], "parameters": ["query", "limit"]},
    "compare_results": {"composition": True, "min_refs": 2, "parameters": ["field"]},
    "set_intersection": {"composition": True, "min_refs": 2, "required": ["field"], "parameters": ["field"]},
    "set_difference": {"composition": True, "min_refs": 2, "required": ["field"], "parameters": ["field"]},
    "rank_results": {"composition": True, "min_refs": 1, "required": ["field"], "parameters": ["field", "order"]},
    "trend_results": {"composition": True, "min_refs": 1,
                      "required": ["time_field", "value_field"],
                      "parameters": ["time_field", "value_field"]},
}

SEMANTIC_CATALOG = {
    "captures": "Completed upload provenance and readiness; no local paths are exposed.",
    "packets": "Filtered classified metadata without raw payload bytes.",
    "flows": "Bidirectional transport summaries linked to captures and endpoints.",
    "parties": "Endpoint-pair entities; infrastructure roles never identify a human peer.",
    "calls": "Qualified sessions; confirmed voice/video and unresolved candidates remain separate; direction is unknown.",
    "endpoints": "Normalized IP observations and communication history.",
    "crypto": "Flow-linked TLS/QUIC/PQC observations; negotiation requires complete server evidence.",
    "geo": "Cached country/ASN enrichment with reliability limitations.",
    "metrics": "Per-upload admission, rejection and reconciliation metrics.",
    "correlations": "Persisted cross-capture correlation results.",
    "quality": "Readiness, validation findings, rules and limitations.",
}


class PlanValidationError(ValueError):
    pass


def planner_schema() -> Dict[str, Any]:
    return {"type": "object", "required": ["steps"], "properties": {
        "steps": {"type": "array", "minItems": 1, "maxItems": 8, "items": {
            "type": "object", "required": ["operator", "parameters"], "properties": {
                "operator": {"type": "string", "enum": sorted(OPERATOR_SPEC)},
                "parameters": {"type": "object"},
                "input_refs": {"type": "array", "items": {"type": "string"}},
                "output_type": {"type": "string", "enum": ["scalar", "table", "record"]},
            }, "additionalProperties": False}},
        "complexity_score": {"type": "integer", "minimum": 1, "maximum": 12},
    }, "additionalProperties": False}


def validate_plan_payload(payload: Dict[str, Any], scope: AnalysisScope, hard_limit: int) -> QueryPlan:
    if not isinstance(payload, dict) or not isinstance(payload.get("steps"), list):
        raise PlanValidationError("Planner response must contain a steps array")
    if not 1 <= len(payload["steps"]) <= 8:
        raise PlanValidationError("A plan must contain between one and eight steps")
    steps: List[PlanStep] = []; known = set(); calculated_cost = 0
    for index, raw in enumerate(payload["steps"]):
        if not isinstance(raw, dict) or raw.get("operator") not in OPERATOR_SPEC:
            raise PlanValidationError(f"Step {index} has an unsupported operator")
        operator = raw["operator"]; spec = OPERATOR_SPEC[operator]
        params = raw.get("parameters", {})
        if not isinstance(params, dict): raise PlanValidationError(f"Step {index} parameters must be an object")
        # JSON planners commonly materialize optional fields as null. Treat null
        # exactly like an omitted optional value before applying the allowlist;
        # no authority or query scope is gained by this normalization.
        params = {name: value for name, value in params.items() if value is not None}
        unknown = set(params) - set(spec.get("parameters", [])); missing = set(spec.get("required", [])) - set(params)
        if unknown or missing:
            raise PlanValidationError(f"Step {index} has invalid parameters; unknown={sorted(unknown)}, missing={sorted(missing)}")
        refs = raw.get("input_refs", [])
        if not isinstance(refs, list) or any(ref not in known for ref in refs):
            raise PlanValidationError(f"Step {index} contains a forward, circular, or unknown input reference")
        if spec.get("composition"):
            if len(refs) < spec.get("min_refs", 1): raise PlanValidationError(f"Step {index} requires more input references")
        elif refs:
            raise PlanValidationError(f"Step {index} is a database operator and cannot consume input_refs")
        if "limit" in params and (not isinstance(params["limit"], int) or not 1 <= params["limit"] <= hard_limit):
            raise PlanValidationError(f"Step {index} has an invalid row limit")
        for name in ("upload_ids", "batch_ids", "endpoint_filters"):
            if name in params and (not isinstance(params[name], list) or not all(isinstance(v, str) for v in params[name])):
                raise PlanValidationError(f"Step {index} {name} must be a string array")
        for name in ("start_time", "end_time", "packet_no"):
            if name in params and not isinstance(params[name], (int, float)):
                raise PlanValidationError(f"Step {index} {name} must be numeric")
        for name, value in params.items():
            if name not in {"limit", "start_time", "end_time", "packet_no", "upload_ids", "batch_ids", "endpoint_filters", "include_candidates"} and not isinstance(value, str):
                raise PlanValidationError(f"Step {index} {name} must be a string")
        if "include_candidates" in params and not isinstance(params["include_candidates"], bool):
            raise PlanValidationError(f"Step {index} include_candidates must be boolean")
        known.add(f"step_{index}"); calculated_cost += 2 if spec.get("composition") else 1
        steps.append(PlanStep(operator, refs, params, raw.get("output_type", "table")))
    declared = payload.get("complexity_score", calculated_cost)
    if not isinstance(declared, int) or declared < calculated_cost or declared > 12:
        raise PlanValidationError("complexity_score is invalid or understates the plan cost")
    return QueryPlan(str(uuid.uuid4()), "B", scope, steps, required_evidence=[s.operator for s in steps], complexity_score=declared)


def planner_prompt(question: str, scope: AnalysisScope) -> str:
    return (
        "Return only a JSON query plan, never SQL or an answer. Use database operators first and trusted composition "
        "operators only with prior step_N references. Omit null, empty, and unused parameters. Every limit must be an "
        "integer from 1 through 200. A composition input_ref must name an earlier step only; intersections and "
        "differences require at least two earlier database-result steps. Do not invent fields outside the operator "
        "definitions. Use exact references such as step_0, never an operator name. Database operators always have "
        "an empty input_refs array. Example for ranking protocol traffic: flow_summary as step_0, followed by "
        "rank_results with input_refs [step_0], field total_bytes, and order desc. Decrypted content, contact identity, "
        "caller/callee direction and raw payload are unavailable.\n"
        f"Question: {question}\nScope: {json.dumps(scope.__dict__, sort_keys=True)}\n"
        f"Semantic catalog: {json.dumps(SEMANTIC_CATALOG, sort_keys=True)}\n"
        f"Operators: {json.dumps(OPERATOR_SPEC, sort_keys=True)}"
    )
