from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import time
import uuid
from dataclasses import asdict
from typing import Any, Dict, List, Optional, TypedDict

from langgraph.graph import END, START, StateGraph

from .audit import AuditStore
from .config import Settings
from .live_source import LiveDatabase, LiveDatabaseError, LiveDatabaseSource
from .ollama_client import OllamaClient, OllamaError
from .operators import OperatorResult, execute_composition, execute_operator
from .planner import OPERATOR_SPEC, PlanValidationError, planner_prompt, planner_schema, validate_plan_payload
from .router import route_question
from .security import readonly_connection
from .types import AnalysisScope, AnswerPackage, QueryIntent, QueryPlan
from .verifier import VerificationError, build_answer_package, narration_prompt, narration_schema, verify_narration


class HarnessState(TypedDict, total=False):
    question: str
    database: LiveDatabase
    scope: AnalysisScope
    route: str
    intent: QueryIntent
    plan: QueryPlan
    results: List[OperatorResult]
    evidence_source_digests: List[Dict[str, Any]]
    analysis_revision: int
    package: AnswerPackage
    answer: str
    clarification: Optional[str]
    limitations: List[str]
    model_name: Optional[str]
    model_digest: Optional[str]


class HarnessEngine:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.source = LiveDatabaseSource(settings.analysis_db)
        self.audit = AuditStore(settings.audit_db)
        self.ollama = OllamaClient(settings.ollama_url, settings.primary_model,
                                  settings.fallback_model, settings.context_tokens)
        self.graph = self._build_graph()

    def _build_graph(self):
        graph = StateGraph(HarnessState)
        for name, node in (("route", self._route), ("propose", self._propose), ("execute", self._execute),
                           ("verify", self._verify), ("narrate", self._narrate), ("stop", self._stop)):
            graph.add_node(name, node)
        graph.add_edge(START, "route")
        graph.add_conditional_edges("route", lambda s: s["route"], {"A": "execute", "B": "propose", "C": "stop"})
        graph.add_edge("propose", "execute"); graph.add_edge("execute", "verify")
        graph.add_conditional_edges("verify", lambda s: s["route"], {"A": END, "B": "narrate"})
        graph.add_edge("narrate", END); graph.add_edge("stop", END)
        return graph.compile()

    def _route(self, state: HarnessState) -> Dict[str, Any]:
        route, intent, plan, clarification = route_question(
            state["question"], state["scope"], self.settings.default_row_limit, self.settings.hard_row_limit,
        )
        result: Dict[str, Any] = {"route": route, "intent": intent, "clarification": clarification}
        if plan: result["plan"] = plan
        return result

    def _propose(self, state: HarnessState) -> Dict[str, Any]:
        prompt = planner_prompt(state["question"], state["scope"]); last_error = ""
        model_name = model_digest = None
        for attempt in range(2):
            current = prompt if attempt == 0 else prompt + "\nPrevious plan rejected: " + last_error + "\nReturn one corrected plan."
            try:
                payload, model_name, model_digest = self.ollama.structured(current, planner_schema(), 0.0)
                return {"plan": validate_plan_payload(payload, state["scope"], self.settings.hard_row_limit),
                        "model_name": model_name, "model_digest": model_digest}
            except (OllamaError, PlanValidationError) as exc:
                last_error = str(exc)
                if isinstance(exc, OllamaError): break
        raise PlanValidationError(f"No valid controlled plan could be produced: {last_error}")

    def _execute(self, state: HarnessState) -> Dict[str, Any]:
        scope = state["scope"]; results: List[OperatorResult] = []; prior: Dict[str, OperatorResult] = {}
        with readonly_connection(state["database"].database_path, self.settings.query_timeout_ms) as conn:
            revision = int(conn.execute("SELECT current_revision FROM v_agent_dataset").fetchone()[0] or 0)
            for index, step in enumerate(state["plan"].ordered_steps):
                params = dict(step.parameters)
                for key in ("upload_ids", "batch_ids", "endpoint_filters"):
                    value = getattr(scope, key)
                    if value: params[key] = list(value)
                if scope.start_time is not None: params["start_time"] = scope.start_time
                if scope.end_time is not None: params["end_time"] = scope.end_time
                if scope.call_type and step.operator in {"count_calls", "list_calls", "call_detail"}:
                    params["call_type"] = scope.call_type
                    if scope.call_type == "unresolved": params["include_candidates"] = True
                if scope.confidence_policy != "reported" and step.operator in {
                    "packet_summary", "list_packets", "flow_summary", "list_flows",
                    "party_summary", "list_parties", "count_calls", "list_calls",
                }:
                    params["confidence"] = scope.confidence_policy
                scoped = type(step)(step.operator, list(step.input_refs), params, step.output_type)
                if OPERATOR_SPEC[step.operator].get("composition"):
                    result = execute_composition(state["database"], revision, scoped, prior, self.settings.hard_row_limit)
                else:
                    result = execute_operator(state["database"], revision, scoped, conn, self.settings.hard_row_limit)
                results.append(result); prior[f"step_{index}"] = result
            digest_where = ["1=1"]; digest_values: List[Any] = []
            if scope.upload_ids:
                digest_where.append("c.upload_id IN (%s)" % ",".join("?" for _ in scope.upload_ids))
                digest_values.extend(scope.upload_ids)
            if scope.batch_ids:
                digest_where.append("c.batch_id IN (%s)" % ",".join("?" for _ in scope.batch_ids))
                digest_values.extend(scope.batch_ids)
            if scope.start_time is not None:
                digest_where.append("COALESCE(c.capture_end_ts,c.capture_start_ts) >= ?")
                digest_values.append(scope.start_time)
            if scope.end_time is not None:
                digest_where.append("COALESCE(c.capture_start_ts,c.capture_end_ts) < ?")
                digest_values.append(scope.end_time)
            if scope.endpoint_filters:
                marks = ",".join("?" for _ in scope.endpoint_filters)
                digest_where.append(
                    f"EXISTS (SELECT 1 FROM v_agent_flows f WHERE f.upload_id=c.upload_id "
                    f"AND (f.endpoint_a_ip IN ({marks}) OR f.endpoint_b_ip IN ({marks})))"
                )
                digest_values.extend(scope.endpoint_filters); digest_values.extend(scope.endpoint_filters)
            source_digests = [dict(row) for row in conn.execute(
                "SELECT c.upload_id,c.source_sha256,c.filtered_sha256,c.result_digest,c.analysis_revision "
                "FROM v_agent_captures c WHERE " + " AND ".join(digest_where) + " ORDER BY c.upload_id",
                digest_values,
            ).fetchall()]
        return {"results": results, "analysis_revision": revision,
                "evidence_source_digests": source_digests}

    def _verify(self, state: HarnessState) -> Dict[str, Any]:
        package = build_answer_package(state["question"], state["scope"], state["database"],
                                       state["analysis_revision"], state["results"],
                                       state.get("evidence_source_digests", []))
        return {"package": package, **({"answer": package.direct_answer} if state["route"] == "A" else {})}

    def _narrate(self, state: HarnessState) -> Dict[str, Any]:
        try:
            response, model_name, model_digest = self.ollama.structured(
                narration_prompt(state["package"]), narration_schema(), 0.0,
            )
            return {"answer": verify_narration(response.get("answer"), state["package"]),
                    "model_name": model_name, "model_digest": model_digest}
        except (OllamaError, VerificationError):
            return {"answer": state["package"].direct_answer}

    @staticmethod
    def _stop(state: HarnessState) -> Dict[str, Any]:
        message = state.get("clarification") or "This question cannot be answered reliably from the forensic database."
        return {"answer": message, "limitations": [message]}

    @staticmethod
    def _validated_scope(raw: Dict[str, Any]) -> AnalysisScope:
        uploads = raw.get("upload_ids") or []; batches = raw.get("batch_ids") or []
        endpoints = raw.get("endpoint_filters") or []
        for name, values in (("upload_ids", uploads), ("batch_ids", batches), ("endpoint_filters", endpoints)):
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                raise ValueError(f"{name} must be a list of strings")
        normalized = []
        for value in endpoints[:20]:
            try: parsed = ipaddress.ip_address(value.split("%", 1)[0])
            except ValueError as exc: raise ValueError(f"Invalid endpoint filter {value!r}") from exc
            if getattr(parsed, "ipv4_mapped", None): parsed = parsed.ipv4_mapped
            normalized.append(str(parsed))
        start = float(raw["start_time"]) if raw.get("start_time") is not None else None
        end = float(raw["end_time"]) if raw.get("end_time") is not None else None
        if (start is not None and not math.isfinite(start)) or (end is not None and not math.isfinite(end)):
            raise ValueError("start_time and end_time must be finite epoch values")
        if start is not None and end is not None and end <= start:
            raise ValueError("end_time must be greater than start_time")
        call_type = raw.get("call_type") or None
        if call_type not in {None, "voice", "video", "unresolved"}:
            raise ValueError("call_type must be voice, video, or unresolved")
        policy = raw.get("confidence_policy", "reported")
        if policy not in {"reported", "high", "medium", "low"}:
            raise ValueError("confidence_policy is invalid")
        return AnalysisScope(uploads[:100], batches[:100], start, end, normalized, call_type, policy)

    def _validate_scope(self, database: LiveDatabase, scope: AnalysisScope) -> None:
        if not scope.upload_ids and not scope.batch_ids: return
        with readonly_connection(database.database_path, self.settings.query_timeout_ms) as conn:
            rows = conn.execute("SELECT upload_id,batch_id FROM v_agent_captures").fetchall()
        known_uploads = {row[0] for row in rows}; known_batches = {row[1] for row in rows if row[1]}
        if set(scope.upload_ids) - known_uploads: raise ValueError("One or more upload IDs are not ready or do not exist")
        if set(scope.batch_ids) - known_batches: raise ValueError("One or more batch IDs are not ready or do not exist")

    def query(self, question: str, scope_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        trace_id = str(uuid.uuid4()); started = time.monotonic(); question = " ".join(str(question).split())
        if not 1 <= len(question) <= 4000: raise ValueError("question must contain between 1 and 4000 characters")
        database = self.source.inspect(); scope = self._validated_scope(scope_data or {}); self._validate_scope(database, scope)
        state: HarnessState = {"question": question, "database": database, "scope": scope}
        status, error = "success", None
        administrative = any(term in question.lower() for term in (
            "database", "overview", "capture", "upload", "status", "ready", "quality", "failed", "rule", "methodology"
        ))
        try:
            if not administrative and int(database.summary.get("ready_upload_count", 0)) == 0:
                message = (
                    "There is no ready forensic evidence to analyze. Upload and finish processing at least one capture "
                    "in the developer application; the harness will use it automatically when its state becomes ready."
                )
                result = {**state, "route": "C", "answer": message, "limitations": [message],
                          "clarification": message}
                status = "refused"
            else:
                result = self.graph.invoke(state)
        except (PlanValidationError, VerificationError, OllamaError) as exc:
            status, error = "refused", str(exc)
            result = {**state, "route": "C", "answer": f"I cannot answer this reliably: {exc}", "limitations": [str(exc)]}
        except Exception as exc:
            status, error = "error", str(exc)
            result = {**state, "route": "C", "answer": "The query failed safely without changing evidence.", "limitations": [str(exc)]}
        plan = result.get("plan"); package = result.get("package"); operator_results = result.get("results", [])
        trace = [{"operator": item.operator, "query_digest": item.query_digest, "parameters": item.parameters,
                  "row_count": len(item.rows), "result_hash": hashlib.sha256(
                      json.dumps(item.rows, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()}
                 for item in operator_results]
        response = {
            "trace_id": trace_id, "status": status, "route": result.get("route", "C"), "answer": result["answer"],
            "clarification_required": bool(result.get("clarification")),
            "facts": [asdict(f) for f in package.facts] if package else [], "tables": package.tables if package else [],
            "citations": [asdict(r) for r in package.citations] if package else [],
            "limitations": package.limitations if package else result.get("limitations", []),
            "database_instance_id": database.database_instance_id,
            "analysis_revision": package.analysis_revision if package else database.current_revision,
            "evidence_snapshot_digest": package.evidence_snapshot_digest if package else None,
            "model": result.get("model_name"), "model_digest": result.get("model_digest"),
            "resolved_scope": asdict(scope),
            "validated_plan": ([{"step": index + 1, "operator": step.operator,
                                  "input_refs": step.input_refs, "parameters": step.parameters}
                                 for index, step in enumerate(plan.ordered_steps)] if plan else []),
            "execution": trace,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
        }
        self.audit.append({
            "trace_id": trace_id, "question": question, "route": response["route"],
            "database_instance_id": database.database_instance_id, "analysis_revision": response["analysis_revision"],
            "evidence_snapshot_digest": response["evidence_snapshot_digest"],
            "model_name": response["model"], "model_digest": response["model_digest"],
            "scope": asdict(scope), "plan": asdict(plan) if plan else None, "trace": trace,
            "answer_package": package.to_dict() if package else None, "displayed_answer": response["answer"],
            "status": status, "error": error,
        })
        return response
