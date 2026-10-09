from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence, Tuple

from .live_source import LiveDatabase
from .types import EvidenceFact, EvidenceRef, PlanStep


class OperatorError(RuntimeError):
    pass


@dataclass
class OperatorResult:
    operator: str
    rows: List[Dict[str, Any]]
    facts: List[EvidenceFact] = field(default_factory=list)
    citations: List[EvidenceRef] = field(default_factory=list)
    evidence_snapshots: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    summary: str = ""
    query_digest: str = ""
    parameters: List[Any] = field(default_factory=list)


def _digest(sql: str, params: Sequence[Any]) -> str:
    return hashlib.sha256((sql + "\0" + json.dumps(list(params), sort_keys=True, default=str)).encode()).hexdigest()


def _row_hash(row: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(row, sort_keys=True, default=str, separators=(",", ":")).encode()).hexdigest()


def _citation(db: LiveDatabase, revision: int, view: str, row: Dict[str, Any], primary: str) -> EvidenceRef:
    primary_id = str(row.get(primary) or row.get("upload_id") or row.get("endpoint_ip") or "aggregate")
    snapshot_hash = _row_hash(row)
    raw = f"{db.database_instance_id}|{revision}|{view}|{primary_id}|{snapshot_hash}"
    return EvidenceRef(
        citation_id="ev-" + hashlib.sha256(raw.encode()).hexdigest()[:20],
        database_instance_id=db.database_instance_id, analysis_revision=revision,
        view_name=view, primary_id=primary_id, record_snapshot_hash=snapshot_hash,
        upload_id=row.get("upload_id") or row.get("capture_id"), packet_no=row.get("packet_no"),
        flow_id=row.get("flow_id"), party_id=row.get("party_id"), session_id=row.get("session_id"),
    )


def _with_citations(db: LiveDatabase, revision: int, view: str, rows: List[Dict[str, Any]],
                    primary: str, sql: str, params: Sequence[Any]) -> Tuple[List[EvidenceRef], Dict[str, Dict[str, Any]]]:
    evidence_rows = rows or [{primary: f"aggregate-{_digest(sql, params)[:16]}", "aggregate": True}]
    refs = [_citation(db, revision, view, row, primary) for row in evidence_rows]
    return refs, {ref.citation_id: row for ref, row in zip(refs, evidence_rows)}


def _fact(operator: str, value: Any, unit: str | None, derivation: str,
          citations: List[EvidenceRef], limitations: List[str] | None = None) -> EvidenceFact:
    return EvidenceFact(
        fact_id=f"fact-{operator}-{hashlib.sha256((derivation + str(value)).encode()).hexdigest()[:12]}",
        value=value, unit=unit, derivation=derivation, evidence_refs=citations,
        limitations=limitations or [],
    )


def _run(conn: sqlite3.Connection, sql: str, params: Sequence[Any]) -> List[Dict[str, Any]]:
    try:
        return [dict(row) for row in conn.execute(sql, tuple(params)).fetchall()]
    except sqlite3.Error as exc:
        raise OperatorError(f"Read-only query failed: {exc}") from exc


def _scope(params: Dict[str, Any], alias: str, upload_col: str, time_col: str | None = None,
           batch_col: str | None = "batch_id") -> Tuple[List[str], List[Any]]:
    where: List[str] = []
    values: List[Any] = []
    uploads = params.get("upload_ids") or []
    batches = params.get("batch_ids") or []
    if uploads:
        where.append(f"{alias}.{upload_col} IN ({','.join('?' for _ in uploads)})"); values.extend(uploads)
    if batches and batch_col:
        where.append(f"{alias}.{batch_col} IN ({','.join('?' for _ in batches)})"); values.extend(batches)
    if time_col and params.get("start_time") is not None:
        where.append(f"{alias}.{time_col} >= ?"); values.append(float(params["start_time"]))
    if time_col and params.get("end_time") is not None:
        where.append(f"{alias}.{time_col} < ?"); values.append(float(params["end_time"]))
    return where, values


def _endpoints(params: Dict[str, Any]) -> List[str]:
    values = list(dict.fromkeys(str(v) for v in (params.get("endpoint_filters") or []) if v))
    if params.get("endpoint") and params["endpoint"] not in values:
        values.append(str(params["endpoint"]))
    return values


def _result(db: LiveDatabase, revision: int, op: str, view: str, primary: str,
            sql: str, values: Sequence[Any], rows: List[Dict[str, Any]], fact_value: Any,
            unit: str | None, derivation: str, summary: str,
            limitations: List[str] | None = None) -> OperatorResult:
    refs, snapshots = _with_citations(db, revision, view, rows, primary, sql, values)
    return OperatorResult(op, rows, [_fact(op, fact_value, unit, derivation, refs, limitations)],
                          refs, snapshots, summary, _digest(sql, values), list(values))


def execute_operator(db: LiveDatabase, revision: int, step: PlanStep, conn: sqlite3.Connection,
                     hard_limit: int) -> OperatorResult:
    op, p = step.operator, dict(step.parameters)
    limit = min(max(int(p.get("limit", 50)), 1), hard_limit)

    if op == "dataset_overview":
        sql, values = "SELECT * FROM v_agent_dataset", []
        rows = _run(conn, sql, values)
        return _result(db, revision, op, "v_agent_dataset", "database_instance_id", sql, values, rows,
                       rows[0] if rows else {}, None, "Read the live database contract summary.",
                       "Live forensic database overview retrieved.")

    if op in {"capture_summary", "list_captures"}:
        where, values = _scope(p, "c", "upload_id", "capture_start_ts")
        clause = " WHERE " + " AND ".join(where) if where else ""
        if op == "capture_summary":
            sql = ("SELECT state,quality_status,COUNT(*) AS capture_count,SUM(packet_count) AS packet_count,"
                   "SUM(flow_count) AS flow_count,SUM(party_count) AS party_count,SUM(session_count) AS session_count "
                   "FROM v_agent_captures c" + clause + " GROUP BY state,quality_status ORDER BY state,quality_status")
        else:
            sql = ("SELECT * FROM v_agent_captures c" + clause + " ORDER BY capture_start_ts DESC LIMIT ?")
            values.append(limit)
        rows = _run(conn, sql, values)
        return _result(db, revision, op, "v_agent_captures", "upload_id", sql, values, rows, rows,
                       None, "Selected readiness-filtered capture provenance records.",
                       f"Retrieved {len(rows)} capture result row(s).")

    if op in {"packet_summary", "list_packets", "packet_detail"}:
        where, values = _scope(p, "p", "upload_id", "timestamp")
        endpoints = _endpoints(p)
        if endpoints:
            marks = ','.join('?' for _ in endpoints)
            where.append(f"(p.src_ip IN ({marks}) OR p.dst_ip IN ({marks}))"); values.extend(endpoints + endpoints)
        for key, column in (("protocol", "protocol"), ("confidence", "whatsapp_confidence"),
                            ("activity", "whatsapp_media_guess")):
            if p.get(key): where.append(f"lower(p.{column})=?"); values.append(str(p[key]).lower())
        if op == "packet_detail":
            where.append("p.packet_no=?"); values.append(int(p["packet_no"]))
        clause = " WHERE " + " AND ".join(where) if where else ""
        if op == "packet_summary":
            sql = ("SELECT COALESCE(whatsapp_media_guess,'unknown') AS activity,protocol,whatsapp_confidence,"
                   "COUNT(*) AS packet_count,SUM(COALESCE(length,0)) AS total_bytes,COUNT(DISTINCT flow_id) AS flow_count "
                   "FROM v_agent_packets p" + clause +
                   " GROUP BY activity,protocol,whatsapp_confidence ORDER BY packet_count DESC LIMIT ?")
            values.append(limit)
        else:
            sql = "SELECT * FROM v_agent_packets p" + clause + " ORDER BY timestamp LIMIT ?"
            values.append(2 if op == "packet_detail" else limit)
        rows = _run(conn, sql, values)
        return _result(db, revision, op, "v_agent_packets", "packet_id", sql, values, rows, rows,
                       None, "Read filtered and classified packet metadata; no payload bytes were queried.",
                       f"Retrieved {len(rows)} packet result row(s).")

    if op in {"flow_summary", "list_flows", "flow_detail", "endpoint_history"}:
        where, values = _scope(p, "f", "upload_id", "first_seen")
        endpoints = _endpoints(p)
        if endpoints:
            marks = ','.join('?' for _ in endpoints)
            where.append(f"(f.endpoint_a_ip IN ({marks}) OR f.endpoint_b_ip IN ({marks}))"); values.extend(endpoints + endpoints)
        if p.get("protocol"): where.append("lower(f.protocol)=?"); values.append(str(p["protocol"]).lower())
        if p.get("media_type"): where.append("lower(f.media_type)=?"); values.append(str(p["media_type"]).lower())
        if p.get("confidence"): where.append("lower(f.confidence)=?"); values.append(str(p["confidence"]).lower())
        if op == "flow_detail": where.append("f.flow_id=?"); values.append(p["flow_id"])
        clause = " WHERE " + " AND ".join(where) if where else ""
        if op == "flow_summary":
            sql = ("SELECT protocol,COALESCE(media_type,'unknown') AS media_type,confidence,COUNT(*) AS flow_count,"
                   "SUM(a_to_b_packets+b_to_a_packets) AS total_packets,SUM(a_to_b_bytes+b_to_a_bytes) AS total_bytes "
                   "FROM v_agent_flows f" + clause +
                   " GROUP BY protocol,media_type,confidence ORDER BY flow_count DESC LIMIT ?")
        else:
            sql = "SELECT * FROM v_agent_flows f" + clause + " ORDER BY first_seen LIMIT ?"
        values.append(2 if op == "flow_detail" else limit)
        rows = _run(conn, sql, values)
        return _result(db, revision, op, "v_agent_flows", "flow_id", sql, values, rows, rows,
                       None, "Selected bidirectional persisted flow records.", f"Retrieved {len(rows)} flow row(s).")

    if op == "traffic_by_capture":
        where, values = _scope(p, "f", "upload_id", "first_seen")
        if p.get("protocol"):
            where.append("lower(f.protocol)=?"); values.append(str(p["protocol"]).lower())
        endpoints = _endpoints(p)
        if endpoints:
            marks = ','.join('?' for _ in endpoints)
            where.append(f"(f.endpoint_a_ip IN ({marks}) OR f.endpoint_b_ip IN ({marks}))")
            values.extend(endpoints + endpoints)
        clause = " WHERE " + " AND ".join(where) if where else ""
        sql = ("SELECT upload_id,batch_id,protocol,COUNT(*) AS flow_count,"
               "SUM(a_to_b_packets+b_to_a_packets) AS total_packets,"
               "SUM(a_to_b_bytes+b_to_a_bytes) AS total_bytes FROM v_agent_flows f" + clause +
               " GROUP BY upload_id,batch_id,protocol ORDER BY total_bytes DESC LIMIT ?")
        values.append(limit); rows = _run(conn, sql, values)
        return _result(db, revision, op, "v_agent_flows", "upload_id", sql, values, rows, rows,
                       None, "Grouped persisted bidirectional traffic totals by capture.",
                       f"Compared traffic across {len(rows)} capture/protocol group(s).")

    if op in {"party_summary", "list_parties", "party_detail"}:
        where, values = _scope(p, "p", "upload_id", "first_seen")
        endpoints = _endpoints(p)
        if endpoints:
            marks = ','.join('?' for _ in endpoints)
            where.append(f"(p.endpoint_a_ip IN ({marks}) OR p.endpoint_b_ip IN ({marks}) OR p.remote_ip IN ({marks}))")
            values.extend(endpoints + endpoints + endpoints)
        if p.get("role"): where.append("lower(p.role_label)=?"); values.append(str(p["role"]).lower())
        if p.get("confidence"): where.append("lower(p.confidence)=?"); values.append(str(p["confidence"]).lower())
        if op == "party_detail": where.append("p.party_id=?"); values.append(p["party_id"])
        clause = " WHERE " + " AND ".join(where) if where else ""
        if op == "party_summary":
            sql = ("SELECT COALESCE(role_label,party_type,'unknown') AS role,traffic_class,protocol,COUNT(*) AS party_count,"
                   "SUM(total_bytes) AS total_bytes,SUM(packet_count) AS packet_count FROM v_agent_parties p" + clause +
                   " GROUP BY role,traffic_class,protocol ORDER BY party_count DESC LIMIT ?")
        else:
            sql = "SELECT * FROM v_agent_parties p" + clause + " ORDER BY first_seen LIMIT ?"
        values.append(2 if op == "party_detail" else limit)
        rows = _run(conn, sql, values)
        limitations = ["Infrastructure and relay roles do not identify a human peer."]
        return _result(db, revision, op, "v_agent_parties", "party_id", sql, values, rows, rows,
                       None, "Selected persisted endpoint-party records.", f"Retrieved {len(rows)} party row(s).", limitations)

    if op in {"count_calls", "list_calls", "call_detail"}:
        where, values = _scope(p, "c", "capture_id", "start_ts")
        if not p.get("include_candidates"): where.append("c.confirmation_class='confirmed'")
        if p.get("call_type"): where.append("lower(c.call_type)=?"); values.append(str(p["call_type"]).lower())
        if p.get("confidence"): where.append("lower(c.confidence)=?"); values.append(str(p["confidence"]).lower())
        endpoints = _endpoints(p)
        for endpoint in endpoints:
            where.append("(c.local_subscriber_ip=? OR c.remote_endpoints LIKE ?)"); values.extend([endpoint, f'%"{endpoint}"%'])
        if op == "call_detail": where.append("c.session_id=?"); values.append(p["session_id"])
        clause = " WHERE " + " AND ".join(where) if where else ""
        if op == "count_calls":
            count_sql = "SELECT COUNT(DISTINCT c.session_id) AS call_count FROM v_agent_calls c" + clause
            count_rows = _run(conn, count_sql, values); count = int(count_rows[0]["call_count"])
            evidence_sql = "SELECT * FROM v_agent_calls c" + clause + " ORDER BY start_ts LIMIT ?"
            evidence_values = [*values, hard_limit]; rows = _run(conn, evidence_sql, evidence_values)
            refs, snapshots = _with_citations(db, revision, "v_agent_calls", rows, "session_id", count_sql, values)
            limitations = [] if len(rows) == count else ["Evidence row display is capped; the exact count covers the full scope."]
            return OperatorResult(op, count_rows, [_fact(op, count, "calls", "COUNT(DISTINCT session_id) over qualified sessions.", refs, limitations)],
                                  refs, snapshots, f"{count} qualified call(s) matched the scope.", _digest(count_sql, values), values)
        order = {"shortest": "observed_span_s ASC", "longest": "observed_span_s DESC",
                 "latest": "start_ts DESC"}.get(p.get("order"), "start_ts DESC")
        sql = "SELECT * FROM v_agent_calls c" + clause + f" ORDER BY {order} LIMIT ?"
        values.append(2 if op == "call_detail" else limit); rows = _run(conn, sql, values)
        return _result(db, revision, op, "v_agent_calls", "session_id", sql, values, rows, rows,
                       None, "Selected qualified session records; direction was not inferred.",
                       f"Retrieved {len(rows)} call session row(s).",
                       ["Caller/callee direction is unknown unless explicit evidence proves it."])

    if op == "list_unique_endpoints":
        where, values = _scope(p, "f", "upload_id", "first_seen")
        clause = " WHERE " + " AND ".join(where) if where else ""
        base_values = list(values)
        sql = ("SELECT endpoint_ip,MIN(first_seen) AS first_seen,MAX(last_seen) AS last_seen,"
               "COUNT(DISTINCT upload_id) AS capture_count,COUNT(DISTINCT flow_id) AS flow_count FROM ("
               "SELECT upload_id,flow_id,endpoint_a_ip AS endpoint_ip,first_seen,last_seen FROM v_agent_flows f" + clause +
               " UNION ALL SELECT upload_id,flow_id,endpoint_b_ip,first_seen,last_seen FROM v_agent_flows f" + clause +
               ") WHERE endpoint_ip IS NOT NULL GROUP BY endpoint_ip ORDER BY flow_count DESC,endpoint_ip LIMIT ?")
        values = [*base_values, *base_values, limit]; rows = _run(conn, sql, values)
        return _result(db, revision, op, "v_agent_endpoints", "endpoint_ip", sql, values, rows, len(rows),
                       "endpoints returned", "Selected distinct normalized endpoint IP values.",
                       f"Retrieved {len(rows)} unique endpoint(s).")

    if op == "rank_endpoints":
        where, scoped_values = _scope(p, "f", "upload_id", "first_seen")
        clause = " WHERE " + " AND ".join(where) if where else ""
        order_by = p.get("order_by", "total_bytes")
        if order_by not in {"total_bytes", "total_packets", "flow_count"}:
            raise OperatorError("rank_endpoints order_by is invalid")
        endpoint_rows = (
            "SELECT upload_id,flow_id,endpoint_a_ip AS endpoint_ip,"
            "a_to_b_packets+b_to_a_packets AS packets,a_to_b_bytes+b_to_a_bytes AS bytes,"
            "CASE WHEN endpoint_a_ip=local_subscriber_ip THEN 1 ELSE 0 END AS is_subscriber "
            "FROM v_agent_flows f" + clause +
            " UNION ALL SELECT upload_id,flow_id,endpoint_b_ip,"
            "a_to_b_packets+b_to_a_packets,a_to_b_bytes+b_to_a_bytes,"
            "CASE WHEN endpoint_b_ip=local_subscriber_ip THEN 1 ELSE 0 END FROM v_agent_flows f" + clause
        )
        sql = ("SELECT endpoint_ip,COUNT(DISTINCT flow_id) AS flow_count,SUM(packets) AS total_packets,"
               "SUM(bytes) AS total_bytes,COUNT(DISTINCT upload_id) AS capture_count,"
               "MAX(is_subscriber) AS observed_as_subscriber FROM (" + endpoint_rows + ") "
               "WHERE endpoint_ip IS NOT NULL GROUP BY endpoint_ip "
               f"ORDER BY {order_by} DESC,endpoint_ip LIMIT ?")
        values = [*scoped_values, *scoped_values, limit]; rows = _run(conn, sql, values)
        winner = rows[0] if rows else None
        summary = (
            f"{winner['endpoint_ip']} is the highest-ranked IP by {order_by.replace('_', ' ')} "
            f"({winner[order_by]:,}); it appears in {winner['flow_count']} flow(s)."
            if winner else "No endpoint traffic is available in the selected ready evidence."
        )
        return _result(db, revision, op, "v_agent_flows", "endpoint_ip", sql, values, rows,
                       winner or {}, None,
                       f"Ranked endpoints by {order_by} over persisted bidirectional flows.", summary,
                       ["Traffic attributed to an endpoint is the full bidirectional traffic of each flow involving it."])

    if op in {"crypto_summary", "crypto_detail", "crypto_evidence"}:
        view = "v_agent_crypto_evidence" if op == "crypto_evidence" else "v_agent_crypto"
        alias = "e" if op == "crypto_evidence" else "c"
        time_col = "ts" if op == "crypto_evidence" else "first_seen"
        where, values = _scope(p, alias, "upload_id", time_col)
        if p.get("flow_id"): where.append(f"{alias}.flow_id=?"); values.append(p["flow_id"])
        endpoints = _endpoints(p)
        if endpoints and op != "crypto_evidence":
            marks = ','.join('?' for _ in endpoints)
            where.append(f"(c.client_ip IN ({marks}) OR c.server_ip IN ({marks}))"); values.extend(endpoints + endpoints)
        clause = " WHERE " + " AND ".join(where) if where else ""
        if op == "crypto_summary":
            sql = ("SELECT COALESCE(pqc_state,'unknown') AS pqc_state,COALESCE(transport,'unknown') AS transport,"
                   "COUNT(*) AS flow_count,SUM(CASE WHEN server_hello_complete=1 THEN 1 ELSE 0 END) AS complete_server_hello_count "
                   "FROM v_agent_crypto c" + clause + " GROUP BY pqc_state,transport ORDER BY flow_count DESC LIMIT ?")
        else:
            sql = f"SELECT * FROM {view} {alias}" + clause + f" ORDER BY {time_col} LIMIT ?"
        values.append(limit); rows = _run(conn, sql, values)
        primary = "event_id" if op == "crypto_evidence" else "flow_id"
        return _result(db, revision, op, view, primary, sql, values, rows, rows, None,
                       "Read flow-linked cryptographic evidence; negotiation requires a complete ServerHello.",
                       f"Retrieved {len(rows)} cryptographic evidence row(s).",
                       ["Capability or offer evidence is not the same as negotiated PQC."])

    if op in {"geo_summary", "metrics_summary", "correlation_summary", "quality_summary"}:
        where: List[str] = []; values: List[Any] = []
        if op == "geo_summary":
            endpoints = _endpoints(p)
            if endpoints:
                where.append("g.ip IN (%s)" % ','.join('?' for _ in endpoints)); values.extend(endpoints)
            clause = " WHERE " + " AND ".join(where) if where else ""
            view, primary = "v_agent_geo", "ip"
            sql = ("SELECT country,asn,asn_org,COUNT(*) AS endpoint_count FROM v_agent_geo g" + clause +
                   " GROUP BY country,asn,asn_org ORDER BY endpoint_count DESC LIMIT ?")
        elif op == "metrics_summary":
            where, values = _scope(p, "m", "upload_id", None)
            clause = " WHERE " + " AND ".join(where) if where else ""
            view, primary, sql = "v_agent_metrics", "upload_id", "SELECT * FROM v_agent_metrics m" + clause + " ORDER BY upload_id LIMIT ?"
        elif op == "correlation_summary":
            uploads = p.get("upload_ids") or []
            if uploads:
                marks = ','.join('?' for _ in uploads)
                where.append(f"(c.upload_id_a IN ({marks}) OR c.upload_id_b IN ({marks}))"); values.extend(uploads + uploads)
            clause = " WHERE " + " AND ".join(where) if where else ""
            view, primary, sql = "v_agent_correlations", "id", "SELECT * FROM v_agent_correlations c" + clause + " ORDER BY score DESC LIMIT ?"
        else:
            uploads = p.get("upload_ids") or []
            if uploads:
                where.append("q.upload_id IN (%s)" % ','.join('?' for _ in uploads)); values.extend(uploads)
            clause = " WHERE " + " AND ".join(where) if where else ""
            view, primary, sql = "v_agent_quality", "finding_id", "SELECT * FROM v_agent_quality q" + clause + " ORDER BY finding_id DESC LIMIT ?"
        values.append(limit); rows = _run(conn, sql, values)
        return _result(db, revision, op, view, primary, sql, values, rows, rows, None,
                       f"Read the live {op.replace('_', ' ')} view.", f"Retrieved {len(rows)} result row(s).")

    if op == "rule_search":
        query = str(p.get("query") or "").strip()
        tokens = [token for token in query.replace('"', ' ').split() if len(token) > 2][:8]
        match = " OR ".join(f'"{token}"' for token in tokens) or '"limitation"'
        sql = "SELECT rule_id,title,body,category FROM agent_rules_fts WHERE agent_rules_fts MATCH ? LIMIT ?"
        values = [match, limit]
        try:
            rows = _run(conn, sql, values)
        except OperatorError:
            sql = "SELECT * FROM v_agent_rules WHERE lower(title||' '||body) LIKE ? LIMIT ?"
            values = [f"%{query.lower()}%", limit]; rows = _run(conn, sql, values)
        return _result(db, revision, op, "v_agent_rules", "rule_id", sql, values, rows, rows, None,
                       "Retrieved stored forensic definitions and limitations.", f"Retrieved {len(rows)} rule row(s).")

    raise OperatorError(f"Unsupported operator {op!r}")


def execute_composition(db: LiveDatabase, revision: int, step: PlanStep,
                        prior: Dict[str, OperatorResult], hard_limit: int) -> OperatorResult:
    inputs = [prior[ref].rows for ref in step.input_refs]
    op, p = step.operator, step.parameters
    if op == "compare_results":
        field_name = p.get("field")
        rows = []
        for ref in step.input_refs:
            values = [row.get(field_name) for row in prior[ref].rows] if field_name else []
            if field_name and any(value is not None and not isinstance(value, (int, float)) for value in values):
                raise OperatorError(f"compare_results field {field_name!r} must contain numeric values")
            rows.append({"input_ref": ref, "field": field_name,
                         "value": sum(value for value in values if value is not None) if field_name else len(prior[ref].rows)})
    elif op in {"set_intersection", "set_difference"}:
        field_name = p["field"]
        sets = [{str(row.get(field_name)) for row in rows if row.get(field_name) is not None} for rows in inputs]
        values = sets[0].intersection(*sets[1:]) if op == "set_intersection" else sets[0].difference(*sets[1:])
        rows = [{field_name: value} for value in sorted(values)[:hard_limit]]
    elif op == "rank_results":
        field_name = p["field"]
        descending = p.get("order", "desc") == "desc"
        present = [row for row in inputs[0] if row.get(field_name) is not None]
        if present and len({type(row[field_name]) for row in present}) > 1:
            raise OperatorError(f"rank_results field {field_name!r} has incompatible value types")
        rows = sorted(present, key=lambda row: row[field_name], reverse=descending)[:hard_limit]
    elif op == "trend_results":
        time_field, value_field = p["time_field"], p["value_field"]
        source = [row for row in inputs[0] if row.get(time_field) is not None and row.get(value_field) is not None]
        if any(not isinstance(row[value_field], (int, float)) for row in source):
            raise OperatorError(f"trend_results field {value_field!r} must contain numeric values")
        source.sort(key=lambda row: row[time_field]); rows = []
        previous = None
        for row in source[:hard_limit]:
            current = row[value_field]
            rows.append({time_field: row[time_field], value_field: current,
                         "change_from_previous": None if previous is None else current - previous})
            previous = current
    else:
        raise OperatorError(f"Unsupported composition operator {op!r}")
    sql = f"trusted-python:{op}"; params = [step.input_refs, p]
    refs: List[EvidenceRef] = []
    snapshots: Dict[str, Dict[str, Any]] = {}
    for ref in step.input_refs:
        refs.extend(prior[ref].citations); snapshots.update(prior[ref].evidence_snapshots)
    fact = _fact(op, rows, None, f"Trusted Python {op} over validated step outputs.", refs)
    return OperatorResult(op, rows, [fact], refs, snapshots, f"Computed {op} over {len(inputs)} input(s).",
                          _digest(sql, params), params)
