"""Upload-level readiness and provenance for the live AI query contract."""
from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.geo_mapping import classify_remote_party
from src.party_grouper import group_into_entities
from src.session_engine import attach_session_metrics, reconstruct_flow_sessions
from src.webapp import db_analysis, db_registry


class AnalysisReadinessError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_error(error: Any) -> str:
    return " ".join(str(error).split())[:1000]


def _state_values(upload: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "upload_id": upload["upload_id"], "batch_id": upload.get("batch_id") or upload["upload_id"],
        "filename": upload.get("filename"), "file_format": upload.get("file_format"),
        "source_sha256": upload.get("sha256_hash"), "filtered_sha256": upload.get("filtered_sha256"),
        "capture_start_ts": upload.get("capture_start_ts"), "capture_end_ts": upload.get("capture_end_ts"),
        "capture_packet_count": upload.get("capture_packet_count"),
        "capture_duration_s": upload.get("capture_duration_s"),
        "capture_vantage": upload.get("capture_vantage"), "subscriber_ips": upload.get("subscriber_ips"),
    }


def begin_upload_analysis(upload: Dict[str, Any]) -> None:
    values = _state_values(upload)
    conn = db_analysis._connect()
    conn.execute("""INSERT INTO analysis_upload_state
        (upload_id,batch_id,filename,file_format,source_sha256,filtered_sha256,capture_start_ts,
         capture_end_ts,capture_packet_count,capture_duration_s,capture_vantage,subscriber_ips,
         state,contract_version,ruleset_version,quality_status,started_at,error)
        VALUES (:upload_id,:batch_id,:filename,:file_format,:source_sha256,:filtered_sha256,:capture_start_ts,
                :capture_end_ts,:capture_packet_count,:capture_duration_s,:capture_vantage,:subscriber_ips,
                'processing',:contract,:ruleset,'pending',:started,NULL)
        ON CONFLICT(upload_id) DO UPDATE SET
          batch_id=excluded.batch_id,filename=excluded.filename,file_format=excluded.file_format,
          source_sha256=excluded.source_sha256,filtered_sha256=excluded.filtered_sha256,
          capture_start_ts=excluded.capture_start_ts,capture_end_ts=excluded.capture_end_ts,
          capture_packet_count=excluded.capture_packet_count,capture_duration_s=excluded.capture_duration_s,
          capture_vantage=excluded.capture_vantage,subscriber_ips=excluded.subscriber_ips,
          state='processing',contract_version=excluded.contract_version,ruleset_version=excluded.ruleset_version,
          quality_status='pending',started_at=excluded.started_at,completed_at=NULL,error=NULL""", {
        **values, "contract": db_analysis.AGENT_CONTRACT_VERSION,
        "ruleset": db_analysis.AGENT_RULESET_VERSION, "started": _now(),
    })
    conn.commit(); conn.close()


def _append_revision(conn, upload_id: str, event: str, digest: str) -> int:
    previous = conn.execute(
        "SELECT record_hash FROM analysis_revision_ledger ORDER BY revision_id DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous[0] if previous else ""
    created = _now()
    record_hash = hashlib.sha256(
        f"{previous_hash}|{upload_id}|{event}|{digest}|{created}".encode()
    ).hexdigest()
    cursor = conn.execute("""INSERT INTO analysis_revision_ledger
        (upload_id,event,result_digest,previous_hash,record_hash,created_at)
        VALUES (?,?,?,?,?,?)""", (upload_id, event, digest, previous_hash, record_hash, created))
    return int(cursor.lastrowid)


def fail_upload_analysis(upload_id: str, error: Any) -> None:
    message = _safe_error(error)
    digest = hashlib.sha256(message.encode()).hexdigest()
    conn = db_analysis._connect()
    conn.execute("BEGIN IMMEDIATE")
    revision = _append_revision(conn, upload_id, "failed", digest)
    conn.execute("DELETE FROM analysis_quality_findings WHERE upload_id=?", (upload_id,))
    conn.execute("""INSERT INTO analysis_quality_findings
        (upload_id,revision_id,severity,code,message,created_at) VALUES (?,?,?,?,?,?)""",
        (upload_id, revision, "error", "analysis_failed", message, _now()))
    conn.execute("""UPDATE analysis_upload_state SET state='failed',analysis_revision=?,quality_status='fail',
        result_digest=?,completed_at=?,error=? WHERE upload_id=?""",
        (revision, digest, _now(), message, upload_id))
    conn.commit(); conn.close()


def _verify_registered_hash(path: Optional[str], expected: Optional[str], label: str) -> Optional[str]:
    if not path or not os.path.isfile(path):
        return f"{label} bytes are unavailable; the registered digest is retained."
    actual = db_registry.sha256_file(path)
    if expected and actual != expected:
        raise AnalysisReadinessError(f"{label} hash mismatch")
    return None


def _derive_roles(parties: List[Dict[str, Any]]) -> None:
    conn = db_analysis._connect()
    try:
        for party in parties:
            remote_ip = party.get("remote_ip") or ""
            geo = conn.execute("SELECT * FROM geo_cache WHERE ip=?", (remote_ip,)).fetchone()
            geo = dict(geo) if geo else {}
            result = classify_remote_party(
                remote_ip, geo.get("asn"), geo.get("asn_org"), party.get("party_type", "unknown"),
                party.get("remote_port"), party.get("protocol"),
            )
            party.update({
                "role_label": result.get("role_label"), "role_source": "geo_cache" if geo else "endpoint_scope",
                "caveat_type": result.get("caveat_type"), "caveat": result.get("caveat_label"),
                "is_server": int(bool(result.get("is_server"))),
                "location_reliable": int(bool(result.get("location_reliable"))),
            })
    finally:
        conn.close()


def _persist_roles(upload_id: str, parties: List[Dict[str, Any]]) -> None:
    conn = db_analysis._connect()
    conn.executemany("""UPDATE parties SET role_label=?,role_source=?,caveat_type=?,caveat=?,
        is_server=?,location_reliable=? WHERE party_id=? AND upload_id=?""", [
        (p.get("role_label"), p.get("role_source"), p.get("caveat_type"), p.get("caveat"),
         p.get("is_server", 0), p.get("location_reliable", 0), p["party_id"], upload_id)
        for p in parties
    ])
    conn.commit(); conn.close()


def complete_upload_analysis(upload_id: str) -> Dict[str, Any]:
    upload = db_registry.get_upload(upload_id)
    if not upload:
        raise AnalysisReadinessError("Registered upload was not found")
    packets = db_analysis.get_packets(upload_ids=[upload_id])
    batch_id = upload.get("batch_id") or upload_id
    metrics = db_analysis._connect()
    try:
        metric_row = metrics.execute("SELECT * FROM upload_metrics WHERE upload_id=?", (upload_id,)).fetchone()
        metric_data = dict(metric_row) if metric_row else {}
        os_hint = metric_data.get("detected_os") or "unknown"
    finally:
        metrics.close()

    parties = group_into_entities(packets, upload_id, os_hint) if packets else []
    sessions = reconstruct_flow_sessions(packets, parties) if packets else []
    attach_session_metrics(parties, sessions)
    _derive_roles(parties)
    db_analysis.insert_parties(batch_id, parties, upload_id=upload_id)
    _persist_roles(upload_id, parties)
    db_analysis.insert_sessions(batch_id, sessions, upload_id=upload_id)

    conn = db_analysis._connect()
    try:
        flows = [dict(row) for row in conn.execute(
            "SELECT * FROM analysis_flows_v2 WHERE upload_id=?", (upload_id,)
        )]
        crypto_count = conn.execute("SELECT COUNT(*) FROM crypto_flows WHERE upload_id=?", (upload_id,)).fetchone()[0]
        evidence_count = conn.execute("SELECT COUNT(*) FROM crypto_events WHERE upload_id=?", (upload_id,)).fetchone()[0]
    finally:
        conn.close()

    findings: List[Dict[str, str]] = []
    if metric_data and not bool(metric_data.get("reconciliation_ok", 1)):
        raise AnalysisReadinessError("Filter admission/rejection reconciliation failed")
    for label, path, expected in (
        ("Source", upload.get("stored_path"), upload.get("sha256_hash")),
        ("Filtered capture", upload.get("filtered_path"), upload.get("filtered_sha256")),
    ):
        warning = _verify_registered_hash(path, expected, label)
        if warning:
            findings.append({"severity": "warning", "code": "bytes_unavailable", "message": warning})

    packet_flow_ids = {str(row.get("flow_id")) for row in packets if row.get("flow_id")}
    flow_ids = {str(row.get("flow_id")) for row in flows if row.get("flow_id")}
    if packet_flow_ids != flow_ids:
        raise AnalysisReadinessError(
            f"Packet/flow reconciliation failed: packets={len(packet_flow_ids)}, flows={len(flow_ids)}"
        )
    party_flow_ids = {str(value) for party in parties for value in party.get("flow_ids", [])}
    if flow_ids != party_flow_ids:
        raise AnalysisReadinessError(
            f"Party/flow reconciliation failed: flows={len(flow_ids)}, linked={len(party_flow_ids)}"
        )
    party_ids = {str(p["party_id"]) for p in parties}
    for session in sessions:
        if set(map(str, session.get("flow_ids", []))) - flow_ids:
            raise AnalysisReadinessError(f"Session {session.get('session_id')} references an unknown flow")
        if set(map(str, session.get("party_ids", []))) - party_ids:
            raise AnalysisReadinessError(f"Session {session.get('session_id')} references an unknown party")
    if packets:
        confidences = Counter(str(row.get("whatsapp_confidence") or "") for row in packets)
        activities = Counter(str(row.get("sub_activity") or "") for row in packets)
        if len(confidences) == 1:
            findings.append({"severity": "warning", "code": "uniform_confidence",
                             "message": f"All {len(packets)} packets share one confidence value."})
        if len(activities) == 1:
            findings.append({"severity": "warning", "code": "uniform_activity",
                             "message": f"All {len(packets)} packets share one activity value."})

    counts = {
        "packets": len(packets), "flows": len(flows), "parties": len(parties),
        "sessions": len(sessions), "crypto_flows": int(crypto_count),
        "crypto_evidence": int(evidence_count),
    }
    digest_payload = {
        "upload_id": upload_id, "source_sha256": upload.get("sha256_hash"),
        "filtered_sha256": upload.get("filtered_sha256"), "counts": counts,
        "flow_ids": sorted(flow_ids), "party_ids": sorted(party_ids),
        "session_ids": sorted(str(s.get("session_id")) for s in sessions),
        "ruleset": db_analysis.AGENT_RULESET_VERSION,
    }
    result_digest = hashlib.sha256(
        json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    state = "ready" if packets else "ready_no_match"
    quality_status = "warn" if findings else "pass"
    conn = db_analysis._connect()
    conn.execute("BEGIN IMMEDIATE")
    revision = _append_revision(conn, upload_id, state, result_digest)
    conn.execute("DELETE FROM analysis_quality_findings WHERE upload_id=?", (upload_id,))
    if findings:
        conn.executemany("""INSERT INTO analysis_quality_findings
            (upload_id,revision_id,severity,code,message,created_at) VALUES (?,?,?,?,?,?)""", [
            (upload_id, revision, item["severity"], item["code"], item["message"], _now())
            for item in findings
        ])
    conn.execute("""UPDATE analysis_upload_state SET state=?,analysis_revision=?,contract_version=?,ruleset_version=?,
        packet_count=?,flow_count=?,party_count=?,session_count=?,crypto_flow_count=?,crypto_evidence_count=?,
        quality_status=?,result_digest=?,completed_at=?,error=NULL,filtered_sha256=? WHERE upload_id=?""", (
        state, revision, db_analysis.AGENT_CONTRACT_VERSION, db_analysis.AGENT_RULESET_VERSION,
        counts["packets"], counts["flows"], counts["parties"], counts["sessions"],
        counts["crypto_flows"], counts["crypto_evidence"], quality_status, result_digest, _now(),
        upload.get("filtered_sha256"), upload_id,
    ))
    conn.commit(); conn.close()
    return {"upload_id": upload_id, "state": state, "revision": revision, "counts": counts,
            "quality_status": quality_status, "result_digest": result_digest}


def mark_upload_deleted(upload_id: str) -> None:
    digest = hashlib.sha256(f"deleted|{upload_id}|{_now()}".encode()).hexdigest()
    conn = db_analysis._connect(); conn.execute("BEGIN IMMEDIATE")
    revision = _append_revision(conn, upload_id, "deleted", digest)
    conn.execute("UPDATE analysis_upload_state SET state='deleted',analysis_revision=?,result_digest=?,completed_at=? WHERE upload_id=?",
                 (revision, digest, _now(), upload_id))
    conn.commit(); conn.close()


def record_evidence_unavailable(upload_id: str, kind: str) -> None:
    if kind not in {"raw", "filtered"}:
        raise ValueError("kind must be raw or filtered")
    message = f"The registered {kind} evidence bytes were removed after analysis; stored hashes and derived findings remain."
    conn = db_analysis._connect()
    state = conn.execute("SELECT analysis_revision FROM analysis_upload_state WHERE upload_id=?", (upload_id,)).fetchone()
    if state:
        conn.execute("""INSERT INTO analysis_quality_findings
            (upload_id,revision_id,severity,code,message,created_at) VALUES (?,?,?,?,?,?)""",
            (upload_id, state[0], "warning", f"{kind}_bytes_unavailable", message, _now()))
        conn.execute("UPDATE analysis_upload_state SET quality_status='warn' WHERE upload_id=?", (upload_id,))
        conn.commit()
    conn.close()


def backfill_registered_uploads(resume: bool = True) -> List[Dict[str, Any]]:
    results = []
    for upload in db_registry.list_uploads():
        if upload.get("status") not in {"filtered", "analyzed"}:
            continue
        if resume:
            conn = db_analysis._connect()
            row = conn.execute("""SELECT state,ruleset_version FROM analysis_upload_state
                WHERE upload_id=?""", (upload["upload_id"],)).fetchone()
            conn.close()
            if row and row[0] in {"ready", "ready_no_match"} and row[1] == db_analysis.AGENT_RULESET_VERSION:
                results.append({"upload_id": upload["upload_id"], "state": row[0], "skipped": True})
                continue
        begin_upload_analysis(upload)
        try:
            results.append(complete_upload_analysis(upload["upload_id"]))
        except Exception as exc:
            fail_upload_analysis(upload["upload_id"], exc)
            results.append({"upload_id": upload["upload_id"], "state": "failed", "error": _safe_error(exc)})
    return results

