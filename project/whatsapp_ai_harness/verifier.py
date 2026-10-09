from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Sequence

from .operators import OperatorResult
from .live_source import LiveDatabase
from .types import AnalysisScope, AnswerPackage, EvidenceFact, EvidenceRef


class VerificationError(RuntimeError):
    pass


def build_answer_package(question: str, scope: AnalysisScope, database: LiveDatabase,
                         revision: int, results: Sequence[OperatorResult],
                         evidence_source_digests: Sequence[Dict[str, Any]]) -> AnswerPackage:
    facts: List[EvidenceFact] = []
    citations: List[EvidenceRef] = []
    limitations: List[str] = []
    tables = []
    trace = []
    summaries = []
    evidence_snapshots = {}
    for result in results:
        facts.extend(result.facts)
        summaries.append(result.summary)
        tables.append({"operator": result.operator, "rows": result.rows})
        trace.append({"operator": result.operator, "query_digest": result.query_digest,
                      "parameters": result.parameters, "row_count": len(result.rows)})
        for fact in result.facts:
            limitations.extend(fact.limitations)
        citations.extend(result.citations)
        evidence_snapshots.update(result.evidence_snapshots)
    unique = {ref.citation_id: ref for ref in citations}
    citations = list(unique.values())
    if not facts:
        raise VerificationError("The executed plan produced no verifiable facts")
    for fact in facts:
        if not fact.evidence_refs:
            raise VerificationError(f"Fact {fact.fact_id} has no evidence reference")
    trace_digest = hashlib.sha256(json.dumps(trace, sort_keys=True, default=str).encode()).hexdigest()
    digest_material = {
        "record_snapshots": evidence_snapshots,
        "upload_digests": list(evidence_source_digests),
        "analysis_revision": revision,
    }
    evidence_snapshot_digest = hashlib.sha256(
        json.dumps(digest_material, sort_keys=True, default=str, separators=(",", ":")).encode()
    ).hexdigest()
    direct = " ".join(summary for summary in summaries if summary).strip() or "The query completed."
    return AnswerPackage(
        question=question, resolved_scope=scope, direct_answer=direct, facts=facts,
        tables=tables, citations=citations, evidence_snapshots=evidence_snapshots,
        evidence_source_digests=list(evidence_source_digests),
        limitations=sorted(set(limitations)), database_instance_id=database.database_instance_id,
        analysis_revision=revision, evidence_snapshot_digest=evidence_snapshot_digest,
        calculation_trace_digest=trace_digest,
    )


def narration_schema() -> dict:
    return {
        "type": "object", "required": ["answer"],
        "properties": {"answer": {"type": "string", "minLength": 1, "maxLength": 6000}},
        "additionalProperties": False,
    }


def narration_prompt(package: AnswerPackage) -> str:
    return (
        "Write a concise investigator-facing answer using only the verified AnswerPackage below. "
        "Do not calculate, add facts, infer identities or roles, create citations, or mention hidden reasoning. "
        "Preserve all stated limitations. Citation identifiers may be repeated exactly as provided. "
        "Return only JSON matching the requested schema.\nAnswerPackage:\n" +
        json.dumps(package.to_dict(), sort_keys=True, default=str)
    )


def verify_narration(answer: str, package: AnswerPackage) -> str:
    if not isinstance(answer, str) or not answer.strip():
        raise VerificationError("Narration is empty")
    source = json.dumps(package.to_dict(), sort_keys=True, default=str).lower()
    source_numbers = set(re.findall(r"(?<![\w.-])\d+(?:\.\d+)?(?![\w.-])", source))
    # Reject new IP addresses, evidence identifiers, and non-trivial numbers.
    for ip in re.findall(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])", answer):
        if ip.lower() not in source:
            raise VerificationError(f"Narration introduced unsupported IP {ip}")
    for evidence_id in re.findall(r"\bev-[a-f0-9]{8,}\b", answer.lower()):
        if evidence_id not in source:
            raise VerificationError("Narration introduced an unsupported evidence identifier")
    for number in re.findall(r"(?<![\w.-])\d+(?:\.\d+)?(?![\w.-])", answer):
        if float(number) >= 2 and number not in source_numbers:
            raise VerificationError(f"Narration introduced unsupported number {number}")
    return answer.strip()

