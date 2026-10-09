from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AnalysisScope:
    upload_ids: List[str] = field(default_factory=list)
    batch_ids: List[str] = field(default_factory=list)
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    endpoint_filters: List[str] = field(default_factory=list)
    call_type: Optional[str] = None
    confidence_policy: str = "reported"


@dataclass
class QueryIntent:
    intent_type: str
    requested_metrics: List[str] = field(default_factory=list)
    grouping: List[str] = field(default_factory=list)
    ordering: Optional[str] = None
    requested_evidence_depth: str = "summary"
    ambiguity_status: Optional[str] = None


@dataclass
class PlanStep:
    operator: str
    input_refs: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    output_type: str = "table"


@dataclass
class QueryPlan:
    plan_id: str
    route: str
    scope: AnalysisScope
    ordered_steps: List[PlanStep]
    expected_output_schema: Dict[str, str] = field(default_factory=dict)
    required_evidence: List[str] = field(default_factory=list)
    complexity_score: int = 1


@dataclass
class EvidenceRef:
    citation_id: str
    database_instance_id: str
    analysis_revision: int
    view_name: str
    primary_id: str
    record_snapshot_hash: str
    upload_id: Optional[str] = None
    packet_no: Optional[int] = None
    flow_id: Optional[str] = None
    party_id: Optional[str] = None
    session_id: Optional[str] = None


@dataclass
class EvidenceFact:
    fact_id: str
    value: Any
    unit: Optional[str]
    derivation: str
    evidence_refs: List[EvidenceRef]
    confidence: str = "database_exact"
    limitations: List[str] = field(default_factory=list)


@dataclass
class AnswerPackage:
    question: str
    resolved_scope: AnalysisScope
    direct_answer: str
    facts: List[EvidenceFact]
    tables: List[Dict[str, Any]]
    citations: List[EvidenceRef]
    evidence_snapshots: Dict[str, Dict[str, Any]]
    evidence_source_digests: List[Dict[str, Any]]
    limitations: List[str]
    database_instance_id: str
    analysis_revision: int
    evidence_snapshot_digest: str
    calculation_trace_digest: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

