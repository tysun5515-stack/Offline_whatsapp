from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    base_dir: Path
    analysis_db: Path
    instance_dir: Path
    audit_db: Path
    ollama_url: str
    primary_model: str
    fallback_model: str
    context_tokens: int
    query_timeout_ms: int
    default_row_limit: int
    hard_row_limit: int

    @classmethod
    def from_env(cls) -> "Settings":
        base = Path(__file__).resolve().parent
        analysis_db = Path(os.environ.get("WA_HARNESS_ANALYSIS_DB", base.parent / "whatsapp_analysis.db")).resolve()
        instance_dir = Path(os.environ.get("WA_HARNESS_INSTANCE_DIR", base / "instance")).resolve()
        instance_dir.mkdir(parents=True, exist_ok=True)
        return cls(
            base_dir=base,
            analysis_db=analysis_db,
            instance_dir=instance_dir,
            audit_db=instance_dir / "harness_audit.db",
            ollama_url=os.environ.get("WA_HARNESS_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/"),
            primary_model=os.environ.get("WA_HARNESS_MODEL", "deepseek-r1:8b"),
            fallback_model=os.environ.get("WA_HARNESS_FALLBACK_MODEL", "deepseek-r1:7b"),
            context_tokens=int(os.environ.get("WA_HARNESS_CONTEXT", "8192")),
            query_timeout_ms=int(os.environ.get("WA_HARNESS_QUERY_TIMEOUT_MS", "5000")),
            default_row_limit=int(os.environ.get("WA_HARNESS_DEFAULT_LIMIT", "50")),
            hard_row_limit=int(os.environ.get("WA_HARNESS_HARD_LIMIT", "200")),
        )

