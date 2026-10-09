# WhatsApp Live Forensic Query Harness

This standalone application opens the growing `whatsapp_analysis.db` read-only.
It never imports the analyzer, accesses PCAP files, or creates an AI-specific
database copy. Only uploads marked `ready` by the producer appear in forensic
views; `ready_no_match` captures remain visible as completed negative results.

## Processing model

The developer application automatically persists packets, flows, parties,
qualified sessions, crypto observations, metrics and quality findings for each
upload. The harness uses three routes:

- Route A executes fixed parameterized operators without an LLM.
- Route B accepts only a validated, allowlisted JSON plan from local Ollama;
  deterministic code performs all retrieval and composition.
- Route C clarifies or refuses unavailable, ambiguous or unsupported claims.

Each investigation pins the database instance, analysis revision, selected
evidence digests, exact cited row snapshots and calculation digest in an
append-only local audit database.

## One-time migration

Stop both applications, then run this once from the project root:

```powershell
python -m src.backfill_ai_readiness --backup-dir migration_backups
```

The command creates consistent backups of both SQLite databases, skips uploads
already ready under the current ruleset, validates existing derived rows, and
reprocesses inconsistent uploads only when registered source bytes still exist.

## Setup

From the project root:

```powershell
py -3.12 -m venv whatsapp_ai_harness\.venv
whatsapp_ai_harness\.venv\Scripts\pip install -r whatsapp_ai_harness\requirements.txt
ollama pull deepseek-r1:8b
whatsapp_ai_harness\.venv\Scripts\python -m whatsapp_ai_harness.serve
```

Open `http://127.0.0.1:5055`. Route A remains available without Ollama.

From inside the `whatsapp_ai_harness` directory, use the directory-safe
Windows launcher instead:

```powershell
.\start_harness.cmd
```

Do not run `python -m whatsapp_ai_harness.app` while the current directory is
the package directory itself; the package contains `types.py`, which would
shadow Python's standard-library `types` module during interpreter startup.

Set `WA_HARNESS_ANALYSIS_DB` only when the canonical analysis database is not
at the project root. Other settings are `WA_HARNESS_INSTANCE_DIR`,
`WA_HARNESS_OLLAMA_URL`, `WA_HARNESS_MODEL`, and
`WA_HARNESS_FALLBACK_MODEL`.

APIs: `GET /api/v1/database`, `POST /api/v1/query`,
`POST /api/v1/query/stream`, `GET /api/v1/investigations/<trace_id>`,
`GET /api/v1/evidence/<citation_id>`, and `GET /api/v1/health`.
