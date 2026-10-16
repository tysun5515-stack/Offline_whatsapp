# Architecture

## Primary analyzer

The Flask application in `src/webapp` owns evidence registration, runtime job
coordination, persistence, user-facing analysis, reports, and deletion. Source
captures are immutable inputs; filtered captures and SQLite rows are derived
artifacts that can be rebuilt.

`src/pcap_reader.py` reads PCAP/PCAPNG records. `src/packet_parser.py` extracts
network and protocol fields. `src/flow_builder.py` reconstructs conversations,
and `src/whatsapp_filter.py` assigns evidence strength and activity labels.
`src/pipeline.py` is the shared orchestration boundary used by the CLI and job
worker.

The registry database tracks source and filtered evidence. The analysis
database stores derived packets, flows, parties, sessions, crypto observations,
metrics, and agent-facing read-only views. Records are joined through upload and
batch identifiers rather than inferred filenames.

## Optional companion

`whatsapp_ai_harness` is independently launched on loopback port 5055. It opens
the analysis database read-only, validates allowlisted query plans, executes
parameterized operators, verifies citations, and writes only to its separate
audit database. It never imports the capture parser or mutates forensic rows.

## Compatibility

Canonical UI routes are `/uploads`, `/filtering`, `/analysis`, and `/reports`.
The former `/interface/1`, `/interface/2`, `/interface/3`, `/interface/5`, and
`/interface/report-generation` routes redirect to their canonical equivalents.
Existing JSON API paths and response shapes are unchanged.
