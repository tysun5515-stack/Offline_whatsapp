# WhatsApp Offline Traffic Analyzer

This project performs offline, evidence-backed analysis of PCAP, PCAPNG, CSV,
and JSON captures. It identifies WhatsApp-associated encrypted traffic using
deterministic network evidence; it does not decrypt message content or infer a
person's identity from an IP address.

## What it does

- Registers source evidence with hashes and capture metadata.
- Parses PCAP and PCAPNG without sending captures to an external service.
- Reconstructs transport flows and conservatively classifies WhatsApp traffic.
- Stores packet, flow, party, session, geolocation, and crypto observations in
  SQLite with source-file provenance.
- Provides packet inspection, flow analysis, reports, JSON export, evidence
  download, comparison, and explicit deletion workflows.
- Optionally runs TShark-assisted crypto inspection when TShark is installed.

The processing path is:

```text
Source evidence -> packet parser -> flow reconstruction -> classification
                -> derived SQLite records -> Flask UI and reports
```

See [Architecture](docs/ARCHITECTURE.md) for subsystem boundaries and
[Validation](docs/VALIDATION.md) for evidence and testing limitations.

## Setup and run

Use Python 3.12 or newer on Windows. From the project root:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python -m src.webapp.app
```

Open `http://127.0.0.1:5000`. Runtime operation is offline after dependencies
are installed. The checked-in GeoLite2 and browser assets are used locally.
TShark is optional and is discovered from `PATH` or a standard Wireshark
installation.

The command-line pipeline remains available:

```powershell
.venv\Scripts\python -m src.main capture.pcap --output-dir results
```

Frontend CSS is precompiled and checked in. Rebuild it only after changing UI
classes:

```powershell
npm install
npm run build:css
```

## Optional AI companion

`whatsapp_ai_harness/` is a separate, optional read-only investigation UI. It
queries only analysis rows marked ready, uses allowlisted deterministic
operators for evidence access, and records append-only investigation audits.
It does not parse PCAP files or replace the primary classifier. Follow its own
[setup instructions](whatsapp_ai_harness/README.md); Ollama is optional for
deterministic Route A queries and required for model-planned Route B queries.

## Tests

```powershell
python -m pytest -q
python -m unittest discover -s tests -v
python -m compileall -q src whatsapp_ai_harness tests
```

Harness tests that require `langgraph` and `reportlab` must be run in the
companion environment created from `whatsapp_ai_harness/requirements.txt`.

## Evidence boundaries

- STUN is connectivity evidence, not proof of a completed call.
- Encrypted transport cannot provide message content or reliable message counts.
- Relay, CDN, VPN, CGNAT, private, and unresolved endpoints remain distinct.
- Geolocation describes an observed public IP allocation, not a person's
  physical location.
- Missing handshake packets are reported as incomplete evidence, not as proof
  that a protocol or algorithm was absent.

Runtime databases, job state, captures, filtered evidence, caches, and virtual
environments are intentionally excluded from version control. After committing
the reviewed source, build a tracked-files-only mentor archive with:

```powershell
.\scripts\build_submission.ps1
```
