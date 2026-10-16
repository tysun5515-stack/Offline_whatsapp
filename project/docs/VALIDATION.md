# Validation and limitations

The automated suite checks parser and flow invariants, session boundaries,
database replacement behavior, job-scoped filtering, crypto scope, read-only
AI access, audit immutability, compatibility routes, and offline assets.

No classifier-accuracy score is claimed by this repository. A defensible score
requires a versioned labeled-capture manifest, class counts, capture provenance,
an evaluation script, and reproducible confusion-matrix output. The optional
bitrate heuristic remains experimental and is enabled by default for backward
compatibility. Set `WA_ENABLE_EXPERIMENTAL_VOIP_HEURISTICS=false` to disable it.

Automated tests do not establish the identity of a WhatsApp user, decrypt
content, or prove caller/callee direction. Those claims require evidence that
is not generally present in encrypted network captures.
