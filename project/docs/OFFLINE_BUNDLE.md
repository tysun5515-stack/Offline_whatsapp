# Pure offline Windows bundle

The offline archive targets Windows x64 and Python 3.12. It contains the
application, local browser assets, GeoLite2 databases, fully pinned dependency
locks, and a wheelhouse containing every Python runtime dependency.

## Build on an internet-connected computer

Commit the reviewed source, then run from the `project` directory:

```powershell
.\scripts\build_submission.ps1 -Output whatsapp-offline-win64.zip
```

The build downloads binary wheels for both isolated environments, verifies
the wheelhouse without an index, writes `OFFLINE_BUNDLE_MANIFEST.sha256`, and
creates the archive. Building requires internet access; using the completed
archive does not.

The checked-out bundle also includes a current root manifest. Verify a copied
bundle by hashing each listed relative path and comparing it with
`OFFLINE_BUNDLE_MANIFEST.sha256`.

## Install on the offline computer

Extract the archive and run `INSTALL.bat` at its root. The bundle contains the
Python 3.12 x64 and Wireshark/TShark installers, so the target computer does
not need internet access or a preinstalled Python runtime.

For scripted installation after Python is available, run:

```powershell
PowerShell -ExecutionPolicy Bypass -File .\install_offline.ps1
```

The installer creates `.venv` for the primary analyzer and
`whatsapp_ai_harness\.venv` for the separate read-only companion. It uses
`--no-index`, verifies package hashes, runs `pip check`, verifies imports, and
performs a primary application startup import check.

Start the applications with `run_offline.cmd` and, optionally,
`whatsapp_ai_harness\start_harness.cmd`.

## Included and optional components

- Python packages and all transitive runtime dependencies are included as wheels.
- GeoLite2, fonts, CSS, icons, and Chart.js are local.
- Node.js and npm are not runtime dependencies because compiled assets are included.
- Wireshark/TShark is bundled and installed when missing. Baseline filtering
  still works if an administrator chooses not to install it, but crypto
  extraction requires local TShark.
- Ollama and model weights are optional and are not redistributed. Deterministic
  companion Route A works without Ollama; model-planned Route B does not.
- Python 3.12 x64 is included as an offline installer.

Do not run `pip install -r requirements.txt` on a disconnected computer. Use
`INSTALL.bat`, which delegates to `install_offline.ps1` with the hashed lock
files and the top-level `wheels` directory.
