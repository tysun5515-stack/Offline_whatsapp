"""Production local server for the forensic query harness."""
from __future__ import annotations

import os

from waitress import serve

from .app import create_app


def main() -> None:
    host = os.environ.get("WA_HARNESS_HOST", "127.0.0.1")
    port = int(os.environ.get("WA_HARNESS_PORT", "5055"))
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("The forensic harness may only bind to a local loopback address")
    if not 1 <= port <= 65535:
        raise RuntimeError("WA_HARNESS_PORT must be between 1 and 65535")
    serve(
        create_app(), host=host, port=port, threads=4,
        channel_timeout=330, cleanup_interval=30,
        clear_untrusted_proxy_headers=True,
        ident="WA-Forensic-Harness",
    )


if __name__ == "__main__":
    main()
