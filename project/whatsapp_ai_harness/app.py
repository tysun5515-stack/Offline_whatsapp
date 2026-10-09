from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Optional

from flask import Flask, Response, jsonify, render_template, request, send_file, stream_with_context

from .config import Settings
from .live_source import LiveDatabaseError
from .graph import HarnessEngine


def create_app(settings: Optional[Settings] = None) -> Flask:
    settings = settings or Settings.from_env()
    app = Flask(__name__, template_folder="templates", static_folder="static")
    engine = HarnessEngine(settings)
    app.config["HARNESS_ENGINE"] = engine
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/v1/database")
    def database():
        try:
            return jsonify(engine.source.inspect(quick_check=True).public_dict())
        except LiveDatabaseError as exc:
            return jsonify({"error": str(exc)}), 503

    def parse_query_payload() -> Dict[str, Any]:
        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            raise ValueError("JSON request body must be an object")
        if not isinstance(payload.get("question"), str):
            raise ValueError("question is required")
        scope = payload.get("scope") or {}
        if not isinstance(scope, dict):
            raise ValueError("scope must be an object")
        return {"question": payload["question"], "scope_data": scope}

    @app.post("/api/v1/query")
    def query():
        try:
            payload = parse_query_payload()
            result = engine.query(**payload)
            return jsonify(result), 200 if result["status"] != "error" else 500
        except (ValueError, LiveDatabaseError) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/v1/query/stream")
    def query_stream():
        try:
            payload = parse_query_payload()
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        @stream_with_context
        def events():
            yield "event: status\ndata: " + json.dumps({"message": "Routing and verifying query"}) + "\n\n"
            try:
                result = engine.query(**payload)
                yield "event: result\ndata: " + json.dumps(result, default=str) + "\n\n"
            except (ValueError, LiveDatabaseError) as exc:
                yield "event: error\ndata: " + json.dumps({"error": str(exc)}) + "\n\n"

        return Response(events(), mimetype="text/event-stream")

    @app.get("/api/v1/investigations")
    def investigations():
        return jsonify({"investigations": engine.audit.list(min(request.args.get("limit", 50, type=int), 100))})

    @app.get("/api/v1/investigations/<trace_id>")
    def investigation(trace_id: str):
        record = engine.audit.get(trace_id)
        return (jsonify(record), 200) if record else (jsonify({"error": "Investigation not found"}), 404)

    def find_citation(citation_id: str):
        record = engine.audit.find_citation(citation_id)
        package = record.get("answer_package") if record else None
        for ref in (package or {}).get("citations", []):
            if ref.get("citation_id") == citation_id:
                return record, ref
        return None, None

    @app.get("/api/v1/evidence/<citation_id>")
    def evidence(citation_id: str):
        record, ref = find_citation(citation_id)
        if not ref:
            return jsonify({"error": "Evidence citation not found in the local audit history"}), 404
        package = record.get("answer_package") if record else None
        snapshot = (package or {}).get("evidence_snapshots", {}).get(citation_id)
        return jsonify({"reference": ref, "record": snapshot,
                        "note": "This is the immutable evidence snapshot stored with the investigation."})

    @app.get("/api/v1/investigations/<trace_id>/export")
    def export_investigation(trace_id: str):
        record = engine.audit.get(trace_id)
        if not record:
            return jsonify({"error": "Investigation not found"}), 404
        output_format = request.args.get("format", "json").lower()
        if output_format == "json":
            data = json.dumps(record, indent=2, sort_keys=True, default=str).encode()
            return send_file(io.BytesIO(data), mimetype="application/json", as_attachment=True,
                             download_name=f"investigation-{trace_id}.json")
        if output_format == "csv":
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(["trace_id", "database_instance_id", "analysis_revision", "route", "question", "answer", "status"])
            writer.writerow([record["trace_id"], record.get("database_instance_id"), record.get("analysis_revision"), record["route"], record["question"],
                             record["displayed_answer"], record["status"]])
            return send_file(io.BytesIO(buffer.getvalue().encode("utf-8-sig")), mimetype="text/csv",
                             as_attachment=True, download_name=f"investigation-{trace_id}.csv")
        if output_format == "pdf":
            try:
                from reportlab.lib.pagesizes import A4
                from reportlab.pdfgen import canvas
            except ImportError:
                return jsonify({"error": "PDF support requires the pinned reportlab dependency"}), 503
            output = io.BytesIO(); pdf = canvas.Canvas(output, pagesize=A4)
            width, height = A4; y = height - 50
            lines = [f"Investigation {trace_id}", f"Database: {record.get('database_instance_id')}",
                     f"Revision: {record.get('analysis_revision')}",
                     f"Route: {record['route']}", "", "Question: " + record["question"],
                     "", "Answer: " + record["displayed_answer"]]
            for raw in lines:
                words, line = raw.split(), ""
                for word in words or [""]:
                    if pdf.stringWidth(line + " " + word) > width - 90:
                        pdf.drawString(45, y, line); y -= 16; line = word
                    else:
                        line = (line + " " + word).strip()
                pdf.drawString(45, y, line); y -= 18
                if y < 50:
                    pdf.showPage(); y = height - 50
            pdf.save(); output.seek(0)
            return send_file(output, mimetype="application/pdf", as_attachment=True,
                             download_name=f"investigation-{trace_id}.pdf")
        return jsonify({"error": "format must be json, csv, or pdf"}), 400

    @app.get("/api/v1/health")
    def health():
        try:
            database = engine.source.inspect(quick_check=True)
            return jsonify({"status": "ok", "ollama": engine.ollama.status(),
                            "database": database.public_dict()})
        except LiveDatabaseError as exc:
            return jsonify({"status": "degraded", "ollama": engine.ollama.status(),
                            "database_error": str(exc)}), 503

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5055, debug=False, threaded=True)

