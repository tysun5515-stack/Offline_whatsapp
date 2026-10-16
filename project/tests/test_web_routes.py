import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.webapp import app as app_module
from src.webapp import db_analysis, db_registry


class WebRouteSmokeTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.registry_patch = patch.object(db_registry, "REGISTRY_DB_PATH", str(root / "registry.db"))
        self.analysis_patch = patch.object(db_analysis, "ANALYSIS_DB_PATH", str(root / "analysis.db"))
        self.flatten_patch = patch.object(app_module, "flatten_evidence_storage_once")
        self.registry_patch.start()
        self.analysis_patch.start()
        self.flatten_patch.start()
        self.app = app_module.create_app()
        self.app.config.update(TESTING=True)
        self.client = self.app.test_client()

    def tearDown(self):
        self.flatten_patch.stop()
        self.analysis_patch.stop()
        self.registry_patch.stop()
        self.temp_dir.cleanup()

    def test_canonical_pages_render(self):
        for path in ("/dashboard", "/uploads", "/filtering", "/analysis", "/reports",
                     "/interface/evidence-storage", "/interface/classification",
                     "/interface/flow-inspection"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)

    def test_legacy_routes_redirect(self):
        expected = {
            "/interface/1": "/uploads",
            "/interface/2": "/filtering",
            "/interface/3": "/analysis",
            "/interface/5": "/reports",
            "/interface/report-generation": "/reports",
        }
        for old_path, new_path in expected.items():
            with self.subTest(path=old_path):
                response = self.client.get(old_path)
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response.headers["Location"].endswith(new_path))

    def test_evidence_api_lifecycle(self):
        root = Path(self.temp_dir.name)
        raw_path = root / "capture.pcap"
        filtered_path = root / "capture_WF.pcap"
        raw_path.write_bytes(b"test source evidence")
        filtered_path.write_bytes(b"test filtered evidence")
        upload_id, batch_id = "upload-smoke", "batch-smoke"
        db_registry.register_upload(
            "capture.pcap",
            str(raw_path),
            upload_id=upload_id,
            batch_id=batch_id,
            capture_metadata={
                "capture_start_ts": 1_700_000_000.0,
                "capture_end_ts": 1_700_000_001.0,
                "capture_packet_count": 1,
            },
        )
        db_registry.update_filtered_evidence(
            upload_id,
            str(filtered_path),
            file_format="pcap",
            packet_count=1,
            status="filtered_output_created",
        )
        db_analysis.insert_whatsapp_packets(batch_id, upload_id, "capture.pcap", [{
            "packet_no": 1,
            "timestamp": 1_700_000_000.5,
            "src_ip": "10.0.0.2",
            "dst_ip": "31.13.70.1",
            "src_port": 50000,
            "dst_port": 443,
            "protocol": "TCP",
            "length": 120,
            "flow_id": "flow-smoke",
            "flow_instance": 1,
            "capture_id": upload_id,
            "endpoint_a_ip": "10.0.0.2",
            "endpoint_a_port": 50000,
            "endpoint_b_ip": "31.13.70.1",
            "endpoint_b_port": 443,
            "local_subscriber_ip": "10.0.0.2",
            "subscriber_resolution_source": "test fixture",
            "subscriber_resolution_confidence": "high",
            "session_start_confirmed": False,
            "whatsapp_confidence": "high",
            "whatsapp_media_guess": "message",
        }])

        uploads = self.client.get("/api/uploads")
        self.assertEqual(uploads.status_code, 200)
        self.assertEqual(uploads.get_json()[0]["upload_id"], upload_id)

        analysis = self.client.post("/api/analyze")
        self.assertEqual(analysis.status_code, 200)
        self.assertEqual(analysis.get_json()["packet_count"], 1)

        report = self.client.post(
            "/api/reports/generate",
            data={"config": json.dumps({
                "upload_ids": [upload_id],
                "phases": ["filtration", "classification"],
            })},
        )
        self.assertEqual(report.status_code, 200)
        self.assertIn(b"capture.pcap", report.data)

        export = self.client.get(f"/api/export/{batch_id}")
        self.assertEqual(export.status_code, 200)
        self.assertEqual(json.loads(export.data), [])
        export.close()

        deleted = self.client.post(f"/api/delete/upload/{upload_id}")
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(deleted.get_json(), {"status": "deleted"})
        self.assertFalse(raw_path.exists())
        self.assertFalse(filtered_path.exists())
        self.assertEqual(self.client.get("/api/uploads").get_json(), [])


if __name__ == "__main__":
    unittest.main()
