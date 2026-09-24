import os
import tempfile
import unittest
from unittest.mock import patch

from src.geo_plot import generate_map_html
from src.webapp import db_analysis


class PersistenceAndMapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp.name, "analysis.db")
        self.path_patch = patch.object(db_analysis, "ANALYSIS_DB_PATH", self.db_path)
        self.path_patch.start()
        db_analysis.init_analysis_db()

    def tearDown(self):
        self.path_patch.stop()
        self.temp.cleanup()

    def test_zero_result_reanalysis_removes_stale_sessions_and_links(self):
        session = {
            "session_id": "session-v2-1", "party_ids": ["party-v2-1"],
            "start_ts": 1, "end_ts": 2, "call_type": "voice", "total_bytes": 10,
            "total_packets": 1, "schema_version": "session-statistics-v2",
            "capture_id": "upload-1", "local_subscriber_ip": "10.0.0.2",
            "observed_span_s": 1, "active_media_duration_s": 1, "transition_gap_s": 0,
            "flow_ids": ["upload-1:flow-1"], "remote_endpoints": ["8.8.8.8"],
            "confidence": "low",
        }
        db_analysis.insert_sessions("batch-1", [session])
        db_analysis.insert_sessions("batch-1", [])
        conn = db_analysis._connect()
        self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0])
        self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM session_flow_links_v2").fetchone()[0])
        self.assertEqual(2, conn.execute("SELECT version FROM derived_schema_metadata WHERE component='sessions'").fetchone()[0])
        conn.close()

    def test_private_and_cgnat_nodes_are_not_given_map_coordinates(self):
        parties = [{
            "endpoint_a_ip": "10.0.0.2", "endpoint_a_scope": "local",
            "endpoint_b_ip": "100.64.1.2", "endpoint_b_scope": "cgnat",
            "protocol": "UDP", "a_to_b_bytes": 12, "b_to_a_bytes": 34,
            "source_file": "capture.pcap",
        }]
        markup = generate_map_html(parties)
        self.assertIn("Non-geographic endpoints", markup)
        self.assertNotIn("10.0.2.15", markup)
        self.assertNotIn("-30", markup)
        self.assertIn("A→B 12 B", markup)
        self.assertIn("B→A 34 B", markup)


if __name__ == "__main__":
    unittest.main()
