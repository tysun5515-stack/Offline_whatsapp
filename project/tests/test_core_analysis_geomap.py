import os
import tempfile
import unittest
from unittest.mock import patch

from src.webapp import db_analysis
from src.geo_plot import generate_map_html, _activity_group, _arc_color
from src.geo_enrichment import enrich_parties
from src.webapp.app import get_party_activity_group


class CoreAnalysisGeoMapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp.name, "test_analysis.db")
        self.path_patch = patch.object(db_analysis, "ANALYSIS_DB_PATH", self.db_path)
        self.path_patch.start()
        db_analysis.init_analysis_db()

    def tearDown(self):
        self.path_patch.stop()
        self.temp.cleanup()

    def test_geo_cache_schema_and_upsert_subdivision(self):
        # Verify columns exist and upsert_geo saves subdivision and region_code
        db_analysis.upsert_geo("157.240.13.51", {
            "country": "India",
            "city": "Mumbai",
            "subdivision": "Maharashtra",
            "region_code": "MH",
            "postal_code": "400001",
            "latitude": 19.076,
            "longitude": 72.877,
            "asn": "AS32934",
            "asn_org": "Facebook, Inc.",
            "rdns_hostname": "whatsapp-chat.meta.com",
            "looked_up_at": 1000.0
        })

        geo = db_analysis.get_geo("157.240.13.51")
        self.assertIsNotNone(geo)
        self.assertEqual(geo["city"], "Mumbai")
        self.assertEqual(geo["subdivision"], "Maharashtra")
        self.assertEqual(geo["region_code"], "MH")
        self.assertEqual(geo["postal_code"], "400001")

    def test_enrich_parties_creates_display_location(self):
        parties = [{
            "party_id": "p1",
            "remote_ip": "157.240.13.51",
            "endpoint_a_ip": "10.0.0.1",
            "endpoint_a_scope": "local",
            "endpoint_b_ip": "157.240.13.51",
            "endpoint_b_scope": "public",
            "protocol": "TCP",
            "party_type": "client_to_server",
            "sub_activity": "message",
        }]

        def dummy_get_geo(ip):
            if ip == "157.240.13.51":
                return {
                    "country": "India",
                    "city": "Lucknow",
                    "subdivision": "Uttar Pradesh",
                    "region_code": "UP",
                    "latitude": 26.8467,
                    "longitude": 80.9462,
                    "asn": "AS32934",
                    "asn_org": "Meta",
                    "rdns_hostname": None,
                }
            return None

        enriched = enrich_parties(parties, dummy_get_geo, lambda ip, d: None)
        self.assertEqual(enriched[0]["geo_city"], "Lucknow")
        self.assertEqual(enriched[0]["geo_subdivision"], "Uttar Pradesh")
        self.assertIn("Lucknow", enriched[0]["display_location"])
        self.assertIn("Uttar Pradesh", enriched[0]["display_location"])
        self.assertIn("India", enriched[0]["display_location"])

    def test_get_parties_scope_filtering_and_pagination(self):
        parties = [
            {
                "party_id": "p_call",
                "remote_ip": "1.2.3.4",
                "protocol": "UDP",
                "packet_count": 500,
                "total_bytes": 50000,
                "first_seen": 100.0,
                "last_seen": 200.0,
                "party_type": "peer_to_peer",
                "sub_activity": "voice_call",
                "is_p2p": 1,
                "os_hint": "Android",
                "upload_id": "upload_1",
            },
            {
                "party_id": "p_chat",
                "remote_ip": "5.6.7.8",
                "protocol": "TCP",
                "packet_count": 100,
                "total_bytes": 10000,
                "first_seen": 110.0,
                "last_seen": 190.0,
                "party_type": "client_to_server",
                "sub_activity": "message",
                "is_p2p": 0,
                "os_hint": "Android",
                "upload_id": "upload_1",
            },
            {
                "party_id": "p_infra",
                "remote_ip": "9.10.11.12",
                "protocol": "UDP",
                "packet_count": 20,
                "total_bytes": 2000,
                "first_seen": 105.0,
                "last_seen": 195.0,
                "party_type": "client_to_server",
                "sub_activity": "dns",
                "is_p2p": 0,
                "os_hint": "Android",
                "upload_id": "upload_1",
            },
        ]
        db_analysis.insert_parties("batch_1", parties, upload_id="upload_1")

        calls = db_analysis.get_parties_scope(["upload_1"], activity_group="call")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["party_id"], "p_call")

        chats = db_analysis.get_parties_scope(["upload_1"], activity_group="chat")
        self.assertEqual(len(chats), 1)
        self.assertEqual(chats[0]["party_id"], "p_chat")

        infras = db_analysis.get_parties_scope(["upload_1"], activity_group="infra")
        self.assertEqual(len(infras), 1)
        self.assertEqual(infras[0]["party_id"], "p_infra")

        # Test limit and offset
        all_parties = db_analysis.get_parties_scope(["upload_1"], limit=2, offset=0)
        self.assertEqual(len(all_parties), 2)
        offset_parties = db_analysis.get_parties_scope(["upload_1"], limit=2, offset=2)
        self.assertEqual(len(offset_parties), 1)

    def test_geo_plot_activity_markup_and_colors(self):
        party_call = {
            "endpoint_a_ip": "1.2.3.4", "endpoint_a_scope": "public",
            "endpoint_a_lat": 19.07, "endpoint_a_lon": 72.87,
            "endpoint_b_ip": "5.6.7.8", "endpoint_b_scope": "public",
            "endpoint_b_lat": 1.35, "endpoint_b_lon": 103.82,
            "protocol": "UDP", "a_to_b_bytes": 100, "b_to_a_bytes": 200,
            "source_file": "call.pcap",
            "sub_activity": "voice_call",
            "is_p2p": 1
        }
        party_relay = {
            "endpoint_a_ip": "1.2.3.4", "endpoint_a_scope": "public",
            "endpoint_a_lat": 19.07, "endpoint_a_lon": 72.87,
            "endpoint_b_ip": "9.9.9.9", "endpoint_b_scope": "public",
            "endpoint_b_lat": 51.5, "endpoint_b_lon": -0.12,
            "protocol": "UDP", "a_to_b_bytes": 50, "b_to_a_bytes": 60,
            "source_file": "call.pcap",
            "sub_activity": "voice_call",
            "caveat_type": "relay_server"
        }

        self.assertEqual(_activity_group(party_call), "call")
        self.assertEqual(_activity_group(party_relay), "call")
        self.assertEqual(_arc_color(party_call, "call"), "#059669")
        self.assertEqual(_arc_color(party_relay, "call"), "#dc2626")

        html_markup = generate_map_html([party_call, party_relay])
        self.assertIn('data-activity-group="call"', html_markup)
        self.assertIn('data-is-relay="1"', html_markup)
        self.assertIn('stroke="#059669"', html_markup)
        self.assertIn('stroke="#dc2626"', html_markup)
        self.assertIn("Calls (P2P Direct)", html_markup)
        self.assertIn("Calls (Relay Server)", html_markup)

    def test_get_party_activity_group_helper(self):
        self.assertEqual(get_party_activity_group({"sub_activity": "voice_call"}), "call")
        self.assertEqual(get_party_activity_group({"is_p2p": 1}), "call")
        self.assertEqual(get_party_activity_group({"caveat_type": "relay_server"}), "call")
        self.assertEqual(get_party_activity_group({"call_duration_s": 45}), "call")
        self.assertEqual(get_party_activity_group({"sub_activity": "message"}), "chat")
        self.assertEqual(get_party_activity_group({"sub_activity": "photo"}), "chat")
        self.assertEqual(get_party_activity_group({"sub_activity": "dns"}), "infra")


if __name__ == "__main__":
    unittest.main()
