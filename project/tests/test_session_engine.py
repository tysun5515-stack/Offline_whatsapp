import unittest

from src.flow_builder import rebuild_flows
from src.party_grouper import group_into_entities
from src.session_engine import reconstruct_flow_sessions


def packet(ts, src="10.0.0.2", dst="8.8.8.8", sport=50000, dport=3478,
           proto="UDP", flow="u1:f1", label="voice_call", stun=False,
           upload="u1", length=100, subscriber="10.0.0.2", flags=""):
    a, b = sorted((src, dst), key=lambda ip: tuple(int(x) for x in ip.split(".")))
    return {
        "timestamp": ts, "src_ip": src, "dst_ip": dst, "src_port": sport,
        "dst_port": dport, "protocol": proto, "length": length,
        "flow_id": flow, "whatsapp_media_guess": label,
        "whatsapp_confidence": "high", "sub_activity": label,
        "is_stun_binding": stun, "upload_id": upload, "capture_id": upload,
        "endpoint_a_ip": a, "endpoint_b_ip": b,
        "local_subscriber_ip": subscriber, "subscriber_resolution_source": "test",
        "subscriber_resolution_confidence": "high", "filename": f"{upload}.pcap",
        "tcp_udp_flags": flags,
    }


class FlowPartyTests(unittest.TestCase):
    def test_reverse_packets_and_well_known_ports_are_one_party(self):
        packets = [packet(1, sport=443, dport=53, proto="TCP"),
                   packet(2, src="8.8.8.8", dst="10.0.0.2", sport=53, dport=443, proto="TCP", length=150)]
        party = group_into_entities(packets, "scope")[0]
        self.assertEqual((1, 1, 150, 100), (party["a_to_b_packets"], party["b_to_a_packets"],
                                                party["a_to_b_bytes"], party["b_to_a_bytes"]))

    def test_subscribers_and_protocols_remain_separate(self):
        packets = [packet(1), packet(2, src="10.0.0.3", sport=50001, flow="u1:f2", subscriber="10.0.0.3"),
                   packet(3, proto="TCP", flow="u1:f3")]
        parties = group_into_entities(packets, "scope")
        self.assertEqual(3, len(parties))
        self.assertEqual({"TCP", "UDP"}, {p["protocol"] for p in parties})

    def test_flow_ids_are_capture_scoped_and_tuple_reuse_splits(self):
        raw = [packet(1, proto="TCP", flags="SYN"), packet(2, proto="TCP", flags="FIN"),
               packet(2.1, src="8.8.8.8", dst="10.0.0.2", sport=3478, dport=50000, proto="TCP", flags="ACK"),
               packet(5, proto="TCP", flags="SYN")]
        one = rebuild_flows(raw, "upload-one", os_hint="unknown")
        two = rebuild_flows(raw[:1], "upload-two", os_hint="unknown")
        self.assertEqual(2, len(one))
        self.assertEqual(3, one[0]["packet_count"])
        self.assertNotEqual(one[0]["flow_id"], two[0]["flow_id"])


class SessionTests(unittest.TestCase):
    @staticmethod
    def parties(packets):
        return group_into_entities(packets, "scope")

    def test_gap_boundary_and_relay_provenance(self):
        packets = [packet(0, flow="u1:f1"), packet(5, flow="u1:f1"),
                   packet(15, dst="9.9.9.9", flow="u1:f2"), packet(20, dst="9.9.9.9", flow="u1:f2")]
        sessions = reconstruct_flow_sessions(packets, self.parties(packets))
        self.assertEqual(1, len(sessions))
        self.assertEqual(10.0, sessions[0]["transition_gap_s"])
        self.assertEqual(2, len(sessions[0]["flow_ids"]))
        self.assertEqual(2, len(sessions[0]["party_ids"]))
        packets[2]["timestamp"] = 15.001
        self.assertEqual(2, len(reconstruct_flow_sessions(packets, self.parties(packets))))

    def test_unresolved_requires_stun_and_never_becomes_voice(self):
        packets = [packet(10, label="call_stream_unresolved", stun=False)]
        self.assertEqual([], reconstruct_flow_sessions(packets, self.parties(packets)))
        packets.append(packet(9, label="call_signaling", stun=True))
        sessions = reconstruct_flow_sessions(packets, self.parties(packets))
        self.assertEqual("unresolved", sessions[0]["call_type"])

    def test_unknown_subscriber_does_not_join_relay_changes(self):
        packets = [packet(1, flow="u1:f1", subscriber=None),
                   packet(2, dst="9.9.9.9", flow="u1:f2", subscriber=None)]
        self.assertEqual(2, len(reconstruct_flow_sessions(packets, self.parties(packets))))

    def test_long_session_is_not_truncated(self):
        packets = [packet(0), packet(7200)]
        session = reconstruct_flow_sessions(packets, self.parties(packets))[0]
        self.assertEqual(7200, session["observed_span_s"])
        self.assertTrue(session["duration_anomaly"])

    def test_upload_and_subscriber_boundaries(self):
        packets = [packet(1), packet(2, flow="u1:f2", subscriber="10.0.0.3"),
                   packet(3, flow="u2:f1", upload="u2")]
        self.assertEqual(3, len(reconstruct_flow_sessions(packets, self.parties(packets))))

    def test_incompatible_simultaneous_remote_streams_do_not_join(self):
        packets = [packet(0, flow="u1:f1"), packet(20, flow="u1:f1"),
                   packet(5, dst="9.9.9.9", flow="u1:f2"), packet(15, dst="9.9.9.9", flow="u1:f2")]
        self.assertEqual(2, len(reconstruct_flow_sessions(packets, self.parties(packets))))


if __name__ == "__main__":
    unittest.main()
