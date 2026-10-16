import binascii
import unittest

from src.quic_decrypt import QUIC_V1_SALT, hkdf_expand_label, hkdf_extract
from src.whatsapp_filter import META_IP_RANGES, check_cidr_matching, check_port_matching


class QuicKeyDerivationTests(unittest.TestCase):
    def test_rfc_9001_client_initial_keys(self):
        dcid = binascii.unhexlify("8394c8f03e515708")
        initial = hkdf_extract(QUIC_V1_SALT, dcid)
        client = hkdf_expand_label(initial, "client in", b"", 32)

        self.assertEqual(
            initial.hex(),
            "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44",
        )
        self.assertEqual(
            client.hex(),
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
        )
        self.assertEqual(hkdf_expand_label(client, "quic key", b"", 16).hex(),
                         "1f369613dd76d5467730efcbe3b1a22d")
        self.assertEqual(hkdf_expand_label(client, "quic iv", b"", 12).hex(),
                         "fa044b2f42a3fd3b46fb255c")
        self.assertEqual(hkdf_expand_label(client, "quic hp", b"", 16).hex(),
                         "9f50449e04a0e810283a1e9933adedd2")


class FilterEvidenceTests(unittest.TestCase):
    def test_meta_ranges_and_stun_port_evidence(self):
        self.assertGreater(len(META_IP_RANGES), 0)
        self.assertEqual(check_cidr_matching("157.240.196.57"),
                         ("high", ["cidr_strong"]))
        self.assertEqual(check_cidr_matching("57.144.153.54"),
                         ("high", ["cidr_strong"]))
        self.assertEqual(check_port_matching(3478, "UDP"),
                         ("medium", ["port_stun"], "call_signaling"))


if __name__ == "__main__":
    unittest.main()
