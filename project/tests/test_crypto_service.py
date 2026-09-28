import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from src.webapp import crypto_service as service


class CryptoScopeTests(unittest.TestCase):
    def test_null_batch_pending_flow_is_visible(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(service.db, 'ANALYSIS_DB_PATH', os.path.join(root, 'test.db')):
                with service.connect() as c:
                    c.execute('CREATE TABLE analysis_flows_v2 (flow_id TEXT, upload_id TEXT, endpoint_a_ip TEXT, endpoint_a_port INTEGER, endpoint_b_ip TEXT, endpoint_b_port INTEGER, protocol TEXT, first_seen REAL, last_seen REAL, a_to_b_packets INTEGER, b_to_a_packets INTEGER, media_type TEXT)')
                    c.execute("INSERT INTO analysis_flows_v2 VALUES ('flow','upload','10.0.0.1',123,'1.1.1.1',443,'TCP',1,2,3,4,'message')")
                flows, summary, reports = service.scoped([{'upload_id':'upload','sha256_hash':'hash','batch_id':None}], None, None)
                self.assertEqual(summary['total_flows'], 1)
                self.assertEqual(flows[0]['analysis_status'], 'pending')
                self.assertEqual(flows[0]['total_packets'], 7)
                self.assertEqual(summary['analyzed_flows'], 0)

    def test_disabled(self):
        with patch.dict(os.environ, {'WA_CRYPTO_ANALYSIS_ENABLED':'false'}):
            self.assertEqual(service.analyze('nonexistent'), {'status':'disabled'})


if __name__ == '__main__':
    unittest.main()
