import unittest
from unittest.mock import patch

import src.webapp.app as app_module


class JobScopedClassificationTests(unittest.TestCase):
    def setUp(self):
        self.upload = {
            'upload_id': 'upload-1',
            'filename': 'capture.pcap',
            'stored_path': 'raw/capture.pcap',
            'filtered_path': 'filtered/capture_WF.pcap',
            'filtered_status': 'filtered_output_created',
            'filtered_size_bytes': 1,
            'filtered_format': 'pcap',
            'file_format': 'pcap',
            'capture_start_ts': 10.0,
            'capture_end_ts': 20.0,
        }

    def _client(self):
        patches = [
            patch.object(app_module, 'init_registry_db'),
            patch.object(app_module, 'init_analysis_db'),
            patch.object(app_module, 'flatten_evidence_storage_once'),
            patch.object(app_module, 'list_uploads', return_value=[]),
            patch.object(app_module, 'get_file_list', return_value=[]),
            patch.object(app_module, 'get_upload', return_value=self.upload),
            patch.object(app_module, 'render_template', return_value='ok'),
            patch.object(app_module.os.path, 'isfile', return_value=True),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        app = app_module.create_app()
        app.config.update(TESTING=True)
        return app.test_client()

    @patch('src.webapp.job_queue.get_job_status', return_value={
        'job_id': 'job-1', 'upload_ids': ['upload-1'], 'status': 'completed'
    })
    def test_classification_resolves_job_uploads(self, get_job_status):
        response = self._client().get('/interface/classification?job_id=job-1')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), 'ok')
        get_job_status.assert_called_once_with('job-1')

    def test_legacy_upload_id_scope_still_works(self):
        response = self._client().get('/interface/classification?upload_ids=upload-1')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_data(as_text=True), 'ok')


if __name__ == '__main__':
    unittest.main()
