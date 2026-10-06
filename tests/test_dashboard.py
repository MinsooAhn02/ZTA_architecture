"""Security interface regression: no cluster or subprocess is launched."""
from pathlib import Path
from http.server import ThreadingHTTPServer
import http.client
import importlib.util
import json
import sys
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('zta_dashboard', ROOT / 'visualizer/server.py')
dashboard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dashboard)


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(('127.0.0.1', 0), dashboard.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()

    def request(self, method, path, headers=None):
        client = http.client.HTTPConnection('127.0.0.1', self.httpd.server_port)
        client.request(method, path, headers=dict({'Host': 'localhost:5002'}, **(headers or {})))
        response = client.getresponse()
        status, body = response.status, response.read()
        client.close()
        return status, body

    def test_get_cannot_start_and_other_origin_cannot_post(self):
        with patch.object(dashboard.subprocess, 'Popen') as launch:
            self.assertEqual(self.request('GET', '/api/run/test-all')[0], 405)
            self.assertEqual(self.request('POST', '/api/run/test-all', {'Origin': 'http://evil.invalid', 'X-ZTA-CSRF': dashboard.CSRF})[0], 403)
            self.assertEqual(self.request('POST', '/api/run/test-all', {'Origin': 'http://localhost:5002'})[0], 403)
            self.assertEqual(self.request('GET', '/', {'Host': 'evil.invalid:5002'})[0], 403)
            launch.assert_not_called()

    def test_busy_is409_and_unknown_readonly_stream404(self):
        with patch.object(dashboard, 'acquire_lock', side_effect=dashboard.RuntimeError('busy')):
            self.assertEqual(self.request('POST', '/api/run/test-all', {'Origin': 'http://localhost:5002', 'X-ZTA-CSRF': dashboard.CSRF})[0], 409)
        self.assertEqual(self.request('GET', '/api/runs/00000000-0000-0000-0000-000000000000/events')[0], 404)

    def test_template_uses_text_log_sink_and_all34_metadata(self):
        source = dashboard.build_html()
        self.assertNotIn('s.innerHTML = text', source)
        self.assertIn('s.textContent = text', source)
        self.assertIn("method:'POST'", source)
        self.assertNotIn('ZTA_CSRF_NONCE', source)
        self.assertEqual(set(dashboard.META), {f'S{i:02d}' for i in range(1, 35)})


if __name__ == '__main__':
    unittest.main()
