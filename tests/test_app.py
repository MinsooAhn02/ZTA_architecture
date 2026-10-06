import unittest
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from app import app as web


class AppTests(unittest.TestCase):
    def setUp(self):
        self.client = web.test_client()

    def test_frontend_forwards_identity_and_preserves_upstream_response(self):
        upstream = SimpleNamespace(
            content=b'{"resource":"sensor-data"}',
            status_code=403,
            headers={"Content-Type": "application/json"},
        )
        with patch("app.ROLE", "frontend"), patch("app.requests.get", return_value=upstream) as get:
            response = self.client.get(
                "/api/data",
                headers={
                    "Authorization": "Bearer access-test",
                    "X-ZTA-Posture": "posture-test",
                    "X-Request-ID": "run-21",
                },
            )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_data(), upstream.content)
        self.assertEqual(response.mimetype, "application/json")
        self.assertEqual(response.headers["X-Request-ID"], "run-21")
        self.assertEqual(get.call_args.kwargs["headers"], {
            "Authorization": "Bearer access-test",
            "X-ZTA-Posture": "posture-test",
            "X-Request-ID": "run-21",
        })
        self.assertFalse(get.call_args.kwargs["allow_redirects"])

    def test_upstream_failures_are_not_reported_as_success(self):
        with patch("app.ROLE", "frontend"), patch("app.requests.get", side_effect=__import__("requests").Timeout):
            response = self.client.get("/api/data", headers={"X-Request-ID": "invalid id"})
            self.assertEqual(response.status_code, 504)
            self.assertEqual(response.json["request_id"], response.headers["X-Request-ID"])
        with patch("app.ROLE", "frontend"), patch("app.requests.get", side_effect=__import__("requests").ConnectionError):
            self.assertEqual(self.client.get("/api/data").status_code, 502)

    def test_write_is_json_bounded_and_simulation_only(self):
        with patch("app.ROLE", "backend"):
            response = self.client.post("/api/write", json={"change": "demo"})
            self.assertEqual(response.status_code, 200)
            self.assertFalse(response.json["committed"])
            self.assertEqual(self.client.post("/api/write", data="x").status_code, 415)
            self.assertEqual(self.client.post("/api/write", json="scalar").status_code, 400)
            self.assertEqual(self.client.post("/api/write", data=b"x" * (64 * 1024 + 1), content_type="application/json").status_code, 413)

    def test_health_is_unauthed_safe_json(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "ok")
        self.assertTrue(response.headers["X-Request-ID"])


if __name__ == "__main__":
    unittest.main()
