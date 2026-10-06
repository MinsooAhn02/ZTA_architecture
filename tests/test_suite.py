import base64
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
stub_identity = types.SimpleNamespace(issue_tokens=lambda *args, **kwargs: {
    "access": "e30.eyJzdWIiOiJ1In0.sig", "posture": "e30.eyJzdWIiOiJ1In0.sig",
    "refresh_access": "unused", "refresh_posture": "unused"},
    test_tokens=lambda *args, **kwargs: {"access": "e30.eyJzdWIiOiJ1In0.sig",
                                        "posture": "e30.eyJzdWIiOiJ1In0.sig"},
    CLIENTS={"zta-app": {"secret": "test"}})
sys.modules.setdefault("identity", stub_identity)
import suite
import performance


class FakeRuntime:
    def __init__(self, result):
        self.namespace = "zta-v2"
        self.result = result
        self.args = None
        self.input = None

    def kubectl_process(self, *args, input=None, **kwargs):
        self.request_id = input.splitlines()[2]
        self.args, self.input = args, input
        return self.result


class SuiteRuntime:
    def __init__(self):
        self.mode = "strict"

    def apply_mode(self, mode):
        self.mode = mode

    def opa_query(self, query):
        return getattr(self, "mode", "strict")

    def wait_ready(self):
        pass

    def kubectl_process(self, *args, input=None, **kwargs):
        self.request_id = input.splitlines()[2]
        client = next((arg.split("/", 1)[1] for arg in args if arg.startswith("deploy/")), "")
        if client == "rogue-client":
            code, curl_exit, body = "000", 35, ""
        elif "Authorization" not in input:
            code, curl_exit, body = "403", 0, ""
        else:
            code, curl_exit, body = "200", 0, "sensor-data admin-config write-accepted"
        encoded = base64.b64encode(body.encode()).decode()
        return subprocess.CompletedProcess([], 0, f"__ZTA_RESULT__\t{code}\t{curl_exit}\t{encoded}\n", "")

    def kubectl(self, *args, **kwargs):
        if args[0] == 'logs':
            return __import__('json').dumps({'request_id': getattr(self, 'request_id', ''), 'response_code_details': 'ext_authz_denied'})
        return "10.0.0.2" if args[0] == "get" else "TLS_handshake_failure 10.0.0.2"


class PerfRuntime(SuiteRuntime):
    def kubectl_process(self, *args, input=None, **kwargs):
        if "deploy/fortio-client" in args:
            import json
            payload = json.loads(input)
            body = json.dumps({'DurationHistogram': {'Count':100,'Avg':0.001,'Percentiles':[{'Percentile':p,'Value':0.002} for p in (50,95,99)]},
                              'RetCodes':{'200':100},'ActualQPS':8,'RequestedQPS':'8','RequestedDuration':payload['t'], 'NumThreads':int(payload['c']),
                              'ActualDuration':int(payload['t'].rstrip('s')) * 1000000000})
            return subprocess.CompletedProcess([], 0, body, '')
        if '/fortio/rest/run' in input:
            import json
            payload = json.loads(base64.b64decode(input.splitlines()[-1]))
            body = json.dumps({'DurationHistogram': {'Count':100,'Avg':0.001,'Percentiles':[{'Percentile':p,'Value':0.002} for p in (50,95,99)]},
                              'RetCodes':{'200':100},'ActualQPS':8,'RequestedQPS':'8','RequestedDuration':payload['t'], 'NumThreads':int(payload['c']),
                              'ActualDuration':int(payload['t'].rstrip('s')) * 1000000000}).encode()
        else:
            body = b'sensor-data'
        encoded = base64.b64encode(body).decode()
        return subprocess.CompletedProcess([], 0, f"__ZTA_RESULT__\t200\t0\t{encoded}\n", "")

    def kubectl(self, *args, **kwargs):
        if "cat" in args:
            return '{"DurationHistogram":{"Count":100,"Avg":0.001,"Percentiles":[{"Percentile":50,"Value":0.001},{"Percentile":99,"Value":0.002}]},"RetCodes":{"200":100},"ActualQPS":10}'
        return ""


class SuiteTests(unittest.TestCase):
    def test_remote_request_keeps_secret_in_stdin_and_parses_body(self):
        body = base64.b64encode(b"sensor-data").decode()
        runtime = FakeRuntime(subprocess.CompletedProcess([], 0,
            f"__ZTA_RESULT__\t200\t0\t{body}\n", ""))
        result = suite.request(runtime, "http://frontend", "/api/data",
                               headers={"Authorization": "Bearer secret-value"})
        self.assertEqual(result["kind"], "http")
        self.assertEqual(result["body"], "sensor-data")
        self.assertNotIn("secret-value", " ".join(runtime.args))
        self.assertIn(base64.b64encode(b"Authorization: Bearer secret-value").decode(), runtime.input)
        self.assertTrue(runtime.input.splitlines()[2])
        self.assertIn('"X-Request-ID: $rid"', suite.REMOTE)

    def test_transport_000_is_not_http_and_timeout_stays_distinct(self):
        for curl_exit, kind in ((35, "transport_denied"), (28, "timeout")):
            runtime = FakeRuntime(subprocess.CompletedProcess([], 0,
                f"__ZTA_RESULT__\t000\t{curl_exit}\t\n", ""))
            self.assertEqual(suite.request(runtime, "http://backend", "/")["kind"], kind)

    def test_kubectl_failure_is_error_even_when_output_looks_like_a_deny(self):
        runtime = FakeRuntime(subprocess.CompletedProcess([], 1,
            "__ZTA_RESULT__\t403\t0\t\n", "exec failed"))
        self.assertEqual(suite.request(runtime, "http://frontend", "/")["kind"], "error")

    def test_record_schema_drops_response_body(self):
        row = suite._row("r", "S01", "strict", {"http_code": 403},
                         {"kind": "http", "http_code": 403, "body": "private",
                          "request_id": "id"}, True)
        self.assertEqual(row["status"], "PASS")
        self.assertEqual(row["request_id"], "id")
        self.assertNotIn("body", row["observed"])

    def test_unavailable_fixture_is_error_not_pass(self):
        row = suite._unsupported("r", "S09", "strict", "no key fixture")
        self.assertEqual(row["status"], "ERROR")
        self.assertEqual(row["observed"]["kind"], "error")

    def test_suite_emits_one_row_per_scenario_id(self):
        with patch("suite.urlopen") as logout:
            logout.return_value.__enter__.return_value.status = 204
            rows = suite.run_suite(SuiteRuntime(), ROOT / "runs" / "test-run")
        ids = {row["case_id"] for row in rows}
        self.assertEqual(len(rows), 33)
        self.assertEqual(ids, {f"S{i:02d}" for i in range(1, 35)} - {"S32"})
        self.assertEqual(next(row for row in rows if row["case_id"] == "S16")["status"], "ERROR")

    def test_run_case_executes_only_selected_scenario(self):
        row = suite.run_case(SuiteRuntime(), "S01", ROOT / "runs" / "one-case")
        self.assertEqual(row["case_id"], "S01")
        self.assertEqual(row["status"], "PASS")

    def test_perf_matrix_and_percentile_labels_keep_all_cells_distinct(self):
        self.assertEqual(len(performance.LAYERS) * len(performance.CONCURRENCY) * performance.REPEATS, 30)
        values = performance._percentiles({"Percentiles": [
            {"Percentile": 99, "Value": 0.001},
            {"Percentile": 99.9, "Value": 0.002},
        ]})
        self.assertEqual(values, {"p99": 1.0, "p99_9": 2.0})
        scrubbed = performance._safe_report({"headers": {"Authorization": "Bearer secret"},
                                             "note": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.signature"})
        self.assertNotIn("headers", scrubbed)
        self.assertNotIn("signature", scrubbed["note"])

    def test_perf_runner_aggregates_30_local_samples_and_restores_strict(self):
        with tempfile.TemporaryDirectory() as tempdir:
            rows = performance.run_performance(PerfRuntime(), Path(tempdir) / "run")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["case_id"], "S32")
        self.assertEqual(rows[0]["status"], "PASS")
        self.assertEqual(len(rows[0]["observed"]["cells"]), 30)
        self.assertIsNone(rows[0]["observed"]["restore_error"])
        sample = rows[0]['observed']['cells'][0]['observed']
        self.assertIsNone(sample['body_ok'])
        self.assertTrue(sample['preflight_body_ok'])
        self.assertFalse(sample['measured_response_body_asserted'])

    def test_perf_transport_error_keeps_actual_codes_and_sanitized_artifact(self):
        canary = {'kind':'http','http_code':200,'curl_exit':0,'kubectl_exit':0,'body':'sensor-data','request_id':'canary'}
        timeout = {'kind':'timeout','http_code':0,'curl_exit':28,'kubectl_exit':0,
                   'body':'credential fragment must not be saved','request_id':'control'}
        with tempfile.TemporaryDirectory() as tempdir, patch('performance.request', return_value=canary), \
                patch('performance._fortio', return_value=timeout), patch('performance._envoy_line', return_value={}):
            path = Path(tempdir) / 'cell.json'
            row = performance._measure(PerfRuntime(), 'run', 'cell', 'strict', 1, '30s', {}, 'measurement', path, '')
            self.assertEqual(row['status'], 'ERROR')
            self.assertEqual(row['observed']['curl_exit'], 28)
            self.assertEqual(row['observed']['kubectl_exit'], 0)
            self.assertEqual(row['observed']['control_request_id'], 'control')
            self.assertNotIn('credential fragment', path.with_suffix('.error.json').read_text())

    def test_perf_rejects_truncated_jwt_in_fortio_logs(self):
        runtime = PerfRuntime()
        with patch('performance.request', return_value={'kind':'http','http_code':200,'body':'{}'}), \
                patch.object(runtime, 'kubectl', return_value='REST body: eyJhbGciOiJSUzI1NiJ9...'):
            with self.assertRaisesRegex(RuntimeError, 'credential masking failed'):
                performance._fortio(runtime, 1, '30s', {}, 'run', '')

    def test_perf_loopback_control_keeps_credentials_on_stdin(self):
        runtime = PerfRuntime()
        original = runtime.kubectl_process
        calls = []
        def capture(*args, input=None, **kwargs):
            calls.append((args, input))
            return original(*args, input=input, **kwargs)
        runtime.kubectl_process = capture
        result = performance._fortio(runtime, 4, '30s', {'Authorization':'Bearer private-test-marker'}, 'run', '')
        args, payload = calls[0]
        self.assertNotIn('private-test-marker', ' '.join(args))
        self.assertIn('private-test-marker', payload)
        self.assertIn('-stdclient', args)
        self.assertEqual(args[-1], 'http://localhost:8080/fortio/rest/run')
        self.assertEqual(result['kind'], 'report')
        self.assertIsNone(result['http_code'])

    def test_verify_rejects_path_traversal_and_mismatched_manifest_action(self):
        import json
        import zta as cli
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            runtime = types.SimpleNamespace(state=root, source_fingerprint=lambda:'fixed')
            (root/'last-check.json').write_text(json.dumps({'status':'PASS','source_sha256':'fixed'}))
            for identifier, message in [('../outside', 'Invalid evidence run ID'),
                                       ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'manifest identity')]:
                with self.subTest(identifier=identifier), patch.object(cli, 'EVIDENCE', root):
                    (root/'latest-test.json').write_text(json.dumps({'run_id':identifier}))
                    if '/' not in identifier:
                        directory = root/identifier
                        directory.mkdir()
                        (directory/'manifest.json').write_text(json.dumps({'schema_version':1,'run_id':identifier,'action':'perf'}))
                    with self.assertRaisesRegex(cli.RuntimeError, message):
                        cli.verify(runtime)


if __name__ == "__main__":
    unittest.main()
