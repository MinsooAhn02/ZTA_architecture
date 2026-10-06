"""Local dashboard: safe display, shared run lock, POST start and read-only SSE."""
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import uuid
from urllib.parse import urlparse

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE / 'scripts'))
from runtime import Runtime, RuntimeError, redact
from zta import EVIDENCE, acquire_lock

PORT = 5002
CSRF = secrets.token_urlsafe(32)
HOSTS = {'localhost:5002', '127.0.0.1:5002'}
ORIGINS = {'http://' + host for host in HOSTS}
JOBS = {}
META = json.loads((BASE / 'visualizer/scenarios.json').read_text())


def build_html():
    template = (BASE / 'visualizer/dashboard.html').read_text()
    return template.replace('ZTA_META_JSON', json.dumps(META, ensure_ascii=False).replace('<', '\\u003c')).replace('ZTA_CSRF_NONCE', CSRF)


def result_rows():
    result = {}
    for file in sorted([*EVIDENCE.glob('*/case-progress.jsonl'), *EVIDENCE.glob('*/results.jsonl')], key=lambda p: p.stat().st_mtime):
        for line in file.read_text().splitlines():
            try:
                row = json.loads(line)
                if row['case_id'] not in META:
                    continue
                manifest = json.loads((file.parent / 'manifest.json').read_text())
                row['run_status'] = manifest['status']
                if manifest.get('finished_at'):
                    from datetime import datetime
                    row['task_duration_seconds'] = (datetime.fromisoformat(manifest['finished_at']) - datetime.fromisoformat(manifest['started_at'])).total_seconds()
                row['expect'] = html.escape(json.dumps(row['expected'], ensure_ascii=False))
                row['result'] = html.escape(str(row['observed'].get('http_code', row['observed'].get('kind', ''))))
                result[row['case_id']] = row
            except (ValueError, KeyError):
                continue
    return result


def collect(run_id, process, path):
    with path.open('a') as output:
        for line in process.stdout:
            output.write(json.dumps({'line': redact(line.strip())[:4000]}, ensure_ascii=False) + '\n')
            output.flush()
        code = process.wait()
        output.write(json.dumps({'done': True, 'status': 'PASS' if code == 0 else 'ERROR' if code == 2 else 'FAIL', 'exit_code': code}) + '\n')
    JOBS[run_id]['done'] = True


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def valid_host(self):
        return self.headers.get('Host') in HOSTS

    def send_json(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        for key, value in {'Content-Type': 'application/json; charset=utf-8', 'Content-Length': str(len(body)),
                           'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'}.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not self.valid_host() or self.headers.get('Origin') not in ORIGINS or not secrets.compare_digest(self.headers.get('X-ZTA-CSRF', ''), CSRF):
            return self.send_json(403, {'error': 'Invalid host/origin/CSRF'})
        path = urlparse(self.path).path
        if not path.startswith('/api/run/'):
            return self.send_json(404, {'error': 'Not found'})
        identifier = path[len('/api/run/'):]
        actions = {'test-all': ('test', []), 'perf': ('perf', []), 'jwt-refresh': ('jwt-refresh', []),
                   'restore-strict': ('restore-strict', []), 'logs-pretty': ('logs', [])}
        if identifier == 'S32':
            actions[identifier] = ('perf', [])
        elif identifier in META:
            actions[identifier] = ('case', ['--case-id', identifier])
        if identifier not in actions:
            return self.send_json(400, {'error': 'Unknown action'})
        try:
            descriptor = acquire_lock()
        except RuntimeError:
            return self.send_json(409, {'error': 'Run already active'})
        run_id = str(uuid.uuid4())
        directory = Path.home() / '.cache/zta-v2/events'
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        log = directory / (run_id + '.jsonl')
        log.touch()
        action, extra = actions[identifier]
        try:
            process = subprocess.Popen([sys.executable, str(BASE / 'scripts/zta.py'), action, '--run-id', run_id, *extra], cwd=BASE,
                env=dict(os.environ, ZTA_LOCK_FD=str(descriptor)), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, pass_fds=(descriptor,), start_new_session=True)
        finally:
            os.close(descriptor)
        JOBS[run_id] = {'process': process, 'path': log, 'done': False}
        threading.Thread(target=collect, args=(run_id, process, log), daemon=True).start()
        self.send_json(202, {'run_id': run_id, 'events_url': '/api/runs/' + run_id + '/events'})

    def do_GET(self):
        if not self.valid_host() or (self.headers.get('Origin') and self.headers['Origin'] not in ORIGINS):
            return self.send_json(403, {'error': 'Invalid host/origin'})
        path = urlparse(self.path).path
        if path.startswith('/api/run/'):
            return self.send_json(405, {'error': 'Use POST'})
        if path == '/':
            content = build_html().encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            self.send_header('X-Frame-Options', 'DENY')
            self.end_headers()
            return self.wfile.write(content)
        if path == '/api/data':
            return self.send_json(200, {'results': result_rows(), 'opa_logs': []})
        if path == '/api/cluster':
            try:
                runtime = Runtime()
                pods = runtime.kubectl('get', 'pods', json_output=True)['items']
                return self.send_json(200, {'pods': [{'name': p['metadata']['name'], 'status': p['status'].get('phase'),
                    'ready': str(sum(c.get('ready', False) for c in p['status'].get('containerStatuses', []) + p['status'].get('initContainerStatuses', []) if c['name'] != 'istio-init'))}
                    for p in pods], 'profile': runtime.profile})
            except Exception as error:
                return self.send_json(503, {'error': redact(error)})
        if path == '/api/perf':
            row = result_rows().get('S32')
            return self.send_json(200, {'rows': row['observed'].get('cells', []) if row else []})
        if path == '/api/report-exists':
            return self.send_json(200, {'exists': (BASE / 'docs/v2/RESULTS.md').is_file()})
        if path == '/report.md' and (BASE / 'docs/v2/RESULTS.md').is_file():
            body = (BASE / 'docs/v2/RESULTS.md').read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'text/markdown; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            return self.wfile.write(body)
        match = re.fullmatch(r'/api/runs/([0-9a-f-]{36})/events', path)
        if match:
            run_id = match.group(1)
            if run_id not in JOBS:
                return self.send_json(404, {'error': 'Unknown run'})
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            try:
                with JOBS[run_id]['path'].open() as stream:
                    while True:
                        line = stream.readline()
                        if line:
                            self.wfile.write(('data: ' + line.rstrip() + '\n\n').encode())
                            self.wfile.flush()
                            if json.loads(line).get('done'):
                                break
                        elif JOBS[run_id]['done']:
                            break
                        else:
                            time.sleep(.1)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        self.send_json(404, {'error': 'Not found'})


def serve():
    print('ZTA v2 dashboard http://localhost:5002', flush=True)
    ThreadingHTTPServer(('127.0.0.1', PORT), Handler).serve_forever()


if __name__ == '__main__':
    serve()
