"""One locked entry point for v2 CLI and dashboard. Stdlib except existing PyYAML."""
from pathlib import Path
import argparse
import compileall
import contextlib
import datetime
import fcntl
import json
import os
import subprocess
import sys
import time
import uuid
import re

from runtime import ROOT, Runtime, RuntimeError, redact

EVIDENCE = ROOT / 'evidence/v2'
ACTIONS = ('check', 'start', 'test', 'perf', 'verify', 'dashboard', 'status', 'stop', 'restore-strict', 'jwt-refresh', 'case', 'logs')


def acquire_lock():
    inherited = os.environ.get('ZTA_LOCK_FD')
    if inherited:
        descriptor = int(inherited)
        os.fstat(descriptor)
        return descriptor
    directory = Path.home() / '.cache/zta-v2'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(directory / 'run.lock', os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        raise RuntimeError('A ZTA run is already active')
    return descriptor


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def canaries(runtime):
    from identity import issue_tokens
    from suite import request
    admin = issue_tokens(runtime, 'admin-user')
    viewer = issue_tokens(runtime, 'viewer-user')
    allowed = request(runtime, path='/api/data', headers={'Authorization': 'Bearer ' + admin['access'],
        'X-ZTA-Posture': admin['posture']})
    denied = request(runtime, path='/api/admin', headers={'Authorization': 'Bearer ' + viewer['access'],
        'X-ZTA-Posture': viewer['posture']})
    empty = request(runtime, path='/api/admin', headers={})
    missing_posture = request(runtime, path='/api/data', headers={'Authorization': 'Bearer ' + admin['access']})
    def code(result):
        return int(result.get('http_code', result.get('http_status', 0)) or 0)
    body = allowed.get('body', '')
    if code(allowed) != 200 or 'sensor-data' not in body or code(denied) not in (401, 403) or code(empty) not in (401, 403) or code(missing_posture) != 403:
        raise RuntimeError('Strict allow/deny/backend-body canaries failed (credentials omitted)')
    print('PASS: strict admin backend-data, viewer admin deny, missing JWT/posture deny', flush=True)


def check(runtime):
    outputs = []
    if not all(compileall.compile_dir(ROOT / name, quiet=1) for name in ('app', 'scripts', 'visualizer', 'tests')):
        raise RuntimeError('Python syntax error')
    for script in (ROOT / 'scripts').glob('*.sh'):
        runtime.run(['bash', '-n', str(script)])
    for args in [('check', '/src/k8s/policy.rego', '/src/k8s/mask.rego'),
                 ('test', '/src/k8s/policy.rego', '/src/k8s/mask.rego', '/src/tests/policy_test.rego', '-v')]:
        command = ['docker', 'run', '--rm', '-v', str(ROOT) + ':/src:ro', '--entrypoint=/opa',
                   'openpolicyagent/opa:0.70.0-envoy', *args]
        result = runtime.run(command, timeout=300)
        outputs.append(redact(result.stdout))
        print(redact(result.stdout), flush=True)
    host_python = runtime.state / 'venv/bin/python'
    if host_python.exists():
        result = runtime.run([str(host_python), '-m', 'unittest', 'discover', '-s', 'tests', '-v'])
        outputs.append(redact(result.stderr + result.stdout))
        print(redact(result.stderr + result.stdout), flush=True)
    else:
        raise RuntimeError('Run setup of the local test venv before check')
    for mode in ('sidecar', 'mtls', 'jwt', 'opa-role', 'strict'):
        objects = runtime.rendered_resources(mode)
        if sum(o['kind'] == 'Deployment' for o in objects) != 9:
            raise RuntimeError('Rendered deployment inventory differs')
        for item in objects:
            if item['kind'] == 'AuthorizationPolicy' and item['spec'].get('action') == 'CUSTOM' and any('from' in rule for rule in item['spec']['rules']):
                raise RuntimeError('Unsupported principal matching on CUSTOM policy')
            if item['kind'] == 'Service' and item['metadata']['name'] == 'opa' and item['spec']['ports'][0].get('appProtocol') != 'grpc':
                raise RuntimeError('OPA service protocol must be explicitly gRPC')
    print('PASS: Python/Bash/Rego/app/runner/dashboard regression checks', flush=True)
    write_json(runtime.state / 'last-check.json', {'status':'PASS','source_sha256':runtime.source_fingerprint(),
        'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'level':'unit', 'outputs':outputs, 'manifest_modes':5})


def execute_results(runtime, action, run_id=None, case_id=None):
    run_id = run_id or str(uuid.uuid4())
    uuid.UUID(run_id)
    directory = EVIDENCE / run_id
    directory.mkdir(parents=True, exist_ok=False)
    manifest = {'schema_version': 1, 'run_id': run_id, 'action': action,
                'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'status': 'RUNNING',
                **runtime.manifest()}
    write_json(directory / 'manifest.json', manifest)
    if hasattr(runtime, 'state') and (runtime.state / 'last-check.json').exists():
        offline = json.loads((runtime.state / 'last-check.json').read_text())
        if offline.get('source_sha256') == manifest.get('source_sha256'):
            write_json(directory / 'offline-check.json', offline)
    rows = []
    restoration_ok = False
    execution_error = None
    try:
        manifest['live_contract'] = runtime.live_contract()
        if hasattr(runtime, 'app_unit_check'):
            manifest['app_unit'] = runtime.app_unit_check(directory / 'app-python312-unit.txt')
        if action in ('test', 'case'):
            from suite import run_suite
            rows = run_suite(runtime, directory, only=case_id)
        else:
            from performance import run_performance
            rows = run_performance(runtime, directory)
        required = {case_id} if action == 'case' else {f'S{i:02d}' for i in range(1, 35)} - {'S32'} if action == 'test' else {'S32'}
        if {r['case_id'] for r in rows} != required or len(rows) != len(required):
            raise RuntimeError('Case coverage mismatch: required ' + ','.join(sorted(required)))
        with open(directory / 'results.jsonl', 'w') as result_file:
            for row in rows:
                result_file.write(json.dumps(row, ensure_ascii=False) + '\n')
                print(row['case_id'] + ' ' + row['status'], flush=True)
    except BaseException as error:
        execution_error = type(error).__name__
        if (directory / 'case-progress.jsonl').exists():
            rows = [json.loads(line) for line in (directory / 'case-progress.jsonl').read_text().splitlines()]
            (directory / 'results.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
        raise
    finally:
        print('Restoring strict policy and checking live canaries', flush=True)
        try:
            runtime.apply_mode('strict')
            canaries(runtime)
            restoration_ok = True
        finally:
            if hasattr(runtime, 'source_fingerprint'):
                manifest['source_unchanged'] = runtime.source_fingerprint() == manifest.get('source_sha256')
                if not manifest['source_unchanged']:
                    execution_error = execution_error or 'SourceChangedDuringRun'
            manifest['restored_strict'] = restoration_ok
            manifest['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            manifest['execution_error'] = execution_error
            passed = bool(rows) and all(r['status'] == 'PASS' for r in rows) and restoration_ok
            manifest['status'] = 'PASS' if passed and not execution_error else 'ERROR' if execution_error or any(r['status'] == 'ERROR' for r in rows) or not restoration_ok else 'FAIL'
            write_json(directory / 'manifest.json', manifest)
    if manifest['status'] == 'PASS':
        latest = EVIDENCE / ('latest-' + action + '.json')
        temporary = latest.with_suffix('.tmp')
        write_json(temporary, {'run_id': run_id})
        temporary.replace(latest)
    return 0 if manifest['status'] == 'PASS' else 2 if manifest['status'] == 'ERROR' else 1


def verify(runtime):
    check_record = json.loads((runtime.state / 'last-check.json').read_text())
    if check_record.get('status') != 'PASS' or check_record.get('source_sha256') != runtime.source_fingerprint():
        raise RuntimeError('Current source has no passing offline check')
    coverage = {}
    for name in ('test', 'perf'):
        reference = json.loads((EVIDENCE / ('latest-' + name + '.json')).read_text())
        identifier = reference.get('run_id')
        try:
            if not isinstance(identifier, str) or str(uuid.UUID(identifier)) != identifier:
                raise ValueError('noncanonical run ID')
        except (ValueError, AttributeError):
            raise RuntimeError('Invalid evidence run ID')
        directory = EVIDENCE / reference['run_id']
        if directory.resolve().parent != EVIDENCE.resolve():
            raise RuntimeError('Evidence directory escapes the v2 evidence root')
        manifest = json.loads((directory / 'manifest.json').read_text())
        if manifest.get('run_id') != identifier or manifest.get('action') != name or manifest.get('schema_version') != 1:
            raise RuntimeError('Evidence manifest identity/action/schema mismatch')
        if manifest['status'] != 'PASS' or not manifest.get('restored_strict'):
            raise RuntimeError('Latest ' + name + ' is not a valid completed run')
        if manifest.get('source_sha256') != runtime.source_fingerprint() or not manifest.get('source_unchanged'):
            raise RuntimeError('Latest ' + name + ' was not generated by the current unchanged source')
        for line in (directory / 'results.jsonl').read_text().splitlines():
            row = json.loads(line)
            if row.get('run_id') != identifier or row.get('schema_version') != 1 or row.get('case_id') in coverage:
                raise RuntimeError('Evidence result identity/schema/duplicate mismatch')
            if row['status'] != 'PASS':
                raise RuntimeError('Latest evidence contains failed case')
            coverage[row['case_id']] = row
    if set(coverage) != {f'S{i:02d}' for i in range(1, 35)}:
        raise RuntimeError('Missing actual34-case coverage')
    cells = coverage['S32']['observed']['cells']
    expected_cells = {f'S32-{layer}-c{c}-r{repeat}' for layer in ('sidecar', 'mtls', 'jwt', 'opa-role', 'strict') for c in (1,4) for repeat in (1,2,3)}
    if len(cells) != 30 or {c['case_id'] for c in cells} != expected_cells or any(c['status'] != 'PASS' or c['observed'].get('duration_seconds') != 30 or c['observed'].get('error_rate') != 0 for c in cells):
        raise RuntimeError('Official performance matrix is incomplete or invalid')
    for row in coverage.values():
        for file in (EVIDENCE / row['run_id']).rglob('*'):
            if file.is_file() and __import__('re').search(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', file.read_text(errors='replace')):
                raise RuntimeError('Credential-like JWT found in evidence')
    if runtime.opa_query('data.jwt_trust.mode') != 'strict':
        raise RuntimeError('Live policy not strict')
    runtime.wait_ready()
    runtime.live_contract()
    canaries(runtime)
    baseline = ROOT.parent.parent / 'zta-project'
    if runtime.run(['git', '-C', str(baseline), 'status', '--porcelain']).stdout.strip():
        raise RuntimeError('Original repository tracked state changed')
    print('PASS:34 cases, official performance, strict restoration, baseline preserved', flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=ACTIONS)
    parser.add_argument('--run-id')
    parser.add_argument('--case-id')
    args = parser.parse_args()
    if args.action == 'dashboard':
        sys.path.insert(0, str(ROOT / 'visualizer'))
        from server import serve
        serve()
        return 0
    descriptor = None
    try:
        descriptor = acquire_lock()
        runtime = Runtime()
        if args.action == 'check':
            check(runtime)
        elif args.action == 'start':
            runtime.start()
            canaries(runtime)
        elif args.action in ('test', 'perf'):
            return execute_results(runtime, args.action, args.run_id)
        elif args.action == 'verify':
            verify(runtime)
        elif args.action == 'restore-strict':
            runtime.apply_mode('strict')
            canaries(runtime)
        elif args.action == 'jwt-refresh':
            runtime.sync_jwks()
            canaries(runtime)
        elif args.action == 'status':
            print(runtime.run(['minikube', '-p', runtime.profile, 'status']).stdout)
            print(runtime.kubectl('get', 'deployments'))
        elif args.action == 'stop':
            runtime.stop()
        elif args.action == 'logs':
            print(redact(runtime.kubectl('logs', 'deploy/opa', '--tail=150')))
        elif args.action == 'case':
            if args.case_id not in {f'S{i:02d}' for i in range(1,35)} - {'S32'}:
                raise RuntimeError('Unknown functional case')
            return execute_results(runtime, 'case', args.run_id, args.case_id)
    except (Exception, KeyboardInterrupt) as error:
        print(redact('ERROR: ' + str(error)), file=sys.stderr, flush=True)
        return 2
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
