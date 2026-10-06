"""Repeatable Fortio matrix; only valid 200/body samples are PASS."""
from __future__ import annotations

import json
import random
import re
import secrets
import subprocess
import statistics
import time
from pathlib import Path

import identity
from suite import SCHEMA_VERSION, _activate_mode, _envoy_line, request

LAYERS = ("sidecar", "mtls", "jwt", "opa-role", "strict")
CONCURRENCY = (1, 4)
REPEATS = 3
DURATION = "30s"
WARMUP = "10s"
OFFERED_QPS = "8"
FORTIO_DEPLOYMENT = "deploy/fortio-client"
FORTIO_CONTAINER = "fortio"


def _row(run_id, case_id, level, expected, observed, status, evidence=()):
    observed = dict(observed)
    observed.setdefault("mode", level if level in LAYERS else "multiple")
    return {"schema_version": SCHEMA_VERSION, "run_id": run_id, "case_id": case_id,
            "level": "experiment", "request_id": observed.get("request_id"), "status": status,
            "expected": expected, "observed": observed, "evidence": list(evidence)}


def _headers(runtime, layer):
    issued = identity.issue_tokens(runtime, username="admin-user", kind="healthy")
    return {"Authorization": f"Bearer {issued['access']}",
            "X-ZTA-Posture": issued["posture"]}, issued["access"]


def _fortio(runtime, concurrency, duration, headers, request_id, output_path):
    # Fortio's local REST API accepts options on stdin, keeping both JWTs out of argv.
    payload = {"url": "http://frontend/api/data", "c": str(concurrency), "qps": OFFERED_QPS,
               "t": duration, "p": "50,95,99", "save": "off",
               "headers": [f"{name}: {value}" for name, value in
                           {**headers, "X-Request-ID": request_id}.items()]}
    # Keep the driver control request outside the mesh policy being measured.
    # Native curl reads the credential-bearing payload from stdin; stdclient
    # decodes chunked responses. The measured REST load client is unchanged.
    timeout = int(duration.rstrip('s')) + 15
    control_id = 'control-' + request_id
    started = time.monotonic()
    response = {'kind':'error', 'http_code':None, 'curl_exit':None, 'kubectl_exit':None,
                'body_ok':None, 'body':'', 'request_id':control_id,
                'control_transport':'pod-loopback-native-fortio-curl'}
    try:
        proc = runtime.kubectl_process('exec', '-i', FORTIO_DEPLOYMENT, '-c', FORTIO_CONTAINER,
            '--', '/usr/bin/fortio', 'curl', '-quiet', '-stdclient', '-timeout', f'{timeout}s',
            '-payload-file', '/dev/stdin', '-H', 'Content-Type: application/json',
            '-H', 'X-Request-ID: ' + control_id, 'http://localhost:8080/fortio/rest/run',
            input=json.dumps(payload), check=False, timeout=timeout + 5)
        response.update(kubectl_exit=proc.returncode, body=proc.stdout,
                        kind='report' if proc.returncode == 0 else 'error')
    except subprocess.TimeoutExpired:
        response['kind'] = 'timeout'
    response['control_duration_seconds'] = round(time.monotonic() - started, 3)
    # Inspect in memory only: even truncated JWTs must never enter evidence/output.
    logs = runtime.kubectl('logs', 'deploy/fortio-client', '-c', 'fortio', '--since=60s')
    if re.search(r'\beyJ[A-Za-z0-9_-]{12,}', logs):
        raise RuntimeError('Fortio log credential masking failed')
    response['fortio_log_credentials_absent'] = True
    return response


def _percentiles(hist):
    out = {}
    for item in hist.get("Percentiles", []):
        if isinstance(item, dict):
            p = item.get("Percentile")
            v = item.get("Value")
            if p is not None and v is not None:
                out[f"p{str(p).replace('.', '_')}"] = round(float(v) * 1000, 3)
    return out


def _safe_report(value):
    if isinstance(value, dict):
        return {key: _safe_report(item) for key, item in value.items()
                if not re.search(r"header|authorization|token|secret|password|credential", str(key), re.I)}
    if isinstance(value, list):
        return [_safe_report(item) for item in value]
    if isinstance(value, str):
        return re.sub(r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\b", "[JWT REDACTED]", value)
    return value


def _measure(runtime, run_id, case_id, layer, concurrency, duration, headers, request_id, output_path, remote_path):
    canary = request(runtime, "http://frontend", "/api/data", headers=headers,
                     client="curl-client")
    if (canary.get("kind") != "http" or canary.get("http_code") != 200
            or "sensor-data" not in canary.get("body", "")):
        return _row(run_id, case_id,
                    layer, {"canary": 200, "body_contains": "sensor-data"},
                    {"kind": "error", "layer": layer, "http_code": canary.get("http_code"),
                     "kubectl_exit": canary.get("kubectl_exit"), "body_ok": False,
                     "request_id": request_id}, "ERROR", ["pre-measurement allow canary failed"])
    result = _fortio(runtime, concurrency, duration, headers, request_id, remote_path)
    status = "ERROR"
    observed = {key: value for key, value in result.items() if key != "body"}
    observed.update({"body_ok": False, "layer": layer, "request_id": request_id,
                     "control_request_id": result["request_id"], "control_kind": result["kind"]})
    evidence = []
    if result['kind'] == 'report' and result['kubectl_exit'] == 0:
        try:
            data = json.loads(result['body'])
            output_path.write_text(json.dumps(_safe_report(data), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            histogram = data.get("DurationHistogram", {})
            codes = {str(k): int(v) for k, v in data.get("RetCodes", {}).items()}
            count = int(histogram.get("Count", sum(codes.values())))
            # Fortio observes status/timing; only the preceding canary checks a body.
            canary_body_ok = True
            observed.update({"kind": "http", "http_code": 200 if codes == {"200": count} else None,
                             "curl_exit": None, "kubectl_exit": 0, "body_ok": None,
                             "preflight_body_ok": canary_body_ok,
                             "preflight_request_id": canary['request_id'],
                             "measured_response_body_asserted": False,
                             "request_id": request_id, "layer": layer, "mode": layer,
                             "responses": count, "status_histogram": codes,
                             "concurrency": concurrency, "duration_seconds": float(duration.rstrip('s')),
                             "actual_duration_seconds": float(data.get('ActualDuration', 0)) / 1e9,
                             "error_rate": 1 - codes.get('200', 0) / count if count else 1,
                             "actual_qps": data.get("ActualQPS"),
                             "offered_qps": float(OFFERED_QPS),
                             "avg_ms": round(float(histogram.get("Avg", 0)) * 1000, 3),
                             "latency_ms": _percentiles(histogram)})
            valid_options = (data.get('RequestedDuration') == duration and data.get('NumThreads') == concurrency
                             and float(data.get('RequestedQPS', -1)) == float(OFFERED_QPS)
                             and float(data.get('ActualDuration', 0)) / 1e9 >= float(duration.rstrip('s')))
            status = "PASS" if count > 0 and codes == {"200": count} and canary_body_ok and valid_options and {'p50','p95','p99'} <= set(observed['latency_ms']) else "FAIL"
            evidence.append(f"{output_path.name}: Fortio JSON")
            evidence.append("pre-measurement canary body contains sensor-data")
        except Exception as exc:
            evidence.append(f"result parse failed: {type(exc).__name__}")
    else:
        observed['kind'] = 'error'
        evidence.append("Fortio REST request failed; actual transport fields retained")
    if status == "ERROR":
        observed['kind'] = 'error'
        if result.get('control_transport') != 'pod-loopback-native-fortio-curl':
            try:
                observed['control_envoy'] = _envoy_line(runtime, 'curl-client', result['request_id'])
            except Exception as exc:
                observed['control_envoy_error'] = type(exc).__name__
        error_path = output_path.with_suffix('.error.json')
        error_path.write_text(json.dumps(_safe_report(observed), ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        evidence.append(f"{error_path.name}: transport observation (response body omitted)")
    return _row(run_id, case_id, layer,
                {"http_code": 200, "preflight_body_contains": "sensor-data", "duration": duration,
                 "concurrency": concurrency}, observed, status, evidence)


def run_performance(runtime, run_dir):
    run_id = Path(run_dir).name
    outdir = Path(run_dir) / "perf"
    outdir.mkdir(parents=True, exist_ok=True)
    cells = [(layer, c) for layer in LAYERS for c in CONCURRENCY]
    seed = int.from_bytes(secrets.token_bytes(4), "big")
    rng = random.Random(seed)
    warm_order = cells[:]
    rng.shuffle(warm_order)
    samples = []
    errors = {}
    restore_error = None
    try:
        # Warm each profile/concurrency once, then interleave the 30 measured runs.
        for layer, concurrency in warm_order:
            try:
                _activate_mode(runtime, layer)
                headers, _ = _headers(runtime, layer)
                rid = f"{run_id}-warm-{layer}-c{concurrency}"
                remote_path = f"/tmp/{rid}.json"
                proc = _fortio(runtime, concurrency, WARMUP, headers, rid,
                               remote_path)
                warm_data = json.loads(proc['body']) if proc['kind'] == 'report' else {}
                warm_ok = (proc['kind'] == 'report' and proc['kubectl_exit'] == 0
                    and set(warm_data.get('RetCodes', {})) == {'200'}
                    and sum(warm_data.get('RetCodes', {}).values()) > 0
                    and warm_data.get('RequestedDuration') == WARMUP
                    and warm_data.get('NumThreads') == concurrency
                    and float(warm_data.get('RequestedQPS', -1)) == float(OFFERED_QPS)
                    and float(warm_data.get('ActualDuration', 0)) / 1e9 >= float(WARMUP.rstrip('s')))
                (outdir / f'warmup-{layer}-c{concurrency}.json').write_text(
                    json.dumps(_safe_report(warm_data), indent=2) + '\n', encoding='utf-8')
                if not warm_ok:
                    errors[(layer, concurrency, 0)] = "warmup process failed"
                    (outdir / f'warmup-{layer}-c{concurrency}.error.json').write_text(
                        json.dumps(_safe_report({k:v for k,v in proc.items() if k != 'body'}), indent=2) + '\n', encoding='utf-8')
            except Exception as exc:
                errors[(layer, concurrency, 0)] = type(exc).__name__
                if getattr(runtime, 'config_ready', True) is False:
                    raise
        schedule = []
        for repeat in range(1, REPEATS + 1):
            layer_order = list(LAYERS)
            rng.shuffle(layer_order)
            for layer in layer_order:
                concurrency_order = list(CONCURRENCY)
                rng.shuffle(concurrency_order)
                schedule.extend((layer, c, repeat) for c in concurrency_order)
        for layer, concurrency, repeat in schedule:
            case_id = f"S32-{layer}-c{concurrency}-r{repeat}"
            print('Measuring ' + case_id, flush=True)
            if (layer, concurrency, 0) in errors:
                samples.append(_row(run_id, case_id, layer, {"ready": True},
                                 {"kind": "error", "layer": layer, "kubectl_exit": None,
                                  "http_code": None, "body_ok": None}, "ERROR",
                                 [f"warmup failed: {errors[(layer, concurrency, 0)]}"]))
                continue
            output_path = outdir / f"{case_id}.json"
            remote_path = f"/tmp/{run_id}-{layer}-c{concurrency}-r{repeat}.json"
            try:
                _activate_mode(runtime, layer)
                headers, _ = _headers(runtime, layer)
                request_id = f"{run_id}-{layer}-c{concurrency}-r{repeat}"
                sample = _measure(runtime, run_id, case_id, layer, concurrency, DURATION,
                                  headers, request_id, output_path, remote_path)
                sample["evidence"].append(f"interleave seed={seed}")
                samples.append(sample)
                print(case_id + ' ' + sample['status'], flush=True)
            except Exception as exc:
                samples.append(_row(run_id, case_id, layer, {"http_code": 200},
                                 {"kind": "error", "layer": layer, "kubectl_exit": None,
                                  "http_code": None, "body_ok": None}, "ERROR",
                                 [f"measurement failed: {type(exc).__name__}"]))
                if getattr(runtime, 'config_ready', True) is False:
                    raise
    finally:
        try:
            runtime.apply_mode("strict")
            runtime.wait_ready()
            control = request(runtime, "http://frontend", "/api/data",
                              headers=_headers(runtime, "strict")[0], client="curl-client")
            if control.get("kind") != "http" or control.get("http_code") != 200 or "sensor-data" not in control.get("body", ""):
                raise RuntimeError("strict allow canary failed")
        except Exception as exc:
            restore_error = type(exc).__name__
    statuses = {sample["status"] for sample in samples}
    status = "ERROR" if "ERROR" in statuses or restore_error else "FAIL" if "FAIL" in statuses else "PASS"
    observed = {"kind": "http" if status == "PASS" else "error" if status == "ERROR" else "http",
                "http_code": None, "curl_exit": None, "kubectl_exit": 0 if status == "PASS" else None,
                "body_ok": None, "layer": "matrix", "mode": "multiple",
                "cells": [{"case_id": sample["case_id"], "request_id": sample["request_id"],
                           "status": sample["status"], "observed": sample["observed"],
                           "evidence": sample["evidence"]} for sample in samples],
                "restore_error": restore_error}
    observed['repeat_variation'] = []
    for layer, concurrency in cells:
        group = [s['observed'] for s in samples if s['status'] == 'PASS' and s['observed']['layer'] == layer and s['observed'].get('concurrency') == concurrency]
        if len(group) == REPEATS:
            values = [s['avg_ms'] for s in group]
            qps = [s['actual_qps'] for s in group]
            observed['repeat_variation'].append({'layer': layer, 'concurrency': concurrency, 'repeats': len(group),
                'mean_latency_ms': statistics.mean(values), 'latency_stdev_ms': statistics.stdev(values),
                'latency_cv': statistics.stdev(values) / statistics.mean(values) if statistics.mean(values) else 0,
                'mean_qps': statistics.mean(qps), 'qps_stdev': statistics.stdev(qps)})
    evidence = [f"interleave seed={seed}", "strict policy restored and allow canary passed" if not restore_error
                else f"strict restoration/canary failed: {restore_error}"]
    return [_row(run_id, "S32", "matrix",
                 {"layers": list(LAYERS), "concurrency": list(CONCURRENCY),
                  "repeats": REPEATS, "duration": DURATION, "warmup": WARMUP,
                  "offered_qps": float(OFFERED_QPS)},
                 observed, status, evidence)]
