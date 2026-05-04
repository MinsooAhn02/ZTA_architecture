#!/usr/bin/env python3
"""
ZTA Security Dashboard — live command runner
Run : python3 visualizer/server.py
Open: http://localhost:5001
"""
import json, re, subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

PORT = 5001
BASE = Path(__file__).resolve().parent.parent  # project root

# All runnable make targets  (id → make target name)
RUNNABLE = {
    # workflow
    "all":              "all",
    "step1":            "step1",
    "step2":            "step2",
    "step3":            "step3",
    "step4":            "step4",
    "ports":            "ports",
    "status":           "status",
    "jwt-refresh":      "jwt-refresh",
    "setup-keycloak":   "setup-keycloak",
    "setup-viewer":     "setup-keycloak-viewer",
    "test-all":         "test-all",
    "logs-pretty":      "logs-pretty",
    # individual test scenarios
    "A-NS-1": "test-block",
    "A-NS-2": "test-pass",
    "A-EW-1": "test-lateral-block",
    "A-EW-2": "test-lateral-sidecar",
    "A-EW-3": "test-lateral-podip",
    "B-1":    "test-fake",
    "B-2":    "test-jwt-tampered",
    "B-4":    "test-jwt-auto",
    "C-1":    "test-context-user-get",
    "C-2":    "test-context-user-admin",
    "C-3":    "test-context-user-post",
    "C-4":    "test-context-admin-post",
    "D-1":    "test-jwt-admin-all",
    "D-2":    "test-jwt-viewer-read",
    "D-3":    "test-jwt-viewer-admin",
    "D-4":    "test-jwt-viewer-post",
    "E-1":    "test-posture-ok",
    "E-2":    "test-posture-block",
}

TEST_META = {
    "A-NS-1": {"attacker_desc":"External client with no JWT and no role header","signals":{"method":"GET","path":"/api/admin","identity":"none"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"istio-deny","block_reason":"require-jwt AuthorizationPolicy: notRequestPrincipals → DENY 403","defense_layer":"Istio Authorization Policy"},
    "A-NS-2": {"attacker_desc":"Client sets role=admin HTTP header (demo scaffolding — client-controllable)","signals":{"method":"GET","path":"/api/admin","identity":"header","role":"admin"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA header rule: role=admin → ALLOW 200 (demo path, not production)","defense_layer":None},
    "A-EW-1": {"attacker_desc":"Compromised pod launched without Istio sidecar — no mTLS certificate","signals":{"method":"GET","path":"/","identity":"none","source":"no-sidecar"},"pipeline":"ew","flow":["rogue-pod","mtls","spiffe","backend"],"block_at":"mtls","block_reason":"mTLS STRICT: no client certificate → TLS handshake fails 403/503","defense_layer":"Istio mTLS STRICT"},
    "A-EW-2": {"attacker_desc":"Pod has Istio sidecar but uses backend-sa; allowlist requires frontend-sa","signals":{"method":"GET","path":"/","identity":"spiffe","sa":"backend-sa"},"pipeline":"ew","flow":["rogue-pod","mtls","spiffe","backend"],"block_at":"spiffe","block_reason":"SPIFFE allowlist: backend-sa ≠ cluster.local/ns/default/sa/frontend-sa → DENY 403","defense_layer":"Istio SPIFFE Allowlist"},
    "A-EW-3": {"attacker_desc":"Rogue pod bypasses service DNS and targets backend podIP:8080 directly","signals":{"method":"GET","path":"/","identity":"none","target":"podIP:8080"},"pipeline":"ew","flow":["rogue-pod","mtls","spiffe","backend"],"block_at":"mtls","block_reason":"Inbound Envoy sidecar enforces policy even via pod IP → 503","defense_layer":"Istio Inbound Policy"},
    "B-1":    {"attacker_desc":"JWT crafted with attacker's private key — signature doesn't match Keycloak JWKS","signals":{"method":"GET","path":"/api/admin","identity":"JWT-forged"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"istio-jwt","block_reason":"Istio JWKS verify: RSA sig invalid → no principal → require-jwt DENY 403","defense_layer":"Istio JWT Authentication (JWKS)"},
    "B-2":    {"attacker_desc":"Real JWT payload modified (added admin role) but original signature kept","signals":{"method":"GET","path":"/api/admin","identity":"JWT-tampered"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"istio-jwt","block_reason":"RSA verify: new_payload hash ≠ original_signature → 401 Unauthorized","defense_layer":"Istio JWT Authentication (RSA verify)"},
    "B-4":    {"attacker_desc":"testuser obtains a valid Keycloak JWT and accesses the admin endpoint","signals":{"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"admin"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"All layers passed: JWKS ✓ → principal ✓ → OPA admin role ✓ → 200 OK","defense_layer":None},
    "C-1":    {"attacker_desc":"Client with role=user reads the general data endpoint","signals":{"method":"GET","path":"/api/data","identity":"header","role":"user"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA: role=user + GET + non-admin path → ALLOW 200","defense_layer":None},
    "C-2":    {"attacker_desc":"Client with role=user requests admin endpoint — admin path restriction","signals":{"method":"GET","path":"/api/admin","identity":"header","role":"user"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"opa","block_reason":"OPA: role=user + path=/api/admin → startswith check fails → DENY 403","defense_layer":"OPA Context Policy (role+path)"},
    "C-3":    {"attacker_desc":"Client with role=user attempts POST — write operations require admin","signals":{"method":"POST","path":"/api/write","identity":"header","role":"user"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"opa","block_reason":"OPA: role=user + method=POST → no matching allow rule → DENY 403","defense_layer":"OPA Context Policy (role+method)"},
    "C-4":    {"attacker_desc":"Admin user performing an authorized write operation","signals":{"method":"POST","path":"/api/write","identity":"header","role":"admin"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA: role=admin → device_posture_ok → ALLOW 200","defense_layer":None},
    "D-1":    {"attacker_desc":"testuser Keycloak JWT with realm_access.roles=[admin] → admin endpoint","signals":{"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"admin"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA jwt_has_role(admin) + device_posture_ok → ALLOW 200","defense_layer":None},
    "D-2":    {"attacker_desc":"vieweruser Keycloak JWT with realm_access.roles=[viewer] → data endpoint","signals":{"method":"GET","path":"/api/data","identity":"JWT-valid","role":"viewer"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA jwt_has_role(viewer) + GET + non-admin path → ALLOW 200","defense_layer":None},
    "D-3":    {"attacker_desc":"vieweruser JWT tries admin path — viewer role has no admin access","signals":{"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"viewer"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"opa","block_reason":"OPA: jwt_has_role(viewer) + /api/admin → admin path forbidden → DENY 403","defense_layer":"OPA JWT Claim Policy"},
    "D-4":    {"attacker_desc":"vieweruser JWT attempts write — viewer is read-only, POST requires admin JWT","signals":{"method":"POST","path":"/api/write","identity":"JWT-valid","role":"viewer"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"opa","block_reason":"OPA: jwt_has_role(viewer) + POST → viewer is read-only → DENY 403","defense_layer":"OPA JWT Claim Policy"},
    "E-1":    {"attacker_desc":"Admin JWT + X-Device-Firewall: enabled — device posture gate passes","signals":{"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"admin","posture":"enabled"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA device_posture_ok: X-Device-Firewall=enabled → ALLOW 200","defense_layer":None},
    "E-2":    {"attacker_desc":"Stolen valid admin JWT but device is unhealthy (X-Device-Firewall: disabled)","signals":{"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"admin","posture":"disabled"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"opa","block_reason":"OPA device_posture_ok: X-Device-Firewall=disabled → DENY 403","defense_layer":"OPA Device Posture Policy"},
}


def parse_test_summary():
    path = BASE / ".test-summary.log"
    tests = []
    if not path.exists():
        return tests
    for line in path.read_text(errors="replace").splitlines():
        parts = line.strip().split("|")
        if len(parts) < 4:
            continue
        name_full = parts[0].strip()
        idx = name_full.find(" ")
        test_id = name_full[:idx] if idx > 0 else name_full
        name    = name_full[idx+1:] if idx > 0 else name_full
        tests.append({
            "id": test_id, "name": name,
            "scenario": test_id.split("-")[0],
            "expect": parts[1].strip(), "result": parts[2].strip(),
            "status": parts[3].strip(),
            "detail": parts[4].strip() if len(parts) > 4 else "",
        })
    return tests


def parse_opa_logs():
    path = BASE / "evidence" / "opa-decision-logs.txt"
    logs = []
    if not path.exists():
        return logs
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 3:
            continue
        mp = parts[1].split()
        ctx = parts[2] if len(parts) > 2 else ""
        rm = re.search(r"role=(\S+)", ctx)
        fm = re.search(r"fw=(\S+)",   ctx)
        logs.append({
            "decision": parts[0],
            "method":   mp[0] if mp else "-",
            "path":     mp[1] if len(mp) > 1 else "-",
            "role":     rm.group(1) if rm else "-",
            "firewall": fm.group(1) if fm else "-",
            "identity": parts[3].replace("id=","").strip() if len(parts) > 3 else "-",
        })
    return logs[-60:]


# ── HTML ───────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ZTA Security Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',system-ui,sans-serif;font-size:14px}

/* ── Header ── */
.hdr{background:#161b22;border-bottom:1px solid #21262d;padding:10px 22px;display:flex;align-items:center;justify-content:space-between;gap:12px;position:sticky;top:0;z-index:30;flex-wrap:wrap}
.hdr-left h1{font-size:16px;font-weight:700;color:#f0f6fc}
.hdr-left .sub{font-size:11px;color:#8b949e;margin-top:1px}
.svc-links{display:flex;gap:8px;flex-wrap:wrap}
.svc-btn{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:6px;font-size:12px;font-weight:600;text-decoration:none;border:1px solid;cursor:pointer;transition:opacity .15s;white-space:nowrap}
.svc-btn:hover{opacity:.8}
.svc-kc {background:#1a1000;color:#e3b341;border-color:#d29922}
.svc-gf {background:#1a0e00;color:#f89040;border-color:#d26911}
.svc-ki {background:#0d1f38;color:#79c0ff;border-color:#388bfd}
.hdr-right{display:flex;align-items:center;gap:16px}
.stats{display:flex;gap:14px}
.stat{text-align:center}
.stat .val{font-size:18px;font-weight:700}
.stat .lbl{font-size:10px;color:#8b949e;text-transform:uppercase}
.st-t .val{color:#79c0ff}.st-p .val{color:#3fb950}.st-f .val{color:#f85149}
.hdr-ts{font-size:10px;color:#484f58}

/* ── Layout ── */
.main{max-width:1480px;margin:0 auto;padding:16px 22px;display:flex;flex-direction:column;gap:16px}
.card{background:#161b22;border:1px solid #21262d;border-radius:8px;overflow:hidden}
.ch{padding:11px 16px;border-bottom:1px solid #21262d;display:flex;align-items:center;justify-content:space-between;gap:8px}
.ch h2{font-size:11px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.6px}
.cb{padding:16px}

/* ── Workflow phases ── */
.phase-row{display:flex;align-items:stretch;gap:0;overflow-x:auto;padding:4px 0}
.ph-node{
  display:flex;flex-direction:column;align-items:center;justify-content:center;gap:4px;
  min-width:130px;padding:12px 10px;border:2px solid #30363d;border-radius:8px;
  background:#0d1117;cursor:pointer;transition:all .2s;flex-shrink:0;position:relative
}
.ph-node:hover{border-color:#388bfd;background:#0d1f38}
.ph-node.ph-running{border-color:#d29922;background:#130f00;animation:shimmer .8s infinite}
.ph-node.ph-pass   {border-color:#238636;background:#0d2010}
.ph-node.ph-fail   {border-color:#da3633;background:#2d0c0c}
.ph-node.ph-all    {border-color:#8957e5;background:#120d2a;min-width:110px}
.ph-node.ph-all:hover{border-color:#bc8cff}
.ph-ico{font-size:22px;line-height:1}
.ph-lbl{font-size:12px;font-weight:700;color:#e6edf3;text-align:center}
.ph-sub{font-size:10px;color:#8b949e;text-align:center}
.ph-desc{font-size:10px;color:#484f58;text-align:center;line-height:1.3}
.ph-status{position:absolute;top:5px;right:7px;font-size:11px;font-weight:700}
.ph-arrow{display:flex;align-items:center;padding:0 6px;font-size:18px;color:#30363d;flex-shrink:0}

@keyframes shimmer{0%,100%{opacity:1}50%{opacity:.55}}

/* ── Quick commands ── */
.quick-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(165px,1fr));gap:10px;margin-top:14px}
.qc{
  display:flex;align-items:center;gap:10px;padding:10px 12px;
  border:1px solid #21262d;border-radius:6px;cursor:pointer;transition:all .15s;background:#0d1117
}
.qc:hover{border-color:#388bfd;background:#0d1f38}
.qc.qc-running{border-color:#d29922;background:#130f00}
.qc.qc-pass   {border-color:#238636;background:#0d2010}
.qc.qc-fail   {border-color:#da3633;background:#2d0c0c}
.qc-ico{font-size:18px;flex-shrink:0}
.qc-body{flex:1;min-width:0}
.qc-lbl{font-size:12px;font-weight:600;color:#e6edf3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.qc-desc{font-size:10px;color:#8b949e;margin-top:1px}
.qc-badge{font-size:10px;font-weight:700;padding:1px 5px;border-radius:8px;border:1px solid;flex-shrink:0}
.qb-idle{background:#21262d;color:#8b949e;border-color:#30363d}
.qb-run {background:#1a1000;color:#e3b341;border-color:#d29922}
.qb-ok  {background:#1c4025;color:#3fb950;border-color:#238636}
.qb-ng  {background:#3d1b1b;color:#f85149;border-color:#da3633}

/* ── Terminal ── */
.term-card{background:#161b22;border:1px solid #21262d;border-radius:8px;overflow:hidden;display:flex;flex-direction:column}
.term-bar{display:flex;align-items:center;gap:8px;padding:7px 14px;background:#0d1117;border-bottom:1px solid #21262d;flex-shrink:0}
.term-bar .dots span{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:3px}
.d-r{background:#f85149}.d-y{background:#e3b341}.d-g{background:#3fb950}
.term-ttl{font-size:11px;color:#8b949e;font-family:'Consolas',monospace;flex:1}
.run-badge{font-size:11px;font-weight:600;padding:2px 10px;border-radius:10px;border:1px solid}
.rb-idle{background:#21262d;color:#8b949e;border-color:#30363d}
.rb-run {background:#1a1000;color:#e3b341;border-color:#d29922;animation:shimmer .8s infinite}
.rb-ok  {background:#1c4025;color:#3fb950;border-color:#238636}
.rb-ng  {background:#3d1b1b;color:#f85149;border-color:#da3633}
.term-body{padding:10px 14px;font-family:'Consolas','Monaco',monospace;font-size:12px;line-height:1.6;overflow-y:auto;max-height:300px;min-height:60px}
.term-body::-webkit-scrollbar{width:4px}
.term-body::-webkit-scrollbar-track{background:#0d1117}
.term-body::-webkit-scrollbar-thumb{background:#30363d;border-radius:2px}
.tl{display:block;white-space:pre-wrap;word-break:break-all}
.tl-cmd{color:#00b4d8}.tl-sep{color:#30363d}.tl-hdr{color:#f0f6fc;font-weight:700}
.tl-sec{color:#79c0ff}.tl-sig{color:#8b949e}.tl-note{color:#d29922}
.tl-exp{color:#79c0ff}.tl-res{color:#e3b341}
.tl-pass{color:#3fb950;font-weight:700}.tl-fail{color:#f85149;font-weight:700}
.tl-ok{color:#3fb950;border-top:1px solid #238636;margin-top:6px;padding-top:5px}
.tl-ng{color:#f85149;border-top:1px solid #da3633;margin-top:6px;padding-top:5px}
.tl-idle{color:#484f58;font-style:italic}

/* ── Pipeline (security flow) ── */
.pl-wrap{display:flex;align-items:stretch;overflow-x:auto;padding:4px 0}
.pl-node{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:4px;min-width:110px;padding:12px 8px;border:2px solid #30363d;border-radius:8px;background:#0d1117;transition:all .28s;flex-shrink:0}
.pl-node .ico{font-size:20px;line-height:1}
.pl-node .lbl{font-size:11px;font-weight:700;text-align:center;color:#8b949e;transition:color .28s}
.pl-node .sub{font-size:10px;text-align:center;color:#484f58}
.pl-arrow{display:flex;align-items:center;padding:0 5px;font-size:16px;color:#30363d;flex-shrink:0;transition:color .28s}
.pl-node.inactive{border-color:#21262d;opacity:.3}
.pl-node.active  {border-color:#388bfd;background:#0d1f38}.pl-node.active .lbl{color:#79c0ff}
.pl-node.passed  {border-color:#238636;background:#0d2010}.pl-node.passed .lbl{color:#3fb950}
.pl-node.allowed {border-color:#238636;background:#0d2010}.pl-node.allowed .lbl{color:#3fb950}
.pl-node.blocked {border-color:#da3633;background:#2d0c0c;animation:pulse-red .85s ease-in-out 4}.pl-node.blocked .lbl{color:#f85149}
.pl-node.unreachable{border-color:#21262d;opacity:.15}
.pl-arrow.passed{color:#238636}.pl-arrow.blocked{color:#21262d}
@keyframes pulse-red{0%{box-shadow:0 0 0 0 rgba(218,54,51,.55)}65%{box-shadow:0 0 0 10px rgba(218,54,51,0)}100%{box-shadow:0 0 0 0 rgba(218,54,51,0)}}

/* ── Detail ── */
.lower{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:14px}
@media(max-width:900px){.lower{grid-template-columns:1fr}}
.dp{padding:12px;background:#0d1117;border:1px solid #21262d;border-radius:6px;min-height:110px}
.dp h3{font-size:11px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
.dp-empty{color:#484f58;font-style:italic;font-size:12px;padding:12px 0}
.dp-desc{font-size:12px;color:#c9d1d9;margin-bottom:8px;line-height:1.5}
.tags{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:8px}
.tag{padding:2px 7px;border-radius:10px;font-size:11px;font-family:'Consolas',monospace;border:1px solid}
.t-m{background:#0d2547;border-color:#1f6feb;color:#79c0ff}
.t-p{background:#1a1000;border-color:#d29922;color:#e3b341}
.t-i{background:#1f1235;border-color:#8957e5;color:#bc8cff}
.t-r{background:#0d2010;border-color:#238636;color:#3fb950}
.t-ok{background:#0d2010;border-color:#238636;color:#3fb950}
.t-bad{background:#2d0c0c;border-color:#da3633;color:#f85149}
.t-sa{background:#1a0f00;border-color:#d29922;color:#e3b341}
.reason{font-size:12px;font-family:'Consolas',monospace;padding:8px 10px;border-radius:4px;line-height:1.5}
.r-deny {background:#2d0c0c;border-left:3px solid #da3633;color:#f85149}
.r-allow{background:#0d2010;border-left:3px solid #238636;color:#3fb950}
.layer-txt{font-size:11px;color:#8b949e;margin-top:4px}

/* ── Test grid ── */
.tabs{display:flex;overflow-x:auto;border-bottom:1px solid #21262d}
.tab{padding:10px 14px;font-size:12px;font-weight:500;color:#8b949e;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap;transition:all .15s}
.tab:hover{color:#e6edf3}.tab.active{color:#f0f6fc;border-bottom-color:#388bfd}
.tab .cnt{background:#21262d;color:#8b949e;font-size:10px;padding:1px 5px;border-radius:8px;margin-left:4px}
.tab.active .cnt{background:#388bfd22;color:#79c0ff}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(172px,1fr));gap:10px;padding:14px}
.tc{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:11px;cursor:pointer;transition:all .15s}
.tc:hover{border-color:#388bfd;background:#0d1f38}
.tc.selected{border-color:#388bfd;background:#0d1f36;box-shadow:0 0 0 1px #388bfd33}
.tc.tc-run{border-color:#d29922;background:#130f00}
.tc .tid{font-size:10px;font-weight:700;font-family:'Consolas',monospace;color:#8b949e;margin-bottom:2px}
.tc .tname{font-size:12px;color:#e6edf3;line-height:1.4;margin-bottom:7px}
.tc .trow{display:flex;justify-content:space-between;align-items:center}
.tc .codes{font-size:11px;font-family:'Consolas',monospace;color:#8b949e}
.badge{padding:2px 7px;border-radius:9px;font-size:11px;font-weight:700;border:1px solid}
.badge.pass   {background:#1c4025;color:#3fb950;border-color:#238636}
.badge.fail   {background:#3d1b1b;color:#f85149;border-color:#da3633}
.badge.running{background:#1a1000;color:#e3b341;border-color:#d29922}
.badge.unknown{background:#21262d;color:#8b949e;border-color:#30363d}
.bl-tag{display:inline-block;font-size:10px;margin-top:4px;padding:2px 6px;border-radius:4px;font-family:'Consolas',monospace;border:1px solid}
.bl-istio{background:#1a0f28;color:#a371f7;border-color:#6e40c9}
.bl-opa  {background:#0d1f30;color:#56b6c2;border-color:#00b4d8}
.bl-allow{background:#0d2010;color:#3fb950;border-color:#238636}
.bl-fail {background:#3d1b1b;color:#f85149;border-color:#da3633}
.grid-empty{grid-column:1/-1;padding:32px;text-align:center;color:#484f58;font-style:italic}

/* ── OPA log ── */
.log-scroll{max-height:240px;overflow-y:auto}
.log-scroll::-webkit-scrollbar{width:4px}
.log-scroll::-webkit-scrollbar-track{background:#0d1117}
.log-scroll::-webkit-scrollbar-thumb{background:#30363d;border-radius:2px}
.log-tbl{width:100%;border-collapse:collapse;font-family:'Consolas',monospace;font-size:12px}
.log-tbl th{padding:7px 12px;background:#0d1117;color:#8b949e;font-size:10px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid #21262d;text-align:left;white-space:nowrap}
.log-tbl td{padding:5px 12px;border-bottom:1px solid #161b22;color:#c9d1d9}
.log-tbl tr:hover td{background:#0d1f36}
.log-tbl td:first-child{font-weight:700}
.d-allow{color:#3fb950}.d-deny{color:#f85149}
.log-empty{padding:24px;text-align:center;color:#484f58;font-size:12px}

.hidden{display:none!important}
</style>
</head>
<body>

<!-- ── Header ──────────────────────────────────────────────────── -->
<div class="hdr">
  <div class="hdr-left">
    <h1>⬡ ZTA Security Dashboard</h1>
    <div class="sub">NIST SP 800-207 · Keycloak + Istio + OPA</div>
  </div>

  <div class="svc-links">
    <a class="svc-btn svc-kc" href="http://localhost:8080" target="_blank">🔑 Keycloak</a>
    <a class="svc-btn svc-gf" href="http://localhost:3000" target="_blank">📊 Grafana</a>
    <a class="svc-btn svc-ki" href="http://localhost:20001" target="_blank">🕸️ Kiali</a>
  </div>

  <div class="hdr-right">
    <div class="stats">
      <div class="stat st-t"><div class="val" id="s-total">—</div><div class="lbl">Total</div></div>
      <div class="stat st-p"><div class="val" id="s-pass">—</div> <div class="lbl">Pass</div></div>
      <div class="stat st-f"><div class="val" id="s-fail">—</div> <div class="lbl">Fail</div></div>
    </div>
    <div class="hdr-ts" id="s-ts"></div>
  </div>
</div>

<div class="main">

<!-- ── 1. Make Workflow ─────────────────────────────────────────── -->
<div class="card">
  <div class="ch">
    <h2>Make Workflow — click a phase to run it</h2>
    <span style="font-size:11px;color:#8b949e">make all = step1 → step2 → step3 → step4</span>
  </div>
  <div class="cb">

    <!-- Phase pipeline -->
    <div class="phase-row" id="phase-row">

      <!-- make all (special) -->
      <div class="ph-node ph-all" id="ph-all" onclick="runCmd('all','all')">
        <div class="ph-status" id="pst-all"></div>
        <div class="ph-ico">⬡</div>
        <div class="ph-lbl">make all</div>
        <div class="ph-sub">Full Setup</div>
        <div class="ph-desc">Entire pipeline</div>
      </div>

      <div class="ph-arrow">→</div>

      <div class="ph-node" id="ph-step1" onclick="runCmd('step1','step1')">
        <div class="ph-status" id="pst-step1"></div>
        <div class="ph-ico">🏗️</div>
        <div class="ph-lbl">Step 1</div>
        <div class="ph-sub">Infrastructure</div>
        <div class="ph-desc">Minikube + Istio<br>Addons + Image</div>
      </div>

      <div class="ph-arrow">→</div>

      <div class="ph-node" id="ph-step2" onclick="runCmd('step2','step2')">
        <div class="ph-status" id="pst-step2"></div>
        <div class="ph-ico">🚀</div>
        <div class="ph-lbl">Step 2</div>
        <div class="ph-sub">Deploy</div>
        <div class="ph-desc">App + Keycloak<br>+ OPA + wait</div>
      </div>

      <div class="ph-arrow">→</div>

      <div class="ph-node" id="ph-step3" onclick="runCmd('step3','step3')">
        <div class="ph-status" id="pst-step3"></div>
        <div class="ph-ico">🛡️</div>
        <div class="ph-lbl">Step 3</div>
        <div class="ph-sub">N-S Policy</div>
        <div class="ph-desc">OPA ext-authz<br>AuthzPolicy</div>
      </div>

      <div class="ph-arrow">→</div>

      <div class="ph-node" id="ph-step4" onclick="runCmd('step4','step4')">
        <div class="ph-status" id="pst-step4"></div>
        <div class="ph-ico">🔐</div>
        <div class="ph-lbl">Step 4</div>
        <div class="ph-sub">E-W + JWT</div>
        <div class="ph-desc">mTLS + SPIFFE<br>JWT + Keycloak</div>
      </div>

      <div class="ph-arrow">→</div>

      <div class="ph-node" id="ph-test-all" onclick="runCmd('test-all','test-all')">
        <div class="ph-status" id="pst-test-all"></div>
        <div class="ph-ico">🧪</div>
        <div class="ph-lbl">Test All</div>
        <div class="ph-sub">Scenarios A–E</div>
        <div class="ph-desc">make test-all</div>
      </div>

    </div>

    <!-- Quick commands -->
    <div class="quick-grid">
      <div class="qc" id="qc-ports" onclick="runCmd('ports','ports')">
        <div class="qc-ico">🔌</div>
        <div class="qc-body"><div class="qc-lbl">Start Ports</div><div class="qc-desc">Port-forward Keycloak / Kiali / Grafana</div></div>
        <div class="qc-badge qb-idle" id="qb-ports">▶</div>
      </div>
      <div class="qc" id="qc-status" onclick="runCmd('status','status')">
        <div class="qc-ico">📋</div>
        <div class="qc-body"><div class="qc-lbl">Cluster Status</div><div class="qc-desc">Pods + Services + Security Policies</div></div>
        <div class="qc-badge qb-idle" id="qb-status">▶</div>
      </div>
      <div class="qc" id="qc-jwt-refresh" onclick="runCmd('jwt-refresh','jwt-refresh')">
        <div class="qc-ico">🔄</div>
        <div class="qc-body"><div class="qc-lbl">JWT Refresh</div><div class="qc-desc">Sync JWKS + restart Istio verifier</div></div>
        <div class="qc-badge qb-idle" id="qb-jwt-refresh">▶</div>
      </div>
      <div class="qc" id="qc-setup-viewer" onclick="runCmd('setup-viewer','setup-viewer')">
        <div class="qc-ico">👥</div>
        <div class="qc-body"><div class="qc-lbl">Add Viewer User</div><div class="qc-desc">Create vieweruser in Keycloak (Scenario D)</div></div>
        <div class="qc-badge qb-idle" id="qb-setup-viewer">▶</div>
      </div>
      <div class="qc" id="qc-logs-pretty" onclick="runCmd('logs-pretty','logs-pretty')">
        <div class="qc-ico">📜</div>
        <div class="qc-body"><div class="qc-lbl">OPA Logs</div><div class="qc-desc">Fetch + parse OPA decision log</div></div>
        <div class="qc-badge qb-idle" id="qb-logs-pretty">▶</div>
      </div>
      <div class="qc" id="qc-setup-keycloak" onclick="runCmd('setup-keycloak','setup-keycloak')">
        <div class="qc-ico">🔑</div>
        <div class="qc-body"><div class="qc-lbl">Setup Keycloak</div><div class="qc-desc">Create realm / client / testuser</div></div>
        <div class="qc-badge qb-idle" id="qb-setup-keycloak">▶</div>
      </div>
    </div>

  </div>
</div>

<!-- ── 2. Terminal ─────────────────────────────────────────────── -->
<div class="term-card">
  <div class="term-bar">
    <div class="dots"><span class="d-r"></span><span class="d-y"></span><span class="d-g"></span></div>
    <span class="term-ttl" id="term-ttl">$ click any phase / quick command / test card to run it live</span>
    <span class="run-badge rb-idle" id="run-badge">idle</span>
  </div>
  <div class="term-body" id="terminal">
    <span class="tl tl-idle">Waiting for command…</span>
  </div>
</div>

<!-- ── 3. ZTA Security Pipeline (shown when test selected) ──────── -->
<div class="card" id="pipeline-card">
  <div class="ch">
    <h2>ZTA Security Pipeline</h2>
    <span style="font-size:11px;color:#8b949e" id="pl-type">North-South</span>
  </div>
  <div class="cb">

    <div id="pl-ns" class="pl-wrap">
      <div class="pl-node" id="node-client"><div class="ico">💻</div><div class="lbl">Client</div><div class="sub">Attacker / User</div></div>
      <div class="pl-arrow" id="arr-ns-1">→</div>
      <div class="pl-node" id="node-istio-jwt"><div class="ico">🔑</div><div class="lbl">Istio JWT Auth</div><div class="sub">JWKS RSA verify</div></div>
      <div class="pl-arrow" id="arr-ns-2">→</div>
      <div class="pl-node" id="node-istio-deny"><div class="ico">🛡️</div><div class="lbl">Istio DENY Policy</div><div class="sub">require-jwt check</div></div>
      <div class="pl-arrow" id="arr-ns-3">→</div>
      <div class="pl-node" id="node-opa"><div class="ico">⚖️</div><div class="lbl">OPA Policy</div><div class="sub">Rego rule eval</div></div>
      <div class="pl-arrow" id="arr-ns-4">→</div>
      <div class="pl-node" id="node-app"><div class="ico">🖥️</div><div class="lbl">App</div><div class="sub">Frontend / Backend</div></div>
    </div>

    <div id="pl-ew" class="pl-wrap hidden">
      <div class="pl-node" id="node-rogue-pod"><div class="ico">☠️</div><div class="lbl">Rogue Pod</div><div class="sub">Compromised workload</div></div>
      <div class="pl-arrow" id="arr-ew-1">→</div>
      <div class="pl-node" id="node-mtls"><div class="ico">🔐</div><div class="lbl">Istio mTLS</div><div class="sub">STRICT cert verify</div></div>
      <div class="pl-arrow" id="arr-ew-2">→</div>
      <div class="pl-node" id="node-spiffe"><div class="ico">🪪</div><div class="lbl">SPIFFE Allowlist</div><div class="sub">ServiceAccount check</div></div>
      <div class="pl-arrow" id="arr-ew-3">→</div>
      <div class="pl-node" id="node-backend"><div class="ico">🖥️</div><div class="lbl">Backend</div><div class="sub">Internal service</div></div>
    </div>

    <div class="lower">
      <div class="dp" id="detail-pane">
        <div class="dp-empty">← Select a test card below to see the attack details</div>
      </div>
      <div class="dp" id="test-info">
        <div class="dp-empty">Pipeline will animate when test card is clicked</div>
      </div>
    </div>

  </div>
</div>

<!-- ── 4. Test Grid ────────────────────────────────────────────── -->
<div class="card">
  <div class="tabs" id="tabs">
    <div class="tab active" data-f="all">All<span class="cnt" id="cnt-all">—</span></div>
    <div class="tab" data-f="A">A — Lateral<span class="cnt" id="cnt-A">—</span></div>
    <div class="tab" data-f="B">B — JWT<span class="cnt" id="cnt-B">—</span></div>
    <div class="tab" data-f="C">C — Context<span class="cnt" id="cnt-C">—</span></div>
    <div class="tab" data-f="D">D — JWT Claim<span class="cnt" id="cnt-D">—</span></div>
    <div class="tab" data-f="E">E — Posture<span class="cnt" id="cnt-E">—</span></div>
  </div>
  <div class="grid" id="grid"><div class="grid-empty">Loading…</div></div>
</div>

<!-- ── 5. OPA Log ──────────────────────────────────────────────── -->
<div class="card">
  <div class="ch"><h2>OPA Decision Log</h2><span style="font-size:11px;color:#8b949e" id="opa-cnt"></span></div>
  <div class="log-scroll">
    <table class="log-tbl">
      <thead><tr><th>Decision</th><th>Method</th><th>Path</th><th>Role</th><th>Firewall</th><th>Identity</th></tr></thead>
      <tbody id="log-body"><tr><td colspan="6"><div class="log-empty">No OPA logs — run: <code>make logs-pretty</code></div></td></tr></tbody>
    </table>
  </div>
</div>

</div><!-- /main -->

<script>
const ARROW = {
  "istio-jwt":"arr-ns-1","istio-deny":"arr-ns-2","opa":"arr-ns-3","app":"arr-ns-4",
  "mtls":"arr-ew-1","spiffe":"arr-ew-2","backend":"arr-ew-3",
};

// Step markers in make output → which phase to activate
const STEP_MARKERS = [
  { match: "[Step 1]",   id: "step1"    },
  { match: "[Step 2]",   id: "step2"    },
  { match: "[Step 3]",   id: "step3"    },
  { match: "[Step 4]",   id: "step4"    },
  { match: "SCENARIO A", id: "test-all" },
  { match: "SCENARIO B", id: "test-all" },
  { match: "SCENARIO C", id: "test-all" },
  { match: "SCENARIO D", id: "test-all" },
  { match: "SCENARIO E", id: "test-all" },
];

let allTests = [], metaMap = {}, filter = "all", selectedId = null;
let activeSource = null, animBusy = false, runningId = null;
// track which phase was last updated for "make all" progress
let lastPhaseActivated = null;

// ── Data load ──────────────────────────────────────────────────────────────
async function load() {
  try {
    const d = await fetch("/api/data").then(r => r.json());
    allTests = d.tests;
    metaMap  = d.meta;
    updateStats();
    updateCounts();
    renderGrid();
    renderLogs(d.opa_logs);
    g("s-ts").textContent = new Date().toLocaleTimeString();
  } catch(e) {
    g("grid").innerHTML = '<div class="grid-empty" style="color:#f85149">⚠ Server unreachable</div>';
  }
}

function updateStats() {
  const pass = allTests.filter(t=>t.status==="PASS").length;
  const fail = allTests.filter(t=>t.status==="FAIL").length;
  g("s-total").textContent = allTests.length||"—";
  g("s-pass").textContent  = allTests.length?pass:"—";
  g("s-fail").textContent  = allTests.length?fail:"—";
}

function updateCounts() {
  ["all","A","B","C","D","E"].forEach(f=>{
    const el = g("cnt-"+f);
    if(el) el.textContent = f==="all"?allTests.length:allTests.filter(t=>t.scenario===f).length;
  });
}

// ── Test grid ──────────────────────────────────────────────────────────────
function renderGrid() {
  const list = filter==="all"?allTests:allTests.filter(t=>t.scenario===filter);
  if(!list.length){g("grid").innerHTML='<div class="grid-empty">No results — run <code>make test-all</code> first</div>';return;}
  g("grid").innerHTML = list.map(t=>{
    const m   = metaMap[t.id], blk = m?m.block_at:null;
    let bTag  = "";
    if(t.status==="FAIL")bTag=`<span class="bl-tag bl-fail">✗ FAIL</span>`;
    else if(!blk)         bTag=`<span class="bl-tag bl-allow">✓ ALLOW</span>`;
    else if(["istio-jwt","istio-deny","mtls","spiffe"].includes(blk))bTag=`<span class="bl-tag bl-istio">✗ Istio</span>`;
    else if(blk==="opa")  bTag=`<span class="bl-tag bl-opa">✗ OPA</span>`;
    const sel = selectedId===t.id?" selected":"";
    const run = runningId===t.id?" tc-run":"";
    const bst = runningId===t.id?"running":(t.status||"unknown").toLowerCase();
    const bl  = runningId===t.id?"▶ …":(t.status||"?");
    return `<div class="tc${sel}${run}" onclick="pickTest('${t.id}')">
<div class="tid">${t.id}</div>
<div class="tname">${t.name}</div>
<div class="trow"><span class="codes">${t.expect} → ${t.result}</span><span class="badge ${bst}">${bl}</span></div>
${bTag}
</div>`;
  }).join("");
}

g("tabs").addEventListener("click",e=>{
  const tab=e.target.closest(".tab");if(!tab)return;
  document.querySelectorAll(".tab").forEach(t=>t.classList.remove("active"));
  tab.classList.add("active");filter=tab.dataset.f;renderGrid();
});

// ── Pick test card ─────────────────────────────────────────────────────────
function pickTest(id) {
  selectedId = id;
  const m = metaMap[id];
  if(!m)return;
  const isEW = m.pipeline==="ew";
  g("pl-ns").classList.toggle("hidden",isEW);
  g("pl-ew").classList.toggle("hidden",!isEW);
  g("pl-type").textContent = isEW?"East-West (Lateral)":"North-South";
  renderDetail(id,m);
  renderGrid();
  resetPipeline(m.flow);
  if(!animBusy) animateFlow(m.flow, m.block_at);
  // run live in terminal
  runCmd(id, id);
}

// ── Detail pane ────────────────────────────────────────────────────────────
function renderDetail(id, m) {
  const sig=m.signals, tags=[];
  if(sig.method)   tags.push(`<span class="tag t-m">${sig.method}</span>`);
  if(sig.path)     tags.push(`<span class="tag t-p">${sig.path}</span>`);
  if(sig.identity) tags.push(`<span class="tag t-i">id:${sig.identity}</span>`);
  if(sig.role)     tags.push(`<span class="tag t-r">role:${sig.role}</span>`);
  if(sig.posture==="enabled")  tags.push(`<span class="tag t-ok">firewall:enabled</span>`);
  if(sig.posture==="disabled") tags.push(`<span class="tag t-bad">firewall:disabled</span>`);
  if(sig.sa)       tags.push(`<span class="tag t-sa">sa:${sig.sa}</span>`);
  const rc=m.block_at?"r-deny":"r-allow", rp=m.block_at?"✗ BLOCKED":"✓ ALLOWED";
  g("detail-pane").innerHTML=`<h3>Attack / Request Signals</h3>
<div class="dp-desc">${m.attacker_desc}</div>
<div class="tags">${tags.join("")}</div>
<h3 style="margin-top:10px">Defense Decision</h3>
<div class="reason ${rc}">${rp}: ${m.block_reason}</div>
${m.defense_layer?`<div class="layer-txt">Layer: ${m.defense_layer}</div>`:""}`;
  g("test-info").innerHTML=`<h3>Test ID: ${id}</h3>
<div class="dp-desc" style="margin-top:6px">make target: <code style="color:#79c0ff">${RUNNABLE_MAP[id]||"?"}</code></div>`;
}

const RUNNABLE_MAP={
  "A-NS-1":"test-block","A-NS-2":"test-pass","A-EW-1":"test-lateral-block",
  "A-EW-2":"test-lateral-sidecar","A-EW-3":"test-lateral-podip","B-1":"test-fake",
  "B-2":"test-jwt-tampered","B-4":"test-jwt-auto","C-1":"test-context-user-get",
  "C-2":"test-context-user-admin","C-3":"test-context-user-post","C-4":"test-context-admin-post",
  "D-1":"test-jwt-admin-all","D-2":"test-jwt-viewer-read","D-3":"test-jwt-viewer-admin",
  "D-4":"test-jwt-viewer-post","E-1":"test-posture-ok","E-2":"test-posture-block",
};

// ── Command runner (workflow + tests share this) ───────────────────────────
function runCmd(id, cmdId) {
  if(activeSource){activeSource.close();activeSource=null;}

  const target  = RUNNABLE_MAP[cmdId] || cmdId; // test IDs use map, workflow IDs = direct
  const term    = g("terminal");
  const badge   = g("run-badge");
  const ttl     = g("term-ttl");

  runningId = cmdId;
  renderGrid();

  badge.className   = "run-badge rb-run";
  badge.textContent = "▶ running";
  ttl.textContent   = `$ make --no-print-directory ${target}`;

  term.innerHTML = `<span class="tl tl-cmd">$ make --no-print-directory ${target}</span>
<span class="tl tl-sep">─────────────────────────────────────────────</span>`;

  // reset phase status for workflow commands
  if(["all","step1","step2","step3","step4","test-all"].includes(cmdId)){
    setPhase(cmdId,"running");
    if(cmdId==="all"){
      ["step1","step2","step3","step4","test-all"].forEach(p=>setPhase(p,""));
      lastPhaseActivated=null;
    }
  }
  setQuick(cmdId,"running");

  const src = new EventSource(`/api/run/${cmdId}`);
  activeSource = src;

  src.onmessage = ev => {
    const d = JSON.parse(ev.data);
    if(d.done){
      src.close(); activeSource=null; runningId=null;
      const ok = d.status==="PASS";
      badge.className   = ok?"run-badge rb-ok":"run-badge rb-ng";
      badge.textContent = ok?"✓ PASS":"✗ FAIL";
      appendLine(term,"─────────────────────────────────────────────","tl-sep");
      appendLine(term,`Exit: ${d.status}  (code ${d.exit_code})`, ok?"tl-ok":"tl-ng");
      if(["all","step1","step2","step3","step4","test-all"].includes(cmdId)){
        setPhase(cmdId, ok?"ph-pass":"ph-fail");
        if(cmdId==="all" && lastPhaseActivated)
          setPhase(lastPhaseActivated, ok?"ph-pass":"ph-fail");
      }
      setQuick(cmdId, ok?"qc-pass":"qc-fail");
      if(cmdId===selectedId && metaMap[selectedId]){
        const m=metaMap[selectedId];
        if(!ok && !m.block_at) flashPipelineFail(m.flow);
      }
      const t=allTests.find(x=>x.id===cmdId);
      if(t) t.status=d.status;
      renderGrid();
      return;
    }
    const line = d.line;
    appendLine(term, line);
    // live phase activation when running "make all"
    if(cmdId==="all"){
      STEP_MARKERS.forEach(sm=>{
        if(line.includes(sm.match) && sm.id!==lastPhaseActivated){
          if(lastPhaseActivated) setPhase(lastPhaseActivated,"ph-pass");
          setPhase(sm.id,"ph-running");
          lastPhaseActivated=sm.id;
        }
      });
    }
    term.scrollTop = term.scrollHeight;
  };

  src.onerror=()=>{
    if(activeSource){activeSource.close();activeSource=null;}
    runningId=null;
    badge.className="run-badge rb-idle";badge.textContent="idle";
    setQuick(cmdId,"");setPhase(cmdId,"");
    renderGrid();
    appendLine(term,"⚠ Stream closed","tl-note");
    term.scrollTop=term.scrollHeight;
  };
}

// ── Phase node state ───────────────────────────────────────────────────────
function setPhase(id, state){
  const el = g("ph-"+id); if(!el)return;
  const st = g("pst-"+id);
  el.classList.remove("ph-running","ph-pass","ph-fail");
  if(state==="ph-running"||state==="running"){el.classList.add("ph-running");if(st)st.textContent="⏳";}
  else if(state==="ph-pass"||state==="pass") {el.classList.add("ph-pass");   if(st)st.textContent="✓";}
  else if(state==="ph-fail"||state==="fail") {el.classList.add("ph-fail");   if(st)st.textContent="✗";}
  else {if(st)st.textContent="";}
}

function setQuick(id, state){
  const el = g("qc-"+id), bel = g("qb-"+id); if(!el&&!bel)return;
  if(el){el.classList.remove("qc-running","qc-pass","qc-fail");
    if(state==="running")el.classList.add("qc-running");
    else if(state.includes("pass")||state==="qc-pass")el.classList.add("qc-pass");
    else if(state.includes("fail")||state==="qc-fail")el.classList.add("qc-fail");}
  if(bel){
    bel.className="qc-badge";
    if(state==="running"){bel.classList.add("qb-run");bel.textContent="⏳";}
    else if(state.includes("pass")){bel.classList.add("qb-ok"); bel.textContent="✓";}
    else if(state.includes("fail")){bel.classList.add("qb-ng"); bel.textContent="✗";}
    else{bel.classList.add("qb-idle");bel.textContent="▶";}
  }
}

// ── Terminal helpers ───────────────────────────────────────────────────────
function appendLine(term, text, fc){
  const s=document.createElement("span");
  s.className="tl "+(fc||lineClass(text));
  s.textContent=text;
  term.appendChild(s);
  term.appendChild(document.createTextNode("\n"));
  term.scrollTop=term.scrollHeight;
}

function lineClass(l){
  if(!l)return"";
  if(l.includes("STATUS: PASS"))return"tl-pass";
  if(l.includes("STATUS: FAIL"))return"tl-fail";
  if(l.includes("SCENARIO")&&l.includes("PASS"))return"tl-pass";
  if(l.includes("SCENARIO")&&l.includes("FAIL"))return"tl-fail";
  if(/^EXPECT:/.test(l))return"tl-exp";
  if(/^RESULT:/.test(l))return"tl-res";
  if(/^\[.+\]/.test(l))return"tl-hdr";
  if(/^={3,}/.test(l)||/^-{3,}/.test(l))return"tl-sep";
  if(/^>>>/.test(l))return"tl-sec";
  if(/^(NOTE|WARNING):/.test(l))return"tl-note";
  if(/^REQUEST SIGNALS:|^\s+-/.test(l))return"tl-sig";
  if(/^(Waiting|deployment|requestauth|Applied|pod)/.test(l))return"";
  return"";
}

// ── Pipeline animation ─────────────────────────────────────────────────────
function resetPipeline(flow){
  flow.forEach(id=>{const el=g("node-"+id);if(el)el.className="pl-node inactive";});
  Object.values(ARROW).forEach(id=>{const el=g(id);if(el)el.className="pl-arrow";});
}

async function animateFlow(flow, blockAt){
  animBusy=true;
  for(let i=0;i<flow.length;i++){
    const nid=flow[i], el=g("node-"+nid);if(!el)continue;
    await wait(350);
    if(i>0){const arr=g(ARROW[nid]);if(arr)arr.className="pl-arrow "+(nid===blockAt?"blocked":"passed");}
    if(nid===blockAt){
      el.className="pl-node blocked";
      flow.slice(i+1).forEach(id=>{const e=g("node-"+id);if(e)e.className="pl-node unreachable";});
      break;
    } else {el.className=i===flow.length-1?"pl-node allowed":"pl-node passed";}
  }
  animBusy=false;
}

function flashPipelineFail(flow){
  flow.forEach(id=>{
    const el=g("node-"+id);
    if(el&&!el.classList.contains("blocked")){
      el.style.transition="border-color .2s";el.style.borderColor="#da3633";
      setTimeout(()=>{el.style.borderColor="";el.style.transition="";},1200);
    }
  });
}

// ── OPA log ───────────────────────────────────────────────────────────────
function renderLogs(logs){
  if(!logs||!logs.length)return;
  g("opa-cnt").textContent=logs.length+" entries";
  g("log-body").innerHTML=logs.map(l=>`<tr>
<td class="${l.decision==="ALLOW"?"d-allow":"d-deny"}">${l.decision}</td>
<td>${l.method}</td><td>${l.path}</td><td>${l.role}</td><td>${l.firewall}</td><td>${l.identity}</td>
</tr>`).join("");
}

const g=id=>document.getElementById(id);
const wait=ms=>new Promise(r=>setTimeout(r,ms));

load();
setInterval(load,30000);
</script>
</body>
</html>"""


# ── HTTP Handler ───────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            body = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/api/data":
            payload = {"tests": parse_test_summary(), "meta": TEST_META, "opa_logs": parse_opa_logs()}
            body = json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path.startswith("/api/run/"):
            self._sse(path[9:])

        else:
            self.send_error(404)

    def _sse(self, cmd_id):
        # cmd_id can be a test scenario id OR a workflow command id
        # test IDs map through RUNNABLE, workflow ids are direct make targets
        target = RUNNABLE.get(cmd_id)
        if not target:
            self.send_error(404, f"Unknown command: {cmd_id}")
            return

        self.send_response(200)
        self.send_header("Content-Type",  "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        def emit(payload):
            self.wfile.write(f"data: {json.dumps(payload)}\n\n".encode())
            self.wfile.flush()

        try:
            proc = subprocess.Popen(
                ["make", "--no-print-directory", target],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                cwd=str(BASE), text=True, bufsize=1, errors="replace",
            )
            for line in proc.stdout:
                emit({"line": line.rstrip()})
            proc.wait()
            emit({"done": True, "status": "PASS" if proc.returncode == 0 else "FAIL",
                  "exit_code": proc.returncode})
        except (BrokenPipeError, ConnectionResetError):
            try: proc.terminate()
            except Exception: pass
        except FileNotFoundError:
            emit({"line": "ERROR: 'make' not found — run this server from WSL"})
            emit({"done": True, "status": "FAIL", "exit_code": 127})
        except Exception as e:
            emit({"line": f"ERROR: {e}"})
            emit({"done": True, "status": "FAIL", "exit_code": 1})

    def log_message(self, fmt, *args):
        pass


# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
        print(f"ZTA Dashboard  →  http://localhost:{PORT}")
        print(f"Project root   :  {BASE}")
        print("Ctrl+C to stop\n")
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
