#!/usr/bin/env python3
"""
ZTA Security Dashboard
Run  : python3 visualizer/server.py   (WSL required for make)
Open : http://localhost:5001
"""
import json, re, subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

PORT = 5001
BASE = Path(__file__).resolve().parent.parent

RUNNABLE = {
    "all": "all", "step1": "step1", "step2": "step2",
    "step3": "step3", "step4": "step4", "ports": "ports",
    "status": "status", "jwt-refresh": "jwt-refresh",
    "setup-keycloak": "setup-keycloak",
    "setup-viewer": "setup-keycloak-viewer",
    "test-all": "test-all", "logs-pretty": "logs-pretty",
    "A-NS-1": "test-block",      "A-NS-2": "test-pass",
    "A-EW-1": "test-lateral-block", "A-EW-2": "test-lateral-sidecar",
    "A-EW-3": "test-lateral-podip", "B-1": "test-fake",
    "B-2": "test-jwt-tampered",  "B-4": "test-jwt-auto",
    "C-1": "test-context-user-get", "C-2": "test-context-user-admin",
    "C-3": "test-context-user-post","C-4": "test-context-admin-post",
    "D-1": "test-jwt-admin-all", "D-2": "test-jwt-viewer-read",
    "D-3": "test-jwt-viewer-admin","D-4": "test-jwt-viewer-post",
    "E-1": "test-posture-ok",    "E-2": "test-posture-block",
}

TEST_META = {
    "A-NS-1": {"attacker_desc":"External client — no JWT, no role header","signals":{"method":"GET","path":"/api/admin","identity":"none"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"istio-deny","block_reason":"require-jwt AuthorizationPolicy: notRequestPrincipals → DENY 403","defense_layer":"Istio Authorization Policy"},
    "A-NS-2": {"attacker_desc":"Client sets role=admin HTTP header (demo scaffolding)","signals":{"method":"GET","path":"/api/admin","identity":"header","role":"admin"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA header rule: role=admin → ALLOW 200","defense_layer":None},
    "A-EW-1": {"attacker_desc":"Compromised pod — no Istio sidecar, no mTLS certificate","signals":{"method":"GET","path":"/","identity":"none","source":"no-sidecar"},"pipeline":"ew","flow":["rogue-pod","mtls","spiffe","backend"],"block_at":"mtls","block_reason":"mTLS STRICT: no client certificate → TLS handshake fails 403/503","defense_layer":"Istio mTLS STRICT"},
    "A-EW-2": {"attacker_desc":"Pod has sidecar but uses backend-sa; allowlist requires frontend-sa","signals":{"method":"GET","path":"/","identity":"spiffe","sa":"backend-sa"},"pipeline":"ew","flow":["rogue-pod","mtls","spiffe","backend"],"block_at":"spiffe","block_reason":"SPIFFE allowlist: backend-sa ≠ frontend-sa → DENY 403","defense_layer":"Istio SPIFFE Allowlist"},
    "A-EW-3": {"attacker_desc":"Rogue pod targets backend podIP:8080 directly (bypasses service DNS)","signals":{"method":"GET","path":"/","identity":"none","target":"podIP:8080"},"pipeline":"ew","flow":["rogue-pod","mtls","spiffe","backend"],"block_at":"mtls","block_reason":"Inbound Envoy enforces policy even via pod IP → 503","defense_layer":"Istio Inbound Policy"},
    "B-1":    {"attacker_desc":"JWT crafted with attacker's key — signature doesn't match JWKS","signals":{"method":"GET","path":"/api/admin","identity":"JWT-forged"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"istio-jwt","block_reason":"Istio JWKS verify: RSA sig invalid → no principal → DENY 403","defense_layer":"Istio JWT Auth (JWKS)"},
    "B-2":    {"attacker_desc":"Real JWT payload modified (added admin role), original signature kept","signals":{"method":"GET","path":"/api/admin","identity":"JWT-tampered"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"istio-jwt","block_reason":"RSA verify: new payload hash ≠ original signature → 401","defense_layer":"Istio JWT Auth (RSA verify)"},
    "B-4":    {"attacker_desc":"testuser obtains valid Keycloak JWT and accesses admin endpoint","signals":{"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"admin"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"JWKS ✓ → principal ✓ → OPA admin role ✓ → 200","defense_layer":None},
    "C-1":    {"attacker_desc":"role=user reads the general data endpoint","signals":{"method":"GET","path":"/api/data","identity":"header","role":"user"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA: role=user + GET + non-admin path → ALLOW 200","defense_layer":None},
    "C-2":    {"attacker_desc":"role=user requests admin endpoint — admin path restriction","signals":{"method":"GET","path":"/api/admin","identity":"header","role":"user"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"opa","block_reason":"OPA: role=user + path=/api/admin → DENY 403","defense_layer":"OPA Context Policy (role+path)"},
    "C-3":    {"attacker_desc":"role=user attempts POST — write requires admin","signals":{"method":"POST","path":"/api/write","identity":"header","role":"user"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"opa","block_reason":"OPA: role=user + method=POST → DENY 403","defense_layer":"OPA Context Policy (role+method)"},
    "C-4":    {"attacker_desc":"Admin user performing authorized write operation","signals":{"method":"POST","path":"/api/write","identity":"header","role":"admin"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA: role=admin + device_posture_ok → ALLOW 200","defense_layer":None},
    "D-1":    {"attacker_desc":"Keycloak JWT with realm_access.roles=[admin] → admin endpoint","signals":{"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"admin"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA jwt_has_role(admin) + device_posture_ok → ALLOW 200","defense_layer":None},
    "D-2":    {"attacker_desc":"vieweruser Keycloak JWT with roles=[viewer] → data endpoint","signals":{"method":"GET","path":"/api/data","identity":"JWT-valid","role":"viewer"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA jwt_has_role(viewer) + GET + non-admin → ALLOW 200","defense_layer":None},
    "D-3":    {"attacker_desc":"vieweruser JWT tries admin path — viewer has no admin access","signals":{"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"viewer"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"opa","block_reason":"OPA: jwt_has_role(viewer) + /api/admin → DENY 403","defense_layer":"OPA JWT Claim Policy"},
    "D-4":    {"attacker_desc":"vieweruser JWT attempts POST — viewer is read-only","signals":{"method":"POST","path":"/api/write","identity":"JWT-valid","role":"viewer"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"opa","block_reason":"OPA: jwt_has_role(viewer) + POST → DENY 403","defense_layer":"OPA JWT Claim Policy"},
    "E-1":    {"attacker_desc":"Admin JWT + X-Device-Firewall: enabled — posture gate passes","signals":{"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"admin","posture":"enabled"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA device_posture_ok: firewall=enabled → ALLOW 200","defense_layer":None},
    "E-2":    {"attacker_desc":"Stolen valid admin JWT but device unhealthy (firewall: disabled)","signals":{"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"admin","posture":"disabled"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"opa","block_reason":"OPA device_posture_ok: firewall=disabled → DENY 403","defense_layer":"OPA Device Posture Policy"},
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
        fm = re.search(r"fw=(\S+)", ctx)
        logs.append({
            "decision": parts[0],
            "method":   mp[0] if mp else "-",
            "path":     mp[1] if len(mp) > 1 else "-",
            "role":     rm.group(1) if rm else "-",
            "firewall": fm.group(1) if fm else "-",
            "identity": parts[3].replace("id=","").strip() if len(parts) > 3 else "-",
        })
    return logs[-60:]


# ── HTML template (META placeholder replaced at startup) ───────────────────
HTML_TMPL = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ZTA Security Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;height:100vh;display:flex;flex-direction:column}

/* ── Header ── */
.hdr{background:#161b22;border-bottom:1px solid #21262d;padding:10px 20px;display:flex;align-items:center;gap:16px;flex-wrap:wrap;flex-shrink:0}
.hdr h1{font-size:15px;font-weight:700;color:#f0f6fc;white-space:nowrap}
.hdr .sub{font-size:11px;color:#8b949e}
.svc-links{display:flex;gap:6px;margin-left:auto}
.svc-btn{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:5px;font-size:11px;font-weight:600;text-decoration:none;border:1px solid;cursor:pointer;transition:opacity .15s}
.svc-btn:hover{opacity:.75}
.svc-kc{background:#1a1000;color:#e3b341;border-color:#d29922}
.svc-gf{background:#1a0e00;color:#f89040;border-color:#d26911}
.svc-ki{background:#0d1f38;color:#79c0ff;border-color:#388bfd}
.stats{display:flex;gap:14px}
.stat .val{font-size:18px;font-weight:700;line-height:1}
.stat .lbl{font-size:10px;color:#8b949e;text-transform:uppercase}
.st-t .val{color:#79c0ff}.st-p .val{color:#3fb950}.st-f .val{color:#f85149}

/* ── Offline banner ── */
.warn-banner{background:#2d1b00;border-bottom:1px solid #d29922;padding:7px 20px;font-size:12px;color:#e3b341;display:flex;align-items:center;gap:8px}
.warn-banner.hidden{display:none}

/* ── Main split layout ── */
.split{display:grid;grid-template-columns:380px 1fr;flex:1;overflow:hidden;min-height:0}
.left-panel{display:flex;flex-direction:column;border-right:1px solid #21262d;overflow:hidden}
.right-panel{display:flex;flex-direction:column;overflow:hidden}

/* ── Tabs ── */
.tabs{display:flex;overflow-x:auto;border-bottom:1px solid #21262d;flex-shrink:0;background:#161b22}
.tab{padding:9px 12px;font-size:11px;font-weight:500;color:#8b949e;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap;transition:all .15s}
.tab:hover{color:#e6edf3}.tab.active{color:#f0f6fc;border-bottom-color:#388bfd}
.tab .cnt{background:#21262d;color:#8b949e;font-size:10px;padding:1px 4px;border-radius:6px;margin-left:3px}
.tab.active .cnt{background:#1f3a6e;color:#79c0ff}

/* ── Test grid ── */
.grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:12px;overflow-y:auto;flex:1}
.tc{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:10px;cursor:pointer;transition:border-color .15s,background .15s}
.tc:hover{border-color:#388bfd;background:#0b1a30}
.tc.selected{border-color:#388bfd;background:#0d1f36;box-shadow:0 0 0 1px #388bfd44}
.tc.tc-run{border-color:#d29922;background:#130f00}
.tc .tid{font-size:10px;font-weight:700;font-family:'Consolas',monospace;color:#6e7681;margin-bottom:2px}
.tc .tname{font-size:11px;color:#e6edf3;line-height:1.4;margin-bottom:6px}
.tc .trow{display:flex;justify-content:space-between;align-items:center;gap:4px}
.tc .codes{font-size:10px;font-family:'Consolas',monospace;color:#6e7681}
.badge{padding:1px 6px;border-radius:8px;font-size:10px;font-weight:700;border:1px solid;white-space:nowrap}
.badge.pass{background:#1c4025;color:#3fb950;border-color:#238636}
.badge.fail{background:#3d1b1b;color:#f85149;border-color:#da3633}
.badge.running{background:#1a1000;color:#e3b341;border-color:#d29922}
.badge.unknown{background:#21262d;color:#6e7681;border-color:#30363d}
.bl-tag{display:inline-block;font-size:10px;margin-top:4px;padding:1px 5px;border-radius:3px;font-family:'Consolas',monospace;border:1px solid}
.bl-istio{background:#1a0f28;color:#a371f7;border-color:#6e40c9}
.bl-opa{background:#0d1f30;color:#56b6c2;border-color:#00b4d8}
.bl-allow{background:#0d2010;color:#3fb950;border-color:#238636}
.bl-fail{background:#3d1b1b;color:#f85149;border-color:#da3633}
.grid-empty{grid-column:1/-1;padding:24px;text-align:center;color:#484f58;font-size:12px;font-style:italic}

/* ── Right panel: pipeline + detail ── */
.pipeline-area{padding:14px 16px;border-bottom:1px solid #21262d;flex-shrink:0}
.pipeline-area h2{font-size:11px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.6px;margin-bottom:10px;display:flex;align-items:center;justify-content:space-between}
.pl-wrap{display:flex;align-items:center;gap:0;overflow-x:auto;padding:2px 0}
.pl-node{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;min-width:90px;padding:10px 6px;border:2px solid #30363d;border-radius:8px;background:#0d1117;transition:all .25s;flex-shrink:0}
.pl-node .ico{font-size:18px;line-height:1}
.pl-node .lbl{font-size:10px;font-weight:700;text-align:center;color:#6e7681;transition:color .25s}
.pl-node .sub{font-size:9px;text-align:center;color:#484f58;line-height:1.3}
.pl-arrow{display:flex;align-items:center;padding:0 4px;font-size:14px;color:#30363d;flex-shrink:0;transition:color .25s}
.pl-node.inactive{border-color:#21262d;opacity:.3}
.pl-node.active{border-color:#388bfd;background:#0d1f38}.pl-node.active .lbl{color:#79c0ff}
.pl-node.passed{border-color:#238636;background:#0d2010}.pl-node.passed .lbl{color:#3fb950}
.pl-node.allowed{border-color:#238636;background:#0d2010}.pl-node.allowed .lbl{color:#3fb950}
.pl-node.blocked{border-color:#da3633;background:#2d0c0c}.pl-node.blocked .lbl{color:#f85149}
.pl-node.blocked{animation:pulse-red .85s ease-in-out 4}
.pl-node.unreachable{border-color:#21262d;opacity:.15}
.pl-arrow.passed{color:#238636}.pl-arrow.blocked{color:#21262d}
@keyframes pulse-red{0%{box-shadow:0 0 0 0 rgba(218,54,51,.5)}65%{box-shadow:0 0 0 8px rgba(218,54,51,0)}100%{box-shadow:0 0 0 0 rgba(218,54,51,0)}}
.pl-empty{color:#484f58;font-size:12px;font-style:italic;padding:20px 0}

.detail-area{padding:14px 16px;overflow-y:auto;flex:1}
.detail-area h3{font-size:10px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
.dp-empty{color:#484f58;font-style:italic;font-size:12px;padding:8px 0}
.dp-desc{font-size:12px;color:#c9d1d9;margin-bottom:8px;line-height:1.5}
.tags{display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px}
.tag{padding:2px 7px;border-radius:9px;font-size:11px;font-family:'Consolas',monospace;border:1px solid}
.t-m{background:#0d2547;border-color:#1f6feb;color:#79c0ff}
.t-p{background:#1a1000;border-color:#d29922;color:#e3b341}
.t-i{background:#1f1235;border-color:#8957e5;color:#bc8cff}
.t-r{background:#0d2010;border-color:#238636;color:#3fb950}
.t-ok{background:#0d2010;border-color:#238636;color:#3fb950}
.t-bad{background:#2d0c0c;border-color:#da3633;color:#f85149}
.t-sa{background:#1a0f00;border-color:#d29922;color:#e3b341}
.reason{font-size:11px;font-family:'Consolas',monospace;padding:8px 10px;border-radius:4px;line-height:1.5;margin-bottom:6px}
.r-deny{background:#2d0c0c;border-left:3px solid #da3633;color:#f85149}
.r-allow{background:#0d2010;border-left:3px solid #238636;color:#3fb950}
.layer-txt{font-size:11px;color:#6e7681}

/* ── Terminal ── */
.term-wrap{flex-shrink:0;border-top:1px solid #21262d;display:flex;flex-direction:column;height:220px}
.term-bar{display:flex;align-items:center;gap:8px;padding:6px 14px;background:#0d1117;border-bottom:1px solid #21262d;flex-shrink:0}
.dots span{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:2px}
.d-r{background:#f85149}.d-y{background:#e3b341}.d-g{background:#3fb950}
.term-ttl{font-size:11px;color:#6e7681;font-family:'Consolas',monospace;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.run-badge{font-size:11px;font-weight:600;padding:2px 10px;border-radius:10px;border:1px solid}
.rb-idle{background:#21262d;color:#6e7681;border-color:#30363d}
.rb-run{background:#1a1000;color:#e3b341;border-color:#d29922;animation:blink .8s infinite}
.rb-ok{background:#1c4025;color:#3fb950;border-color:#238636}
.rb-ng{background:#3d1b1b;color:#f85149;border-color:#da3633}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.5}}
.term-body{padding:8px 14px;font-family:'Consolas','Monaco',monospace;font-size:12px;line-height:1.6;overflow-y:auto;flex:1}
.term-body::-webkit-scrollbar{width:4px}
.term-body::-webkit-scrollbar-thumb{background:#30363d;border-radius:2px}
.tl{display:block;white-space:pre-wrap;word-break:break-all}
.tl-cmd{color:#00b4d8}.tl-sep{color:#30363d}.tl-hdr{color:#f0f6fc;font-weight:700}
.tl-pass{color:#3fb950;font-weight:700}.tl-fail{color:#f85149;font-weight:700}
.tl-exp{color:#79c0ff}.tl-res{color:#e3b341}.tl-note{color:#d29922}
.tl-ok{color:#3fb950;border-top:1px solid #238636;margin-top:6px;padding-top:4px}
.tl-ng{color:#f85149;border-top:1px solid #da3633;margin-top:6px;padding-top:4px}
.tl-idle{color:#484f58;font-style:italic}
.tl-err{color:#f85149}

/* ── Bottom bar ── */
.bottom-bar{flex-shrink:0;background:#161b22;border-top:1px solid #21262d;padding:8px 14px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.bb-btn{display:inline-flex;align-items:center;gap:5px;padding:5px 11px;border-radius:5px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid #30363d;background:#0d1117;color:#8b949e;transition:all .15s}
.bb-btn:hover{border-color:#388bfd;color:#79c0ff;background:#0d1f38}
.bb-btn.bb-run{border-color:#d29922;color:#e3b341;background:#130f00}
.bb-btn.bb-ok{border-color:#238636;color:#3fb950;background:#0d2010}
.bb-btn.bb-ng{border-color:#da3633;color:#f85149;background:#2d0c0c}
.bb-sep{color:#30363d;font-size:14px}
.bb-ts{font-size:10px;color:#484f58;margin-left:auto}

.hidden{display:none!important}
</style>
</head>
<body>

<!-- ── Header ───────────────────────────────────────────────── -->
<div class="hdr">
  <div>
    <h1>⬡ ZTA Security Dashboard</h1>
    <div class="sub">NIST SP 800-207 · Keycloak + Istio + OPA</div>
  </div>
  <div class="stats">
    <div class="stat st-t"><div class="val" id="s-total">—</div><div class="lbl">Total</div></div>
    <div class="stat st-p"><div class="val" id="s-pass">—</div><div class="lbl">Pass</div></div>
    <div class="stat st-f"><div class="val" id="s-fail">—</div><div class="lbl">Fail</div></div>
  </div>
  <div class="svc-links">
    <a class="svc-btn svc-kc" href="http://localhost:8080" target="_blank">🔑 Keycloak</a>
    <a class="svc-btn svc-gf" href="http://localhost:3000" target="_blank">📊 Grafana</a>
    <a class="svc-btn svc-ki" href="http://localhost:20001" target="_blank">🕸️ Kiali</a>
  </div>
</div>

<!-- ── Offline banner ───────────────────────────────────────── -->
<div class="warn-banner hidden" id="offline-banner">
  ⚠ <strong>Server offline or make not found.</strong>
  &nbsp;Run <code>python3 visualizer/server.py</code> inside WSL, then open <code>http://localhost:5001</code>
  &nbsp;— Pipeline animation still works.
</div>

<!-- ── Main split ───────────────────────────────────────────── -->
<div class="split">

  <!-- LEFT: scenario selector -->
  <div class="left-panel">
    <div class="tabs" id="tabs">
      <div class="tab active" data-f="all">All <span class="cnt" id="cnt-all">—</span></div>
      <div class="tab" data-f="A">A·Lateral <span class="cnt" id="cnt-A">—</span></div>
      <div class="tab" data-f="B">B·JWT <span class="cnt" id="cnt-B">—</span></div>
      <div class="tab" data-f="C">C·Context <span class="cnt" id="cnt-C">—</span></div>
      <div class="tab" data-f="D">D·Claim <span class="cnt" id="cnt-D">—</span></div>
      <div class="tab" data-f="E">E·Posture <span class="cnt" id="cnt-E">—</span></div>
    </div>
    <div class="grid" id="grid"><div class="grid-empty">Loading…</div></div>
  </div>

  <!-- RIGHT: pipeline + detail -->
  <div class="right-panel">

    <div class="pipeline-area">
      <h2>
        <span>ZTA Security Pipeline</span>
        <span id="pl-type" style="font-size:10px;font-weight:400;color:#484f58">← click a scenario card</span>
      </h2>

      <!-- North-South -->
      <div id="pl-ns" class="pl-wrap">
        <div class="pl-node inactive" id="node-client"><div class="ico">💻</div><div class="lbl">Client</div><div class="sub">Attacker</div></div>
        <div class="pl-arrow" id="arr-ns-1">→</div>
        <div class="pl-node inactive" id="node-istio-jwt"><div class="ico">🔑</div><div class="lbl">Istio JWT</div><div class="sub">JWKS verify</div></div>
        <div class="pl-arrow" id="arr-ns-2">→</div>
        <div class="pl-node inactive" id="node-istio-deny"><div class="ico">🛡️</div><div class="lbl">Istio DENY</div><div class="sub">require-jwt</div></div>
        <div class="pl-arrow" id="arr-ns-3">→</div>
        <div class="pl-node inactive" id="node-opa"><div class="ico">⚖️</div><div class="lbl">OPA Policy</div><div class="sub">Rego eval</div></div>
        <div class="pl-arrow" id="arr-ns-4">→</div>
        <div class="pl-node inactive" id="node-app"><div class="ico">🖥️</div><div class="lbl">App</div><div class="sub">Flask service</div></div>
      </div>

      <!-- East-West -->
      <div id="pl-ew" class="pl-wrap hidden">
        <div class="pl-node inactive" id="node-rogue-pod"><div class="ico">☠️</div><div class="lbl">Rogue Pod</div><div class="sub">compromised</div></div>
        <div class="pl-arrow" id="arr-ew-1">→</div>
        <div class="pl-node inactive" id="node-mtls"><div class="ico">🔐</div><div class="lbl">mTLS</div><div class="sub">STRICT cert</div></div>
        <div class="pl-arrow" id="arr-ew-2">→</div>
        <div class="pl-node inactive" id="node-spiffe"><div class="ico">🪪</div><div class="lbl">SPIFFE</div><div class="sub">SA allowlist</div></div>
        <div class="pl-arrow" id="arr-ew-3">→</div>
        <div class="pl-node inactive" id="node-backend"><div class="ico">🖥️</div><div class="lbl">Backend</div><div class="sub">internal svc</div></div>
      </div>
    </div>

    <div class="detail-area" id="detail-area">
      <div class="dp-empty">← Click a scenario card to see the attack details and defense decision</div>
    </div>

  </div>
</div>

<!-- ── Terminal ─────────────────────────────────────────────── -->
<div class="term-wrap">
  <div class="term-bar">
    <div class="dots"><span class="d-r"></span><span class="d-y"></span><span class="d-g"></span></div>
    <span class="term-ttl" id="term-ttl">$ click a scenario card or workflow button to run live</span>
    <span class="run-badge rb-idle" id="run-badge">idle</span>
  </div>
  <div class="term-body" id="terminal">
    <span class="tl tl-idle">Waiting for command…</span>
  </div>
</div>

<!-- ── Bottom bar: workflow + quick commands ─────────────────── -->
<div class="bottom-bar" id="bottom-bar">
  <span style="font-size:10px;color:#6e7681;font-weight:600;text-transform:uppercase;letter-spacing:.5px">Workflow:</span>
  <div class="bb-btn" id="bb-all"      onclick="runWorkflow('all')">⬡ make all</div>
  <div class="bb-btn" id="bb-step1"    onclick="runWorkflow('step1')">🏗️ step1</div>
  <div class="bb-btn" id="bb-step2"    onclick="runWorkflow('step2')">🚀 step2</div>
  <div class="bb-btn" id="bb-step3"    onclick="runWorkflow('step3')">🛡️ step3</div>
  <div class="bb-btn" id="bb-step4"    onclick="runWorkflow('step4')">🔐 step4</div>
  <div class="bb-btn" id="bb-test-all" onclick="runWorkflow('test-all')">🧪 test-all</div>
  <div class="bb-sep">|</div>
  <div class="bb-btn" id="bb-ports"       onclick="runWorkflow('ports')">🔌 ports</div>
  <div class="bb-btn" id="bb-status"      onclick="runWorkflow('status')">📋 status</div>
  <div class="bb-btn" id="bb-jwt-refresh" onclick="runWorkflow('jwt-refresh')">🔄 jwt-refresh</div>
  <div class="bb-btn" id="bb-logs-pretty" onclick="runWorkflow('logs-pretty')">📜 opa-logs</div>
  <div class="bb-btn" id="bb-setup-viewer" onclick="runWorkflow('setup-viewer')">👥 add-viewer</div>
  <span class="bb-ts" id="bb-ts"></span>
</div>

<script>
// ── Inline metadata — always available, no server needed for animation ──────
const META = __META__;

const ARROW_MAP = {
  "istio-jwt":"arr-ns-1","istio-deny":"arr-ns-2","opa":"arr-ns-3","app":"arr-ns-4",
  "mtls":"arr-ew-1","spiffe":"arr-ew-2","backend":"arr-ew-3",
};

const MAKE_LABELS = {
  "A-NS-1":"test-block","A-NS-2":"test-pass","A-EW-1":"test-lateral-block",
  "A-EW-2":"test-lateral-sidecar","A-EW-3":"test-lateral-podip",
  "B-1":"test-fake","B-2":"test-jwt-tampered","B-4":"test-jwt-auto",
  "C-1":"test-context-user-get","C-2":"test-context-user-admin",
  "C-3":"test-context-user-post","C-4":"test-context-admin-post",
  "D-1":"test-jwt-admin-all","D-2":"test-jwt-viewer-read",
  "D-3":"test-jwt-viewer-admin","D-4":"test-jwt-viewer-post",
  "E-1":"test-posture-ok","E-2":"test-posture-block",
};

// ── State ────────────────────────────────────────────────────────────────────
let allTests = [];                          // from server (test results)
let metaMap  = Object.assign({}, META);     // always initialized from inline data
let filter   = "all", selectedId = null;
let activeSource = null, animBusy = false, runningId = null;

// ── Data load (test results only — metaMap never reset) ───────────────────
async function load() {
  try {
    const d = await fetch("/api/data").then(r => r.json());
    allTests = d.tests || [];
    if (d.meta) Object.assign(metaMap, d.meta);
    g("offline-banner").classList.add("hidden");
    g("bb-ts").textContent = "updated " + new Date().toLocaleTimeString();
  } catch(e) {
    g("offline-banner").classList.remove("hidden");
    g("bb-ts").textContent = "server offline";
  }
  renderStats();
  renderCounts();
  renderGrid();
}

function renderStats() {
  const pass = allTests.filter(t => t.status === "PASS").length;
  const fail = allTests.filter(t => t.status === "FAIL").length;
  g("s-total").textContent = allTests.length || "—";
  g("s-pass").textContent  = allTests.length ? pass : "—";
  g("s-fail").textContent  = allTests.length ? fail : "—";
}

function renderCounts() {
  ["all","A","B","C","D","E"].forEach(f => {
    const el = g("cnt-" + f);
    if (el) el.textContent = f === "all"
      ? Object.keys(META).length
      : Object.keys(META).filter(id => id.startsWith(f)).length;
  });
}

// ── Test grid ─────────────────────────────────────────────────────────────
function renderGrid() {
  const ids  = filter === "all"
    ? Object.keys(META)
    : Object.keys(META).filter(id => id.startsWith(filter));

  if (!ids.length) {
    g("grid").innerHTML = '<div class="grid-empty">No scenarios</div>';
    return;
  }

  g("grid").innerHTML = ids.map(id => {
    const m   = META[id];
    const t   = allTests.find(x => x.id === id);
    const status = runningId === id ? "running" : (t ? t.status.toLowerCase() : "unknown");
    const blk  = m.block_at;
    let bTag = "";
    if (status === "fail")        bTag = `<span class="bl-tag bl-fail">✗ FAIL</span>`;
    else if (!blk)                bTag = `<span class="bl-tag bl-allow">✓ ALLOW</span>`;
    else if (blk === "opa")       bTag = `<span class="bl-tag bl-opa">✗ OPA</span>`;
    else                          bTag = `<span class="bl-tag bl-istio">✗ Istio</span>`;

    const sel = selectedId === id ? " selected" : "";
    const run = runningId  === id ? " tc-run"   : "";
    const codes = t ? `${t.expect} → ${t.result}` : m.signals.method + " " + m.signals.path;

    return `<div class="tc${sel}${run}" onclick="pickTest('${id}')">
<div class="tid">${id}</div>
<div class="tname">${m.attacker_desc.substring(0,55)}${m.attacker_desc.length>55?"…":""}</div>
<div class="trow"><span class="codes">${codes}</span><span class="badge ${status}">${status==="running"?"▶…":(t?t.status:"—")}</span></div>
${bTag}
</div>`;
  }).join("");
}

g("tabs").addEventListener("click", e => {
  const tab = e.target.closest(".tab");
  if (!tab) return;
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  tab.classList.add("active");
  filter = tab.dataset.f;
  renderGrid();
});

// ── Pick scenario ─────────────────────────────────────────────────────────
function pickTest(id) {
  selectedId = id;
  const m = metaMap[id];
  if (!m) return;

  // Show correct pipeline
  const isEW = m.pipeline === "ew";
  g("pl-ns").classList.toggle("hidden",  isEW);
  g("pl-ew").classList.toggle("hidden", !isEW);
  g("pl-type").textContent = isEW ? "East-West (Lateral)" : "North-South";

  // Render detail
  renderDetail(id, m);

  // Animate pipeline
  resetPipeline(m.flow);
  if (!animBusy) animateFlow(m.flow, m.block_at);

  renderGrid();

  // Run make command (shows live output in terminal)
  runCmd(id);
}

// ── Detail pane ───────────────────────────────────────────────────────────
function renderDetail(id, m) {
  const sig = m.signals, tags = [];
  if (sig.method)   tags.push(`<span class="tag t-m">${sig.method}</span>`);
  if (sig.path)     tags.push(`<span class="tag t-p">${sig.path}</span>`);
  if (sig.identity) tags.push(`<span class="tag t-i">id:${sig.identity}</span>`);
  if (sig.role)     tags.push(`<span class="tag t-r">role:${sig.role}</span>`);
  if (sig.posture === "enabled")  tags.push(`<span class="tag t-ok">fw:enabled</span>`);
  if (sig.posture === "disabled") tags.push(`<span class="tag t-bad">fw:disabled</span>`);
  if (sig.sa)       tags.push(`<span class="tag t-sa">sa:${sig.sa}</span>`);

  const rc = m.block_at ? "r-deny" : "r-allow";
  const rp = m.block_at ? "✗ BLOCKED" : "✓ ALLOWED";

  g("detail-area").innerHTML = `
<h3>Attack Signals — ${id}</h3>
<div class="dp-desc">${m.attacker_desc}</div>
<div class="tags">${tags.join("")}</div>
<h3 style="margin-top:12px">Defense Decision</h3>
<div class="reason ${rc}">${rp}: ${m.block_reason}</div>
${m.defense_layer ? `<div class="layer-txt">Layer: <strong>${m.defense_layer}</strong></div>` : ""}
<div style="margin-top:12px;font-size:11px;color:#484f58">make target: <code style="color:#79c0ff">${MAKE_LABELS[id]||id}</code></div>`;
}

// ── Command runner ────────────────────────────────────────────────────────
function runCmd(id) {
  if (activeSource) { activeSource.close(); activeSource = null; }

  const label = MAKE_LABELS[id] || id;
  runningId = id;
  renderGrid();

  const badge = g("run-badge");
  const ttl   = g("term-ttl");
  badge.className   = "run-badge rb-run";
  badge.textContent = "▶ running";
  ttl.textContent   = `$ make --no-print-directory ${label}`;

  const term = g("terminal");
  term.innerHTML = `<span class="tl tl-cmd">$ make --no-print-directory ${label}</span>\n<span class="tl tl-sep">─────────────────────────────────────</span>\n`;

  const src = new EventSource(`/api/run/${id}`);
  activeSource = src;

  src.onmessage = ev => {
    const d = JSON.parse(ev.data);
    if (d.done) {
      src.close(); activeSource = null; runningId = null;
      const ok = d.status === "PASS";
      badge.className   = ok ? "run-badge rb-ok" : "run-badge rb-ng";
      badge.textContent = ok ? "✓ PASS" : "✗ FAIL";
      appendLine("─────────────────────────────────────", "tl-sep");
      appendLine(`Exit: ${d.status}  (code ${d.exit_code})`, ok ? "tl-ok" : "tl-ng");
      // Update test status in allTests
      let t = allTests.find(x => x.id === id);
      if (!t) { t = {id, scenario: id.split("-")[0]}; allTests.push(t); }
      t.status = d.status;
      renderGrid();
      renderStats();
      return;
    }
    appendLine(d.line);
    term.scrollTop = term.scrollHeight;
  };

  src.onerror = () => {
    if (activeSource) { activeSource.close(); activeSource = null; }
    runningId = null;
    badge.className   = "run-badge rb-idle";
    badge.textContent = "idle";
    appendLine("⚠ Cannot reach server — is python3 visualizer/server.py running in WSL?", "tl-err");
    term.scrollTop = term.scrollHeight;
    renderGrid();
  };
}

function runWorkflow(id) {
  setBbState(id, "run");
  runCmd(id);
  // restore bb state when done (listen for badge change)
  const observer = new MutationObserver(() => {
    const badge = g("run-badge");
    if (!badge.classList.contains("rb-run")) {
      const ok = badge.classList.contains("rb-ok");
      setBbState(id, ok ? "ok" : "ng");
      observer.disconnect();
    }
  });
  observer.observe(g("run-badge"), {attributes: true, attributeFilter: ["class"]});
}

function setBbState(id, state) {
  const el = g("bb-" + id); if (!el) return;
  el.classList.remove("bb-run","bb-ok","bb-ng");
  if (state) el.classList.add("bb-" + state);
}

// ── Terminal helpers ──────────────────────────────────────────────────────
function appendLine(text, cls) {
  const term = g("terminal");
  const s = document.createElement("span");
  s.className = "tl " + (cls || lineClass(text));
  s.textContent = text;
  term.appendChild(s);
  term.appendChild(document.createTextNode("\n"));
  term.scrollTop = term.scrollHeight;
}

function lineClass(l) {
  if (!l) return "";
  if (l.includes("STATUS: PASS")) return "tl-pass";
  if (l.includes("STATUS: FAIL")) return "tl-fail";
  if (/^EXPECT:/.test(l))         return "tl-exp";
  if (/^RESULT:/.test(l))         return "tl-res";
  if (/^\[.+\]/.test(l))          return "tl-hdr";
  if (/^={3,}|^-{3,}/.test(l))    return "tl-sep";
  if (/^>>>/.test(l))             return "tl-hdr";
  if (/^(NOTE|WARNING):/.test(l)) return "tl-note";
  if (l.includes("SCENARIO") && l.includes("PASS")) return "tl-pass";
  if (l.includes("SCENARIO") && l.includes("FAIL")) return "tl-fail";
  return "";
}

// ── Pipeline animation ────────────────────────────────────────────────────
function resetPipeline(flow) {
  flow.forEach(id => {
    const el = g("node-" + id);
    if (el) el.className = "pl-node inactive";
  });
  Object.values(ARROW_MAP).forEach(id => {
    const el = g(id);
    if (el) el.className = "pl-arrow";
  });
}

async function animateFlow(flow, blockAt) {
  animBusy = true;
  for (let i = 0; i < flow.length; i++) {
    const nid = flow[i];
    const el  = g("node-" + nid);
    if (!el) continue;
    await wait(300);
    if (i > 0) {
      const arr = g(ARROW_MAP[nid]);
      if (arr) arr.className = "pl-arrow " + (nid === blockAt ? "blocked" : "passed");
    }
    if (nid === blockAt) {
      el.className = "pl-node blocked";
      flow.slice(i + 1).forEach(id => {
        const e = g("node-" + id);
        if (e) e.className = "pl-node unreachable";
      });
      break;
    } else {
      el.className = i === flow.length - 1 ? "pl-node allowed" : "pl-node passed";
    }
  }
  animBusy = false;
}

const g    = id => document.getElementById(id);
const wait = ms => new Promise(r => setTimeout(r, ms));

// ── Init ──────────────────────────────────────────────────────────────────
renderCounts();  // always works (uses META)
renderGrid();    // shows cards even before server responds
load();
setInterval(load, 30000);
</script>
</body>
</html>"""


_cached_html = None


def build_html():
    return HTML_TMPL.replace("__META__", json.dumps(TEST_META, ensure_ascii=False))


def get_html():
    global _cached_html
    if _cached_html is None:
        _cached_html = build_html().encode()
    return _cached_html


# ── HTTP Handler ───────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            body = get_html()
            self.send_response(200)
            self.send_header("Content-Type",   "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/api/data":
            payload = {
                "tests":    parse_test_summary(),
                "meta":     TEST_META,
                "opa_logs": parse_opa_logs(),
            }
            body = json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type",                "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length",              str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path.startswith("/api/run/"):
            self._sse(path[9:])

        else:
            self.send_error(404)

    def _sse(self, cmd_id):
        target = RUNNABLE.get(cmd_id)
        if not target:
            self.send_error(404, f"Unknown command: {cmd_id}")
            return

        self.send_response(200)
        self.send_header("Content-Type",                "text/event-stream")
        self.send_header("Cache-Control",               "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        def emit(payload):
            try:
                self.wfile.write(f"data: {json.dumps(payload)}\n\n".encode())
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                raise

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
            emit({"line": "ERROR: 'make' not found — run this server from WSL, not Windows PowerShell"})
            emit({"line": "  In WSL: cd /mnt/c/Users/dksal/zta-project && python3 visualizer/server.py"})
            emit({"done": True, "status": "FAIL", "exit_code": 127})
        except Exception as e:
            emit({"line": f"ERROR: {e}"})
            emit({"done": True, "status": "FAIL", "exit_code": 1})

    def log_message(self, fmt, *args):
        pass


# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"ZTA Dashboard  →  http://localhost:{PORT}")
    print(f"Project root   :  {BASE}")
    print("NOTE: run from WSL for 'make' commands to work")
    print("Ctrl+C to stop\n")
    try:
        server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
