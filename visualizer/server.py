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
    "A-NS-1": "test-block",         "A-NS-2": "test-pass",
    "A-EW-1": "test-lateral-block", "A-EW-2": "test-lateral-sidecar",
    "A-EW-3": "test-lateral-podip", "B-1":    "test-fake",
    "B-2":    "test-jwt-tampered",  "B-4":    "test-jwt-auto",
    "C-1":    "test-context-user-get","C-2":   "test-context-user-admin",
    "C-3":    "test-context-user-post","C-4":  "test-context-admin-post",
    "D-1":    "test-jwt-admin-all", "D-2":    "test-jwt-viewer-read",
    "D-3":    "test-jwt-viewer-admin","D-4":  "test-jwt-viewer-post",
    "E-1":    "test-posture-ok",    "E-2":    "test-posture-block",
}

TEST_META = {
    "A-NS-1": {
        "title": "No identity deny",
        "desc": "External client — no JWT, no role header",
        "signals": {"method":"GET","path":"/api/admin","identity":"none"},
        "pipeline": "ns",
        "flow": ["client","istio-jwt","istio-deny","opa","app"],
        "block_at": "istio-deny",
        "block_reason": "require-jwt AuthorizationPolicy: notRequestPrincipals -> DENY 403",
        "defense_layer": "Istio Authorization Policy",
        "make": "test-block"
    },
    "A-NS-2": {
        "title": "role:admin header allow",
        "desc": "Client sets role=admin HTTP header (demo scaffolding)",
        "signals": {"method":"GET","path":"/api/admin","identity":"header","role":"admin"},
        "pipeline": "ns",
        "flow": ["client","istio-jwt","istio-deny","opa","app"],
        "block_at": None,
        "block_reason": "OPA header rule: role=admin -> ALLOW 200 (demo path)",
        "defense_layer": None,
        "make": "test-pass"
    },
    "A-EW-1": {
        "title": "Rogue pod (no sidecar)",
        "desc": "Compromised pod launched without Istio sidecar",
        "signals": {"method":"GET","path":"/","identity":"none","source":"no-sidecar"},
        "pipeline": "ew",
        "flow": ["rogue-pod","mtls","spiffe","backend"],
        "block_at": "mtls",
        "block_reason": "mTLS STRICT: no client certificate -> TLS fails 403/503",
        "defense_layer": "Istio mTLS STRICT",
        "make": "test-lateral-block"
    },
    "A-EW-2": {
        "title": "Wrong ServiceAccount deny",
        "desc": "Pod has sidecar but uses backend-sa; allowlist needs frontend-sa",
        "signals": {"method":"GET","path":"/","identity":"spiffe","sa":"backend-sa"},
        "pipeline": "ew",
        "flow": ["rogue-pod","mtls","spiffe","backend"],
        "block_at": "spiffe",
        "block_reason": "SPIFFE allowlist: backend-sa != frontend-sa -> DENY 403",
        "defense_layer": "Istio SPIFFE Allowlist",
        "make": "test-lateral-sidecar"
    },
    "A-EW-3": {
        "title": "Pod IP bypass deny",
        "desc": "Rogue pod targets backend podIP:8080 directly",
        "signals": {"method":"GET","path":"/","identity":"none","target":"podIP:8080"},
        "pipeline": "ew",
        "flow": ["rogue-pod","mtls","spiffe","backend"],
        "block_at": "mtls",
        "block_reason": "Inbound Envoy enforces policy even via pod IP -> 503",
        "defense_layer": "Istio Inbound Policy",
        "make": "test-lateral-podip"
    },
    "B-1": {
        "title": "Forged JWT reject",
        "desc": "JWT crafted with attacker's key — signature invalid",
        "signals": {"method":"GET","path":"/api/admin","identity":"JWT-forged"},
        "pipeline": "ns",
        "flow": ["client","istio-jwt","istio-deny","opa","app"],
        "block_at": "istio-jwt",
        "block_reason": "Istio JWKS verify: RSA sig invalid -> no principal -> DENY 403",
        "defense_layer": "Istio JWT Auth (JWKS)",
        "make": "test-fake"
    },
    "B-2": {
        "title": "Tampered JWT reject",
        "desc": "Real JWT payload modified (added admin), original signature kept",
        "signals": {"method":"GET","path":"/api/admin","identity":"JWT-tampered"},
        "pipeline": "ns",
        "flow": ["client","istio-jwt","istio-deny","opa","app"],
        "block_at": "istio-jwt",
        "block_reason": "RSA verify: new payload hash != original signature -> 401",
        "defense_layer": "Istio JWT Auth (RSA verify)",
        "make": "test-jwt-tampered"
    },
    "B-4": {
        "title": "Valid Keycloak JWT allow",
        "desc": "testuser obtains valid Keycloak JWT",
        "signals": {"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"admin"},
        "pipeline": "ns",
        "flow": ["client","istio-jwt","istio-deny","opa","app"],
        "block_at": None,
        "block_reason": "JWKS OK -> principal OK -> OPA admin role OK -> 200",
        "defense_layer": None,
        "make": "test-jwt-auto"
    },
    "C-1": {
        "title": "user GET /api/data allow",
        "desc": "role=user reads the general data endpoint",
        "signals": {"method":"GET","path":"/api/data","identity":"header","role":"user"},
        "pipeline": "ns",
        "flow": ["client","istio-jwt","istio-deny","opa","app"],
        "block_at": None,
        "block_reason": "OPA: role=user + GET + non-admin path -> ALLOW 200",
        "defense_layer": None,
        "make": "test-context-user-get"
    },
    "C-2": {
        "title": "user GET /api/admin deny",
        "desc": "role=user requests admin endpoint",
        "signals": {"method":"GET","path":"/api/admin","identity":"header","role":"user"},
        "pipeline": "ns",
        "flow": ["client","istio-jwt","istio-deny","opa","app"],
        "block_at": "opa",
        "block_reason": "OPA: role=user + path=/api/admin -> DENY 403",
        "defense_layer": "OPA Context Policy (role+path)",
        "make": "test-context-user-admin"
    },
    "C-3": {
        "title": "user POST /api/write deny",
        "desc": "role=user attempts POST — write requires admin",
        "signals": {"method":"POST","path":"/api/write","identity":"header","role":"user"},
        "pipeline": "ns",
        "flow": ["client","istio-jwt","istio-deny","opa","app"],
        "block_at": "opa",
        "block_reason": "OPA: role=user + method=POST -> DENY 403",
        "defense_layer": "OPA Context Policy (role+method)",
        "make": "test-context-user-post"
    },
    "C-4": {
        "title": "admin POST /api/write allow",
        "desc": "Admin user performing authorized write",
        "signals": {"method":"POST","path":"/api/write","identity":"header","role":"admin"},
        "pipeline": "ns",
        "flow": ["client","istio-jwt","istio-deny","opa","app"],
        "block_at": None,
        "block_reason": "OPA: role=admin + device_posture_ok -> ALLOW 200",
        "defense_layer": None,
        "make": "test-context-admin-post"
    },
    "D-1": {
        "title": "admin JWT /api/admin allow",
        "desc": "Keycloak JWT with realm_access.roles=[admin]",
        "signals": {"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"admin"},
        "pipeline": "ns",
        "flow": ["client","istio-jwt","istio-deny","opa","app"],
        "block_at": None,
        "block_reason": "OPA jwt_has_role(admin) + device_posture_ok -> ALLOW 200",
        "defense_layer": None,
        "make": "test-jwt-admin-all"
    },
    "D-2": {
        "title": "viewer JWT /api/data allow",
        "desc": "vieweruser Keycloak JWT with roles=[viewer]",
        "signals": {"method":"GET","path":"/api/data","identity":"JWT-valid","role":"viewer"},
        "pipeline": "ns",
        "flow": ["client","istio-jwt","istio-deny","opa","app"],
        "block_at": None,
        "block_reason": "OPA jwt_has_role(viewer) + GET + non-admin -> ALLOW 200",
        "defense_layer": None,
        "make": "test-jwt-viewer-read"
    },
    "D-3": {
        "title": "viewer JWT /api/admin deny",
        "desc": "vieweruser JWT tries admin path",
        "signals": {"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"viewer"},
        "pipeline": "ns",
        "flow": ["client","istio-jwt","istio-deny","opa","app"],
        "block_at": "opa",
        "block_reason": "OPA: jwt_has_role(viewer) + /api/admin -> DENY 403",
        "defense_layer": "OPA JWT Claim Policy",
        "make": "test-jwt-viewer-admin"
    },
    "D-4": {
        "title": "viewer JWT POST deny",
        "desc": "vieweruser JWT attempts POST — viewer is read-only",
        "signals": {"method":"POST","path":"/api/write","identity":"JWT-valid","role":"viewer"},
        "pipeline": "ns",
        "flow": ["client","istio-jwt","istio-deny","opa","app"],
        "block_at": "opa",
        "block_reason": "OPA: jwt_has_role(viewer) + POST -> DENY 403",
        "defense_layer": "OPA JWT Claim Policy",
        "make": "test-jwt-viewer-post"
    },
    "E-1": {
        "title": "Posture enabled allow",
        "desc": "Admin JWT + X-Device-Firewall: enabled",
        "signals": {"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"admin","posture":"enabled"},
        "pipeline": "ns",
        "flow": ["client","istio-jwt","istio-deny","opa","app"],
        "block_at": None,
        "block_reason": "OPA device_posture_ok: firewall=enabled -> ALLOW 200",
        "defense_layer": None,
        "make": "test-posture-ok"
    },
    "E-2": {
        "title": "Posture disabled deny",
        "desc": "Stolen admin JWT but device unhealthy (firewall: disabled)",
        "signals": {"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"admin","posture":"disabled"},
        "pipeline": "ns",
        "flow": ["client","istio-jwt","istio-deny","opa","app"],
        "block_at": "opa",
        "block_reason": "OPA device_posture_ok: firewall=disabled -> DENY 403",
        "defense_layer": "OPA Device Posture Policy",
        "make": "test-posture-block"
    },
}


def parse_test_summary():
    path = BASE / ".test-summary.log"
    tests = {}
    if not path.exists():
        return tests
    for line in path.read_text(errors="replace").splitlines():
        parts = line.strip().split("|")
        if len(parts) < 4:
            continue
        name_full = parts[0].strip()
        idx = name_full.find(" ")
        tid = name_full[:idx] if idx > 0 else name_full
        tests[tid] = {
            "id":     tid,
            "expect": parts[1].strip(),
            "result": parts[2].strip(),
            "status": parts[3].strip(),
        }
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
        })
    return logs[-50:]


# ── HTML (data injected via JSON script tag — 100% reliable) ──────────────
def build_html():
    meta_json = json.dumps(TEST_META, ensure_ascii=False)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ZTA Security Dashboard</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;height:100vh;display:flex;flex-direction:column;overflow:hidden}}

/* header */
.hdr{{background:#161b22;border-bottom:1px solid #21262d;padding:10px 20px;display:flex;align-items:center;gap:16px;flex-shrink:0;flex-wrap:wrap}}
.hdr-title h1{{font-size:15px;font-weight:700;color:#f0f6fc}}
.hdr-title .sub{{font-size:11px;color:#6e7681;margin-top:1px}}
.stats{{display:flex;gap:16px}}
.stat .val{{font-size:20px;font-weight:700;line-height:1}}
.stat .lbl{{font-size:10px;color:#6e7681;text-transform:uppercase;letter-spacing:.4px}}
.st-t .val{{color:#79c0ff}}.st-p .val{{color:#3fb950}}.st-f .val{{color:#f85149}}
.svc-links{{display:flex;gap:6px;margin-left:auto}}
.svc-btn{{display:inline-flex;align-items:center;gap:5px;padding:5px 11px;border-radius:5px;font-size:12px;font-weight:600;text-decoration:none;border:1px solid;transition:opacity .15s}}
.svc-btn:hover{{opacity:.75}}
.svc-kc{{background:#1a1000;color:#e3b341;border-color:#d29922}}
.svc-gf{{background:#1a0e00;color:#f89040;border-color:#d26911}}
.svc-ki{{background:#0d1f38;color:#79c0ff;border-color:#388bfd}}

/* offline banner */
.warn{{background:#2d1b00;border-bottom:1px solid #d29922;padding:6px 20px;font-size:12px;color:#e3b341;flex-shrink:0}}
.warn.hidden{{display:none}}

/* split layout */
.split{{display:flex;flex:1;overflow:hidden;min-height:0}}
.left{{width:340px;min-width:280px;flex-shrink:0;display:flex;flex-direction:column;border-right:1px solid #21262d;background:#0d1117}}
.right{{flex:1;display:flex;flex-direction:column;overflow:hidden;background:#0d1117}}

/* tabs */
.tabs{{display:flex;background:#161b22;border-bottom:1px solid #21262d;flex-shrink:0;overflow-x:auto}}
.tabs::-webkit-scrollbar{{height:2px}}
.tabs::-webkit-scrollbar-thumb{{background:#30363d}}
.tab{{padding:9px 10px;font-size:11px;font-weight:500;color:#6e7681;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap;user-select:none}}
.tab:hover{{color:#e6edf3;background:#0d1117}}
.tab.active{{color:#f0f6fc;border-bottom-color:#388bfd}}
.tab .cnt{{background:#21262d;color:#6e7681;font-size:10px;padding:1px 5px;border-radius:6px;margin-left:3px}}
.tab.active .cnt{{background:#1f3a6e;color:#79c0ff}}

/* test cards */
.cards{{flex:1;overflow-y:auto;padding:10px}}
.cards::-webkit-scrollbar{{width:4px}}
.cards::-webkit-scrollbar-thumb{{background:#21262d;border-radius:2px}}
.tc{{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:11px 12px;cursor:pointer;margin-bottom:8px;transition:border-color .15s,background .15s;position:relative}}
.tc:hover{{border-color:#388bfd;background:#0d1f38}}
.tc.sel{{border-color:#388bfd;background:#0d1f38;box-shadow:inset 0 0 0 1px #388bfd44}}
.tc.running{{border-color:#d29922;background:#130f00}}
.tc .tid{{font-size:10px;font-weight:700;font-family:monospace;color:#484f58;margin-bottom:3px}}
.tc .ttitle{{font-size:12px;font-weight:600;color:#e6edf3;margin-bottom:4px}}
.tc .tdesc{{font-size:11px;color:#8b949e;line-height:1.4;margin-bottom:7px}}
.tc-row{{display:flex;align-items:center;justify-content:space-between;gap:6px}}
.badge{{padding:2px 7px;border-radius:8px;font-size:10px;font-weight:700;border:1px solid}}
.b-pass{{background:#1c4025;color:#3fb950;border-color:#238636}}
.b-fail{{background:#3d1b1b;color:#f85149;border-color:#da3633}}
.b-run{{background:#1a1000;color:#e3b341;border-color:#d29922}}
.b-unknown{{background:#21262d;color:#6e7681;border-color:#30363d}}
.blk-tag{{font-size:10px;padding:1px 6px;border-radius:3px;border:1px solid;font-family:monospace}}
.blk-istio{{background:#1a0f28;color:#a371f7;border-color:#6e40c9}}
.blk-opa{{background:#0d1f30;color:#56b6c2;border-color:#00b4d8}}
.blk-allow{{background:#0d2010;color:#3fb950;border-color:#238636}}
.blk-fail{{background:#3d1b1b;color:#f85149;border-color:#da3633}}
.no-cards{{padding:24px;text-align:center;color:#484f58;font-size:12px;font-style:italic}}

/* pipeline */
.pipeline-wrap{{padding:16px 20px;border-bottom:1px solid #21262d;flex-shrink:0}}
.pipeline-hdr{{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}}
.pipeline-hdr h2{{font-size:11px;font-weight:600;color:#6e7681;text-transform:uppercase;letter-spacing:.7px}}
.pipeline-dir{{font-size:11px;color:#388bfd;font-weight:500}}
.pl-row{{display:flex;align-items:center;gap:0;flex-wrap:nowrap;overflow-x:auto;padding:2px 0}}
.pl-row::-webkit-scrollbar{{height:3px}}
.pl-row::-webkit-scrollbar-thumb{{background:#30363d}}
.pl-node{{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:4px;min-width:100px;padding:12px 8px;border:2px solid #30363d;border-radius:8px;background:#0d1117;transition:border-color .2s,background .2s,opacity .2s;flex-shrink:0}}
.pl-node .ni{{font-size:22px;line-height:1}}
.pl-node .nl{{font-size:11px;font-weight:700;text-align:center;color:#6e7681;transition:color .2s}}
.pl-node .ns{{font-size:9px;text-align:center;color:#484f58;line-height:1.3}}
.pl-arr{{padding:0 6px;font-size:16px;color:#30363d;flex-shrink:0;transition:color .2s;user-select:none}}
/* node states */
.pl-node.inactive{{opacity:.25}}
.pl-node.active{{border-color:#388bfd;background:#0b1c36}}.pl-node.active .nl{{color:#79c0ff}}
.pl-node.passed{{border-color:#238636;background:#0a1f12}}.pl-node.passed .nl{{color:#3fb950}}
.pl-node.allowed{{border-color:#238636;background:#0a1f12}}.pl-node.allowed .nl{{color:#3fb950}}
.pl-node.blocked{{border-color:#da3633;background:#2a0c0c;animation:redpulse .9s ease 4}}.pl-node.blocked .nl{{color:#f85149}}
.pl-node.unreachable{{opacity:.1}}
.pl-arr.ok{{color:#238636}}.pl-arr.blocked{{color:#21262d}}
@keyframes redpulse{{0%{{box-shadow:0 0 0 0 rgba(218,54,51,.6)}}70%{{box-shadow:0 0 0 10px rgba(218,54,51,0)}}100%{{box-shadow:0 0 0 0 rgba(218,54,51,0)}}}}

/* detail pane */
.detail{{flex:1;overflow-y:auto;padding:16px 20px}}
.detail::-webkit-scrollbar{{width:4px}}
.detail::-webkit-scrollbar-thumb{{background:#21262d;border-radius:2px}}
.detail-empty{{color:#484f58;font-size:12px;font-style:italic;padding:8px 0}}
.dl-sec{{font-size:10px;font-weight:600;color:#6e7681;text-transform:uppercase;letter-spacing:.5px;margin-bottom:7px}}
.dl-desc{{font-size:12px;color:#c9d1d9;line-height:1.5;margin-bottom:10px}}
.tags{{display:flex;flex-wrap:wrap;gap:5px;margin-bottom:12px}}
.tag{{padding:3px 8px;border-radius:10px;font-size:11px;font-family:monospace;border:1px solid}}
.t-m{{background:#0d2547;border-color:#1f6feb;color:#79c0ff}}
.t-p{{background:#1a1000;border-color:#d29922;color:#e3b341}}
.t-i{{background:#1f1235;border-color:#8957e5;color:#bc8cff}}
.t-r{{background:#0d2010;border-color:#238636;color:#3fb950}}
.t-ok{{background:#0d2010;border-color:#238636;color:#3fb950}}
.t-bad{{background:#2d0c0c;border-color:#da3633;color:#f85149}}
.t-sa{{background:#1a0f00;border-color:#d29922;color:#e3b341}}
.verdict{{font-size:12px;font-family:monospace;padding:10px 12px;border-radius:5px;line-height:1.5;margin-bottom:6px;word-break:break-word}}
.v-deny{{background:#2a0c0c;border-left:3px solid #da3633;color:#ffa198}}
.v-allow{{background:#0a1f12;border-left:3px solid #238636;color:#7ee787}}
.dl-layer{{font-size:11px;color:#6e7681;margin-top:4px}}
.dl-make{{font-size:11px;color:#484f58;margin-top:10px}}

/* terminal */
.term-wrap{{border-top:1px solid #21262d;flex-shrink:0;display:flex;flex-direction:column;height:200px}}
.term-bar{{display:flex;align-items:center;gap:8px;padding:6px 14px;background:#161b22;border-bottom:1px solid #21262d;flex-shrink:0}}
.dots span{{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:2px}}
.d-r{{background:#f85149}}.d-y{{background:#e3b341}}.d-g{{background:#3fb950}}
.term-ttl{{font-size:11px;color:#6e7681;font-family:monospace;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.rbadge{{font-size:11px;font-weight:600;padding:2px 9px;border-radius:9px;border:1px solid}}
.rb-idle{{background:#21262d;color:#6e7681;border-color:#30363d}}
.rb-run{{background:#1a1000;color:#e3b341;border-color:#d29922;animation:blink .9s infinite}}
.rb-ok{{background:#1c4025;color:#3fb950;border-color:#238636}}
.rb-ng{{background:#3d1b1b;color:#f85149;border-color:#da3633}}
@keyframes blink{{0%,100%{{opacity:1}}50%{{opacity:.4}}}}
.term-body{{flex:1;overflow-y:auto;padding:8px 14px;font-family:monospace;font-size:12px;line-height:1.6}}
.term-body::-webkit-scrollbar{{width:4px}}
.term-body::-webkit-scrollbar-thumb{{background:#30363d;border-radius:2px}}
.tl{{display:block;white-space:pre-wrap;word-break:break-all}}
.tc-pass{{color:#3fb950;font-weight:700}}.tc-fail{{color:#f85149;font-weight:700}}
.tc-exp{{color:#79c0ff}}.tc-res{{color:#e3b341}}.tc-hdr{{color:#f0f6fc;font-weight:700}}
.tc-sep{{color:#30363d}}.tc-note{{color:#d29922}}.tc-err{{color:#f85149}}
.tc-ok{{color:#3fb950;border-top:1px solid #238636;margin-top:5px;padding-top:4px}}
.tc-ng{{color:#f85149;border-top:1px solid #da3633;margin-top:5px;padding-top:4px}}
.tc-idle{{color:#484f58;font-style:italic}}

/* bottom bar */
.bot{{background:#161b22;border-top:1px solid #21262d;padding:7px 14px;display:flex;align-items:center;gap:6px;flex-shrink:0;flex-wrap:wrap}}
.bot-lbl{{font-size:10px;color:#484f58;font-weight:600;text-transform:uppercase;letter-spacing:.4px;white-space:nowrap}}
.bot-sep{{color:#30363d}}
.bb{{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid #30363d;border-radius:5px;background:#0d1117;color:#8b949e;transition:all .15s;white-space:nowrap}}
.bb:hover{{border-color:#388bfd;color:#79c0ff;background:#0b1c36}}
.bb.bb-run{{border-color:#d29922;color:#e3b341;background:#130f00}}
.bb.bb-ok{{border-color:#238636;color:#3fb950;background:#0a1f12}}
.bb.bb-ng{{border-color:#da3633;color:#f85149;background:#2a0c0c}}
.bot-ts{{font-size:10px;color:#484f58;margin-left:auto}}

.hidden{{display:none!important}}
</style>
</head>
<body>

<!-- header -->
<div class="hdr">
  <div class="hdr-title">
    <h1>&#x2B21; ZTA Security Dashboard</h1>
    <div class="sub">NIST SP 800-207 &middot; Keycloak + Istio + OPA</div>
  </div>
  <div class="stats">
    <div class="stat st-t"><div class="val" id="s-total">0</div><div class="lbl">Total</div></div>
    <div class="stat st-p"><div class="val" id="s-pass">0</div><div class="lbl">Pass</div></div>
    <div class="stat st-f"><div class="val" id="s-fail">0</div><div class="lbl">Fail</div></div>
  </div>
  <div class="svc-links">
    <a class="svc-btn svc-kc" href="http://localhost:8080" target="_blank">&#x1F511; Keycloak</a>
    <a class="svc-btn svc-gf" href="http://localhost:3000" target="_blank">&#x1F4CA; Grafana</a>
    <a class="svc-btn svc-ki" href="http://localhost:20001" target="_blank">&#x1F578;&#xFE0F; Kiali</a>
  </div>
</div>

<!-- offline warning -->
<div class="warn hidden" id="warn">
  &#x26A0; Server offline — animation works, but <code>make</code> requires WSL:
  &nbsp;<code>python3 visualizer/server.py</code> inside WSL, then open <code>http://localhost:5001</code>
</div>

<!-- split -->
<div class="split">

  <!-- LEFT: scenario list -->
  <div class="left">
    <div class="tabs" id="tabs">
      <div class="tab active" data-f="all">All <span class="cnt" id="cnt-all">18</span></div>
      <div class="tab" data-f="A">A-Lateral <span class="cnt" id="cnt-A">5</span></div>
      <div class="tab" data-f="B">B-JWT <span class="cnt" id="cnt-B">3</span></div>
      <div class="tab" data-f="C">C-Context <span class="cnt" id="cnt-C">4</span></div>
      <div class="tab" data-f="D">D-Claim <span class="cnt" id="cnt-D">4</span></div>
      <div class="tab" data-f="E">E-Posture <span class="cnt" id="cnt-E">2</span></div>
    </div>
    <div class="cards" id="cards"></div>
  </div>

  <!-- RIGHT: pipeline + detail -->
  <div class="right">

    <div class="pipeline-wrap">
      <div class="pipeline-hdr">
        <h2>ZTA Security Pipeline</h2>
        <span class="pipeline-dir hidden" id="pl-dir"></span>
      </div>

      <!-- North-South -->
      <div class="pl-row" id="pl-ns">
        <div class="pl-node inactive" id="node-client">
          <div class="ni">&#x1F4BB;</div><div class="nl">Client</div><div class="ns">Attacker</div>
        </div>
        <div class="pl-arr" id="arr-ns-1">&#x2192;</div>
        <div class="pl-node inactive" id="node-istio-jwt">
          <div class="ni">&#x1F511;</div><div class="nl">Istio JWT</div><div class="ns">JWKS verify</div>
        </div>
        <div class="pl-arr" id="arr-ns-2">&#x2192;</div>
        <div class="pl-node inactive" id="node-istio-deny">
          <div class="ni">&#x1F6E1;&#xFE0F;</div><div class="nl">Istio DENY</div><div class="ns">require-jwt</div>
        </div>
        <div class="pl-arr" id="arr-ns-3">&#x2192;</div>
        <div class="pl-node inactive" id="node-opa">
          <div class="ni">&#x2696;&#xFE0F;</div><div class="nl">OPA Policy</div><div class="ns">Rego eval</div>
        </div>
        <div class="pl-arr" id="arr-ns-4">&#x2192;</div>
        <div class="pl-node inactive" id="node-app">
          <div class="ni">&#x1F5A5;&#xFE0F;</div><div class="nl">App</div><div class="ns">Flask svc</div>
        </div>
      </div>

      <!-- East-West -->
      <div class="pl-row hidden" id="pl-ew">
        <div class="pl-node inactive" id="node-rogue-pod">
          <div class="ni">&#x2620;&#xFE0F;</div><div class="nl">Rogue Pod</div><div class="ns">compromised</div>
        </div>
        <div class="pl-arr" id="arr-ew-1">&#x2192;</div>
        <div class="pl-node inactive" id="node-mtls">
          <div class="ni">&#x1F510;</div><div class="nl">mTLS</div><div class="ns">STRICT cert</div>
        </div>
        <div class="pl-arr" id="arr-ew-2">&#x2192;</div>
        <div class="pl-node inactive" id="node-spiffe">
          <div class="ni">&#x1FAAA;</div><div class="nl">SPIFFE</div><div class="ns">SA allowlist</div>
        </div>
        <div class="pl-arr" id="arr-ew-3">&#x2192;</div>
        <div class="pl-node inactive" id="node-backend">
          <div class="ni">&#x1F5A5;&#xFE0F;</div><div class="nl">Backend</div><div class="ns">internal svc</div>
        </div>
      </div>
    </div>

    <div class="detail" id="detail">
      <div class="detail-empty">&#x2190; Click a scenario card to see the attack and defense details</div>
    </div>

  </div>
</div>

<!-- terminal -->
<div class="term-wrap">
  <div class="term-bar">
    <div class="dots"><span class="d-r"></span><span class="d-y"></span><span class="d-g"></span></div>
    <span class="term-ttl" id="term-ttl">$ click a scenario card or workflow button to run</span>
    <span class="rbadge rb-idle" id="rbadge">idle</span>
  </div>
  <div class="term-body" id="term">
    <span class="tl tc-idle">Waiting for command...</span>
  </div>
</div>

<!-- bottom bar -->
<div class="bot">
  <span class="bot-lbl">Workflow</span>
  <div class="bb" id="bb-all"      onclick="runW('all')">&#x2B21; all</div>
  <div class="bb" id="bb-step1"    onclick="runW('step1')">&#x1F3D7; step1</div>
  <div class="bb" id="bb-step2"    onclick="runW('step2')">&#x1F680; step2</div>
  <div class="bb" id="bb-step3"    onclick="runW('step3')">&#x1F6E1; step3</div>
  <div class="bb" id="bb-step4"    onclick="runW('step4')">&#x1F510; step4</div>
  <div class="bb" id="bb-test-all" onclick="runW('test-all')">&#x1F9EA; test-all</div>
  <span class="bot-sep">|</span>
  <div class="bb" id="bb-ports"        onclick="runW('ports')">&#x1F50C; ports</div>
  <div class="bb" id="bb-status"       onclick="runW('status')">&#x1F4CB; status</div>
  <div class="bb" id="bb-jwt-refresh"  onclick="runW('jwt-refresh')">&#x1F504; jwt-refresh</div>
  <div class="bb" id="bb-logs-pretty"  onclick="runW('logs-pretty')">&#x1F4DC; opa-logs</div>
  <div class="bb" id="bb-setup-viewer" onclick="runW('setup-viewer')">&#x1F465; add-viewer</div>
  <span class="bot-ts" id="bot-ts"></span>
</div>

<!-- ── embedded metadata (safe JSON, no JS escaping issues) ── -->
<script type="application/json" id="zta-meta">{meta_json}</script>

<script>
// ── load metadata from JSON script tag (always reliable) ──────────────────
const META = (function() {{
  try {{
    return JSON.parse(document.getElementById('zta-meta').textContent);
  }} catch(e) {{
    console.error('META parse error:', e);
    return {{}};
  }}
}})();

const ARROW = {{
  'istio-jwt':'arr-ns-1','istio-deny':'arr-ns-2','opa':'arr-ns-3','app':'arr-ns-4',
  'mtls':'arr-ew-1','spiffe':'arr-ew-2','backend':'arr-ew-3',
}};

// ── state ─────────────────────────────────────────────────────────────────
let results  = {{}};   // tid -> {{status,expect,result}} from server
let filter   = 'all';
let selId    = null;
let animBusy = false;
let sse      = null;
let running  = null;

// ── load test results from server ─────────────────────────────────────────
async function load() {{
  try {{
    const d = await fetch('/api/data').then(r => r.json());
    results = d.results || {{}};
    g('warn').classList.add('hidden');
    g('bot-ts').textContent = 'updated ' + new Date().toLocaleTimeString();
  }} catch(e) {{
    g('warn').classList.remove('hidden');
    g('bot-ts').textContent = 'server offline';
  }}
  renderStats();
  renderCards();
}}

function renderStats() {{
  const ids = Object.keys(META);
  const pass = ids.filter(id => results[id] && results[id].status === 'PASS').length;
  const fail = ids.filter(id => results[id] && results[id].status === 'FAIL').length;
  g('s-total').textContent = ids.length;
  g('s-pass').textContent  = pass;
  g('s-fail').textContent  = fail;
}}

// ── render scenario cards ─────────────────────────────────────────────────
function renderCards() {{
  const ids = filter === 'all'
    ? Object.keys(META)
    : Object.keys(META).filter(id => id.startsWith(filter + '-') || id.startsWith(filter + 'N') || id.startsWith(filter + 'E'));

  if (!ids.length) {{
    g('cards').innerHTML = '<div class="no-cards">No scenarios</div>';
    return;
  }}

  g('cards').innerHTML = ids.map(id => {{
    const m   = META[id];
    const r   = results[id];
    const rid = running === id;

    let badgeCls, badgeTxt;
    if      (rid)              {{ badgeCls = 'b-run';     badgeTxt = '&#x25B6; ...'; }}
    else if (!r)               {{ badgeCls = 'b-unknown'; badgeTxt = '&mdash;'; }}
    else if (r.status==='PASS'){{ badgeCls = 'b-pass';    badgeTxt = 'PASS'; }}
    else                       {{ badgeCls = 'b-fail';    badgeTxt = 'FAIL'; }}

    let blk = '';
    if (!rid && r && r.status==='FAIL')
      blk = '<span class="blk-tag blk-fail">&#x2717; FAIL</span>';
    else if (m.block_at === null)
      blk = '<span class="blk-tag blk-allow">&#x2713; ALLOW</span>';
    else if (m.block_at === 'opa')
      blk = '<span class="blk-tag blk-opa">&#x2717; OPA</span>';
    else
      blk = '<span class="blk-tag blk-istio">&#x2717; Istio</span>';

    const selCls = selId === id ? ' sel' : '';
    const runCls = rid ? ' running' : '';
    const codes  = r ? r.expect + ' &rarr; ' + r.result : m.signals.method + ' ' + m.signals.path;

    return `<div class="tc${{selCls}}${{runCls}}" onclick="pick('${{id}}')">
<div class="tid">${{id}}</div>
<div class="ttitle">${{m.title}}</div>
<div class="tdesc">${{m.desc}}</div>
<div class="tc-row">
  <span style="font-size:10px;font-family:monospace;color:#484f58">${{codes}}</span>
  <span class="badge ${{badgeCls}}">${{badgeTxt}}</span>
</div>
<div style="margin-top:5px">${{blk}}</div>
</div>`;
  }}).join('');
}}

// tab click
g('tabs').addEventListener('click', e => {{
  const tab = e.target.closest('.tab');
  if (!tab) return;
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  tab.classList.add('active');
  filter = tab.dataset.f;
  renderCards();
}});

// ── pick scenario ─────────────────────────────────────────────────────────
function pick(id) {{
  selId = id;
  const m = META[id];
  if (!m) return;

  // show correct pipeline
  const ew = m.pipeline === 'ew';
  g('pl-ns').classList.toggle('hidden',  ew);
  g('pl-ew').classList.toggle('hidden', !ew);
  const dirEl = g('pl-dir');
  dirEl.classList.remove('hidden');
  dirEl.textContent = ew ? 'East-West (Lateral Movement)' : 'North-South';

  // detail pane
  renderDetail(id, m);

  // animate pipeline
  resetPipeline(m.flow);
  if (!animBusy) animateFlow(m.flow, m.block_at);

  renderCards();

  // run make
  runCmd(id);
}}

// ── detail pane ───────────────────────────────────────────────────────────
function renderDetail(id, m) {{
  const s = m.signals;
  const tags = [];
  if (s.method)   tags.push(`<span class="tag t-m">${{s.method}}</span>`);
  if (s.path)     tags.push(`<span class="tag t-p">${{s.path}}</span>`);
  if (s.identity) tags.push(`<span class="tag t-i">id:${{s.identity}}</span>`);
  if (s.role)     tags.push(`<span class="tag t-r">role:${{s.role}}</span>`);
  if (s.posture==='enabled')  tags.push('<span class="tag t-ok">fw:enabled</span>');
  if (s.posture==='disabled') tags.push('<span class="tag t-bad">fw:disabled</span>');
  if (s.sa)       tags.push(`<span class="tag t-sa">sa:${{s.sa}}</span>`);

  const isDeny = m.block_at !== null;
  const vcls   = isDeny ? 'v-deny'  : 'v-allow';
  const verdict= isDeny ? '&#x2717; BLOCKED' : '&#x2713; ALLOWED';

  g('detail').innerHTML = `
<div class="dl-sec">Attack &mdash; ${{id}}</div>
<div class="dl-desc">${{m.desc}}</div>
<div class="tags">${{tags.join('')}}</div>
<div class="dl-sec">Defense Decision</div>
<div class="verdict ${{vcls}}">${{verdict}}: ${{m.block_reason}}</div>
${{m.defense_layer ? `<div class="dl-layer">Layer: <strong>${{m.defense_layer}}</strong></div>` : ''}}
<div class="dl-make">make target: <code style="color:#79c0ff">${{m.make}}</code></div>`;
}}

// ── make runner ───────────────────────────────────────────────────────────
function runCmd(id) {{
  if (sse) {{ sse.close(); sse = null; }}

  running = id;
  renderCards();

  const badge = g('rbadge');
  badge.className   = 'rbadge rb-run';
  badge.textContent = 'running';
  g('term-ttl').textContent = '$ make --no-print-directory ' + (META[id] ? META[id].make : id);

  const term = g('term');
  term.innerHTML = '';
  addLine(`$ make --no-print-directory ${{META[id] ? META[id].make : id}}`, 'tc-hdr');
  addLine('─'.repeat(46), 'tc-sep');

  sse = new EventSource('/api/run/' + id);

  sse.onmessage = ev => {{
    const d = JSON.parse(ev.data);
    if (d.done) {{
      sse.close(); sse = null; running = null;
      const ok = d.status === 'PASS';
      badge.className   = ok ? 'rbadge rb-ok' : 'rbadge rb-ng';
      badge.textContent = ok ? '&#x2713; PASS' : '&#x2717; FAIL';
      addLine('─'.repeat(46), 'tc-sep');
      addLine('Exit: ' + d.status + '  (code ' + d.exit_code + ')', ok ? 'tc-ok' : 'tc-ng');
      if (!results[id]) results[id] = {{}};
      results[id].status = d.status;
      renderCards();
      renderStats();
      return;
    }}
    addLine(d.line);
    term.scrollTop = term.scrollHeight;
  }};

  sse.onerror = () => {{
    if (sse) {{ sse.close(); sse = null; }}
    running = null;
    badge.className   = 'rbadge rb-idle';
    badge.textContent = 'idle';
    addLine('ERROR: Cannot reach server or make not found', 'tc-err');
    addLine('Run from WSL: python3 visualizer/server.py', 'tc-err');
    term.scrollTop = term.scrollHeight;
    renderCards();
  }};
}}

function runW(id) {{
  setBb(id, 'run');
  runCmd(id);
  const obs = new MutationObserver(() => {{
    const b = g('rbadge');
    if (!b.classList.contains('rb-run')) {{
      setBb(id, b.classList.contains('rb-ok') ? 'ok' : 'ng');
      obs.disconnect();
    }}
  }});
  obs.observe(g('rbadge'), {{attributes:true, attributeFilter:['class']}});
}}

function setBb(id, st) {{
  const el = g('bb-' + id); if (!el) return;
  el.classList.remove('bb-run','bb-ok','bb-ng');
  if (st) el.classList.add('bb-' + st);
}}

// ── terminal helper ───────────────────────────────────────────────────────
function addLine(text, cls) {{
  const term = g('term');
  const s = document.createElement('span');
  s.className = 'tl ' + (cls || lineClass(text));
  s.innerHTML = text;
  term.appendChild(s);
  term.appendChild(document.createTextNode('\\n'));
  term.scrollTop = term.scrollHeight;
}}

function lineClass(l) {{
  if (!l) return '';
  if (l.includes('STATUS: PASS')) return 'tc-pass';
  if (l.includes('STATUS: FAIL')) return 'tc-fail';
  if (/^EXPECT:/.test(l))         return 'tc-exp';
  if (/^RESULT:/.test(l))         return 'tc-res';
  if (/^>>>/.test(l)||/^\[.+\]/.test(l)) return 'tc-hdr';
  if (/^[=\-]{{3,}}/.test(l))     return 'tc-sep';
  if (/^(NOTE|WARNING):/.test(l)) return 'tc-note';
  if (l.includes('SCENARIO') && l.includes('PASS')) return 'tc-pass';
  if (l.includes('SCENARIO') && l.includes('FAIL')) return 'tc-fail';
  return '';
}}

// ── pipeline animation ────────────────────────────────────────────────────
function resetPipeline(flow) {{
  flow.forEach(id => {{
    const el = g('node-' + id);
    if (el) el.className = 'pl-node inactive';
  }});
  Object.values(ARROW).forEach(id => {{
    const el = g(id);
    if (el) el.className = 'pl-arr';
  }});
}}

async function animateFlow(flow, blockAt) {{
  animBusy = true;
  for (let i = 0; i < flow.length; i++) {{
    const nid = flow[i];
    const el  = g('node-' + nid);
    if (!el) continue;
    await wait(320);
    if (i > 0) {{
      const arr = g(ARROW[nid]);
      if (arr) arr.className = 'pl-arr ' + (nid === blockAt ? 'blocked' : 'ok');
    }}
    if (nid === blockAt) {{
      el.className = 'pl-node blocked';
      flow.slice(i + 1).forEach(nxt => {{
        const e = g('node-' + nxt);
        if (e) e.className = 'pl-node unreachable';
      }});
      break;
    }} else {{
      el.className = i === flow.length - 1 ? 'pl-node allowed' : 'pl-node passed';
    }}
  }}
  animBusy = false;
}}

const g    = id => document.getElementById(id);
const wait = ms => new Promise(r => setTimeout(r, ms));

// ── init ──────────────────────────────────────────────────────────────────
renderCards();   // immediate — uses META (no server needed)
renderStats();
load();
setInterval(load, 30000);
</script>
</body>
</html>"""


_cached_html = None


def get_html():
    global _cached_html
    if _cached_html is None:
        _cached_html = build_html().encode("utf-8")
    return _cached_html


# ── HTTP handler ───────────────────────────────────────────────────────────

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
                "results":  parse_test_summary(),
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
            self.send_error(404, f"Unknown: {cmd_id}")
            return

        self.send_response(200)
        self.send_header("Content-Type",                "text/event-stream")
        self.send_header("Cache-Control",               "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        def emit(obj):
            try:
                self.wfile.write(f"data: {json.dumps(obj)}\n\n".encode())
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
            emit({"line": "ERROR: 'make' not found"})
            emit({"line": "Run this server from WSL: python3 visualizer/server.py"})
            emit({"done": True, "status": "FAIL", "exit_code": 127})
        except Exception as e:
            emit({"line": f"ERROR: {e}"})
            emit({"done": True, "status": "FAIL", "exit_code": 1})

    def log_message(self, fmt, *args):
        pass


# ── entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"ZTA Dashboard  ->  http://localhost:{PORT}")
    print(f"Project root   :  {BASE}")
    print("NOTE: run from WSL for 'make' to work")
    print("Ctrl+C to stop\n")
    try:
        ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
