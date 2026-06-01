#!/usr/bin/env python3
"""
ZTA Security Dashboard
Run  : python3 visualizer/server.py   (WSL required for make)
Open : http://localhost:5001
"""
import json, os, re, signal, subprocess, mimetypes, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

PORT = 5001
BASE = Path(__file__).resolve().parent.parent

# Wall-clock timeout for a single `make` invocation streamed via SSE.
# `make setup` legitimately takes ~5min on a cold cluster; 10min ceiling
# protects against hung processes blocking the HTTP thread forever.
SUBPROCESS_TIMEOUT_SEC = 600

RUNNABLE = {
    "all": "all", "step1": "step1", "step2": "step2",
    "step3": "step3", "step4": "step4", "ports": "ports",
    "status": "status", "jwt-refresh": "jwt-refresh",
    "setup-keycloak": "setup-keycloak",
    "setup-viewer": "setup-keycloak-viewer",
    "test-all": "test-all", "logs-pretty": "logs-pretty",
    "A-NS-1": "test-block",          "A-NS-2": "test-pass",
    "A-EW-1": "test-lateral-block",  "A-EW-2": "test-lateral-sidecar",
    "A-EW-3": "test-lateral-podip",  "B-1":    "test-fake",
    "B-2":    "test-jwt-tampered",   "B-4":    "test-jwt-auto",
    "C-1":    "test-context-user-get","C-2":   "test-context-user-admin",
    "C-3":    "test-context-user-post","C-4":  "test-context-admin-post",
    "D-1":    "test-jwt-admin-all",  "D-2":    "test-jwt-viewer-read",
    "D-3":    "test-jwt-viewer-admin","D-4":  "test-jwt-viewer-post",
    "E-1":    "test-posture-ok",     "E-2":    "test-posture-block",
}

TEST_META = {
    "A-NS-1": {"title":"No identity deny","desc":"External client — no JWT, no role header","signals":{"method":"GET","path":"/api/admin","identity":"none"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"istio-deny","block_reason":"require-jwt AuthorizationPolicy: notRequestPrincipals -> DENY 403","defense_layer":"Istio Authorization Policy","make":"test-block","why":"Istio's require-jwt AuthorizationPolicy checks every incoming request for a verified JWT principal. A request with no token has no principal, so the notRequestPrincipals selector matches and Istio issues a DENY 403 before the request can reach OPA or the application — identity must be proven upfront."},
    "A-NS-2": {"title":"role:admin header allow","desc":"Client sets role=admin HTTP header (demo scaffolding)","signals":{"method":"GET","path":"/api/admin","identity":"header","role":"admin"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA header rule: role=admin -> ALLOW 200 (demo path)","defense_layer":None,"make":"test-pass","why":"Demo scaffold path: OPA reads the role HTTP header directly and allows access when role=admin. This intentional shortcut exists to test OPA policy logic without needing a Keycloak token. Production uses cryptographically signed JWTs instead (see Scenario D)."},
    "A-EW-1": {"title":"Rogue pod (no sidecar)","desc":"Compromised pod launched without Istio sidecar","signals":{"method":"GET","path":"/","identity":"none","source":"no-sidecar"},"pipeline":"ew","flow":["rogue-pod","mtls","spiffe","backend"],"block_at":"mtls","block_reason":"mTLS STRICT: no client certificate -> TLS fails 403/503","defense_layer":"Istio mTLS STRICT","make":"test-lateral-block","why":"PeerAuthentication STRICT forces every pod-to-pod connection to use mutual TLS. A pod launched without an Istio sidecar has no SPIFFE certificate to present during the TLS handshake. The destination Envoy rejects the connection immediately — no certificate means no entry, regardless of what the attacker sends."},
    "A-EW-2": {"title":"Wrong ServiceAccount deny","desc":"Pod has sidecar but uses backend-sa; allowlist needs frontend-sa","signals":{"method":"GET","path":"/","identity":"spiffe","sa":"backend-sa"},"pipeline":"ew","flow":["rogue-pod","mtls","spiffe","backend"],"block_at":"spiffe","block_reason":"SPIFFE allowlist: backend-sa != frontend-sa -> DENY 403","defense_layer":"Istio SPIFFE Allowlist","make":"test-lateral-sidecar","why":"mTLS passes because the pod has a sidecar with a valid certificate. But Istio then inspects the SPIFFE identity (spiffe://cluster.local/ns/default/sa/...) embedded in that certificate. The AuthorizationPolicy allowlist only permits frontend-sa to reach the backend — backend-sa is not listed, so access is denied even with valid TLS."},
    "A-EW-3": {"title":"Pod IP bypass deny","desc":"Rogue pod targets backend podIP:8080 directly","signals":{"method":"GET","path":"/","identity":"none","target":"podIP:8080"},"pipeline":"ew","flow":["rogue-pod","mtls","spiffe","backend"],"block_at":"mtls","block_reason":"Inbound Envoy enforces policy even via pod IP -> 503","defense_layer":"Istio Inbound Policy","make":"test-lateral-podip","why":"Hitting the pod IP directly instead of the Kubernetes Service does NOT bypass Istio. The Envoy sidecar on the destination pod intercepts all inbound traffic at the network level regardless of routing path. The same mTLS + policy checks apply — there is no way to sneak past Envoy by changing the destination address."},
    "B-1":    {"title":"Forged JWT reject","desc":"JWT crafted with attacker's key — signature invalid","signals":{"method":"GET","path":"/api/admin","identity":"JWT-forged"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"istio-jwt","block_reason":"Istio JWKS verify: RSA sig invalid -> no principal -> DENY 403","defense_layer":"Istio JWT Auth (JWKS)","make":"test-fake","why":"Istio fetches the JWKS (public key set) from Keycloak and uses it to verify every JWT RSA signature. A token crafted with the attacker's own private key produces a signature that does not match any public key in the JWKS. Verification fails, no principal is set, and the require-jwt policy then denies the request."},
    "B-2":    {"title":"Tampered JWT reject","desc":"Real JWT payload modified (added admin), original signature kept","signals":{"method":"GET","path":"/api/admin","identity":"JWT-tampered"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"istio-jwt","block_reason":"RSA verify: new payload hash != original signature -> 401","defense_layer":"Istio JWT Auth (RSA verify)","make":"test-jwt-tampered","why":"A JWT is header.payload.signature where the RSA signature cryptographically commits to the exact bytes of header+payload. Changing even one character in the payload produces a different hash — the original signature no longer matches. Istio detects the mismatch and rejects the token with 401, making JWTs tamper-evident by design."},
    "B-4":    {"title":"Valid Keycloak JWT allow","desc":"testuser obtains valid Keycloak JWT and accesses admin endpoint","signals":{"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"admin"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"JWKS OK -> principal OK -> OPA admin role OK -> 200","defense_layer":None,"make":"test-jwt-auto","why":"A legitimately issued Keycloak JWT carries the correct RSA signature and realm_access.roles=[admin]. Istio verifies the signature and sets the principal. OPA then decodes the JWT payload, confirms the admin role, and approves the request. This is the happy path through the full ZTA stack."},
    "C-1":    {"title":"user GET /api/data allow","desc":"role=user reads the general data endpoint","signals":{"method":"GET","path":"/api/data","identity":"header","role":"user"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA: role=user + GET + non-admin path -> ALLOW 200","defense_layer":None,"make":"test-context-user-get","why":"OPA evaluates the combination of role, HTTP method, and path together. The policy allows role=user to perform GET on any non-admin path. All three context conditions are satisfied here — this demonstrates that least-privilege means users can read general data but nothing more."},
    "C-2":    {"title":"user GET /api/admin deny","desc":"role=user requests admin endpoint — admin path restriction","signals":{"method":"GET","path":"/api/admin","identity":"header","role":"user"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"opa","block_reason":"OPA: role=user + path=/api/admin -> DENY 403","defense_layer":"OPA Context Policy (role+path)","make":"test-context-user-admin","why":"OPA restricts /api/admin to role=admin only. The user role fails the path check and is denied — even though the identity is valid and the method is a harmless GET. This is path-based context control: knowing WHO you are is not enough, you also need the right ROLE for the specific resource."},
    "C-3":    {"title":"user POST /api/write deny","desc":"role=user attempts POST — write requires admin","signals":{"method":"POST","path":"/api/write","identity":"header","role":"user"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"opa","block_reason":"OPA: role=user + method=POST -> DENY 403","defense_layer":"OPA Context Policy (role+method)","make":"test-context-user-post","why":"OPA enforces method-level authorization: any write operation (POST/PUT/DELETE) requires role=admin regardless of path. A user may read but not write. This implements least-privilege at the HTTP verb level — read and write permissions are separated and enforced by policy, not application code."},
    "C-4":    {"title":"admin POST /api/write allow","desc":"Admin user performing authorized write","signals":{"method":"POST","path":"/api/write","identity":"header","role":"admin"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA: role=admin + device_posture_ok -> ALLOW 200","defense_layer":None,"make":"test-context-admin-post","why":"All OPA conditions are satisfied: role=admin meets both the method (POST) and path (/api/write) rules, and device posture defaults to ok. This is the authorized write path — demonstrating that the policy correctly passes legitimate admin write operations."},
    "D-1":    {"title":"admin JWT /api/admin allow","desc":"Keycloak JWT with realm_access.roles=[admin]","signals":{"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"admin"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA jwt_has_role(admin) + device_posture_ok -> ALLOW 200","defense_layer":None,"make":"test-jwt-admin-all","why":"OPA uses io.jwt.decode to extract realm_access.roles from the JWT payload without trusting any HTTP header. It finds admin in the roles array. Combined with device posture ok, all conditions pass. The role claim comes directly from Keycloak's token — it cannot be spoofed via a header."},
    "D-2":    {"title":"viewer JWT /api/data allow","desc":"vieweruser Keycloak JWT with roles=[viewer]","signals":{"method":"GET","path":"/api/data","identity":"JWT-valid","role":"viewer"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA jwt_has_role(viewer) + GET + non-admin -> ALLOW 200","defense_layer":None,"make":"test-jwt-viewer-read","why":"OPA decodes the JWT and finds roles=[viewer]. The viewer role is permitted to GET non-admin paths — read-only access to general data. This demonstrates role-based JWT claim authorization: the role is embedded in the token by Keycloak and verified cryptographically, not set by the caller."},
    "D-3":    {"title":"viewer JWT /api/admin deny","desc":"vieweruser JWT tries admin path","signals":{"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"viewer"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"opa","block_reason":"OPA: jwt_has_role(viewer) + /api/admin -> DENY 403","defense_layer":"OPA JWT Claim Policy","make":"test-jwt-viewer-admin","why":"The JWT signature is valid and Istio sets the principal — authentication succeeds. But OPA decodes the payload and finds only roles=[viewer]. The /api/admin path requires admin role, which viewer does not have. Access is denied at authorization. This separates authentication (who are you?) from authorization (what are you allowed to do?)."},
    "D-4":    {"title":"viewer JWT POST deny","desc":"vieweruser JWT attempts POST — viewer is read-only","signals":{"method":"POST","path":"/api/write","identity":"JWT-valid","role":"viewer"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"opa","block_reason":"OPA: jwt_has_role(viewer) + POST -> DENY 403","defense_layer":"OPA JWT Claim Policy","make":"test-jwt-viewer-post","why":"viewer is explicitly a read-only role. OPA denies POST to any non-admin role. Even with a valid Keycloak-issued JWT, the authorization check fails — the token proves identity but not the permission to write. This enforces least-privilege: authentication does not imply authorization."},
    "E-1":    {"title":"Posture enabled allow","desc":"Admin JWT + X-Device-Firewall: enabled","signals":{"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"admin","posture":"enabled"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":None,"block_reason":"OPA device_posture_ok: firewall=enabled -> ALLOW 200","defense_layer":None,"make":"test-posture-ok","why":"OPA reads X-Device-Firewall from the request headers. A value of enabled signals a healthy device endpoint, satisfying the device_posture_ok check. Combined with a valid admin JWT, all ZTA conditions are met — identity, role, AND device health must all be ok for access."},
    "E-2":    {"title":"Posture disabled deny","desc":"Stolen admin JWT but device unhealthy (firewall: disabled)","signals":{"method":"GET","path":"/api/admin","identity":"JWT-valid","role":"admin","posture":"disabled"},"pipeline":"ns","flow":["client","istio-jwt","istio-deny","opa","app"],"block_at":"opa","block_reason":"OPA device_posture_ok: firewall=disabled -> DENY 403","defense_layer":"OPA Device Posture Policy","make":"test-posture-block","why":"Even with a stolen valid admin JWT, OPA checks the device posture header. X-Device-Firewall: disabled fails the device_posture_ok rule and the request is denied. This is the core ZTA principle: identity alone is never sufficient — context (device health, location, time) must be continuously verified on every request."},
}


def parse_test_summary():
    path = BASE / ".test-summary.log"
    out = {}
    if not path.exists():
        return out
    for line in path.read_text(errors="replace").splitlines():
        parts = line.strip().split("|")
        if len(parts) < 4:
            continue
        name_full = parts[0].strip()
        idx = name_full.find(" ")
        tid = name_full[:idx] if idx > 0 else name_full
        out[tid] = {
            "expect": parts[1].strip(),
            "result": parts[2].strip(),
            "status": parts[3].strip(),
        }
    return out


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
        if len(parts) < 2:
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


_CLUSTER_CACHE_TTL = 10  # seconds
_cluster_cache = {"data": None, "ts": 0.0}
_cluster_lock = threading.Lock()


def _parse_cluster_uncached():
    out = {"pods": [], "policies": [], "error": None}
    try:
        r = subprocess.run(
            ["kubectl", "get", "pods", "--no-headers"],
            capture_output=True, text=True, timeout=8, cwd=str(BASE),
        )
        if r.returncode == 0:
            for line in r.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    out["pods"].append({
                        "name": parts[0], "ready": parts[1], "status": parts[2],
                    })
        else:
            out["error"] = (r.stderr or "kubectl error").strip()
    except Exception as e:
        out["error"] = str(e)
    try:
        r2 = subprocess.run(
            ["kubectl", "get",
             "authorizationpolicy,peerauthentication,requestauthentication",
             "-o", "json"],
            capture_output=True, text=True, timeout=8, cwd=str(BASE),
        )
        if r2.returncode == 0:
            data = json.loads(r2.stdout)
            for item in data.get("items", []):
                kind   = item.get("kind", "?")
                name   = item.get("metadata", {}).get("name", "?")
                action = item.get("spec", {}).get("action", "-")
                out["policies"].append({"name": name, "kind": kind, "action": action})
    except Exception:
        pass
    return out


def parse_cluster():
    now = time.monotonic()
    with _cluster_lock:
        if _cluster_cache["data"] is not None and \
           (now - _cluster_cache["ts"]) < _CLUSTER_CACHE_TTL:
            return _cluster_cache["data"]
    data = _parse_cluster_uncached()
    with _cluster_lock:
        _cluster_cache["data"] = data
        _cluster_cache["ts"] = time.monotonic()
    return data


_HTML_TMPL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ZTA Security Dashboard</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; overflow: hidden; }
body {
  background: #0d1117; color: #e6edf3;
  font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px;
  display: flex; flex-direction: column;
}
.hdr {
  flex-shrink: 0; background: #161b22; border-bottom: 1px solid #21262d;
  padding: 0 18px; display: flex; align-items: center; gap: 10px; height: 50px;
}
.hdr-hex  { font-size: 22px; color: #388bfd; flex-shrink: 0; }
.hdr-h1   { font-size: 17px; font-weight: 700; color: #f0f6fc; white-space: nowrap; flex-shrink: 0; }
.hdr-pipe { color: #30363d; font-size: 18px; flex-shrink: 0; }
.hdr-meta { font-size: 12.5px; color: #6e7681; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.stats { display: flex; gap: 14px; flex-shrink: 0; margin-left: auto; }
.st-item  { display: flex; align-items: baseline; gap: 5px; }
.st-val   { font-size: 20px; font-weight: 700; color: #79c0ff; line-height: 1; }
.st-p     { color: #3fb950; }
.st-lbl   { font-size: 10px; color: #6e7681; text-transform: uppercase; letter-spacing: .4px; }
.svc-links { display: flex; gap: 6px; flex-shrink: 0; }
.svc-btn {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 5px 11px; border-radius: 5px; font-size: 12px; font-weight: 600;
  text-decoration: none; border: 1px solid; transition: opacity .15s;
}
.svc-btn:hover { opacity: .75; }
.svc-kc  { background: #1a1000; color: #e3b341; border-color: #d29922; }
.svc-gf  { background: #1a0e00; color: #f89040; border-color: #d26911; }
.svc-ki  { background: #0d1f38; color: #79c0ff; border-color: #388bfd; }
.svc-pdf { background: #1c4025; color: #3fb950; border-color: #238636; }
.warn { flex-shrink: 0; background: #2d1b00; border-bottom: 1px solid #d29922; padding: 6px 20px; font-size: 12px; color: #e3b341; }
.main-split { flex: 7; display: flex; min-height: 0; }
.vert-tabs { width: 52px; flex-shrink: 0; display: flex; flex-direction: column; background: #161b22; border-right: 1px solid #21262d; overflow-y: auto; }
.vert-tabs::-webkit-scrollbar { width: 0; }
.vt-item { flex-shrink: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 12px 2px; cursor: pointer; border-left: 3px solid transparent; border-bottom: 1px solid #21262d; user-select: none; min-height: 76px; gap: 4px; transition: background .15s; }
.vt-item:hover { background: #0d1117; }
.vt-item.active { border-left-color: #388bfd; background: #0d1f38; }
.vt-cat { font-size: 18px; font-weight: 800; font-family: monospace; color: #6e7681; }
.vt-lbl { font-size: 11px; color: #484f58; text-align: center; line-height: 1.2; }
.vt-cnt { font-size: 10px; background: #21262d; color: #6e7681; padding: 2px 6px; border-radius: 5px; }
.vt-item.active .vt-cat { color: #79c0ff; }
.vt-item.active .vt-cnt { background: #1f3a6e; color: #79c0ff; }
.cards-area { width: 280px; flex-shrink: 0; display: flex; flex-direction: column; border-right: 1px solid #21262d; overflow: hidden; }
.cards { flex: 1; overflow-y: auto; padding: 8px 6px; }
.cards::-webkit-scrollbar { width: 4px; }
.cards::-webkit-scrollbar-thumb { background: #21262d; border-radius: 2px; }
.right { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
.tc {
  background: #161b22; border: 1px solid #21262d; border-radius: 8px;
  padding: 9px 11px; cursor: pointer; margin-bottom: 5px;
  transition: border-color .15s, background .15s, box-shadow .15s;
  position: relative;
}
.tc:hover  { border-color: #388bfd; background: #0d1f38; box-shadow: 0 2px 8px rgba(56,139,253,.12); }
.tc.sel    { border-color: #388bfd; background: #0d1f38; box-shadow: 0 0 0 2px #388bfd33, 0 2px 8px rgba(56,139,253,.15); }
.tc.run    { border-color: #d29922; background: #130f00; }
.tc .tid    { font-size: 12px; font-weight: 800; font-family: monospace; color: #388bfd; margin-bottom: 3px; letter-spacing: .3px; }
.tc .ttitle { font-size: 13px; font-weight: 600; color: #f0f6fc; margin-bottom: 3px; line-height: 1.3; }
.tc .tdesc  { font-size: 12px; color: #8b949e; line-height: 1.4; margin-bottom: 7px; }
.tc-row { display: flex; align-items: center; justify-content: space-between; gap: 6px; }
.codes  { font-size: 12px; font-family: monospace; color: #6e7681; }
.badge { padding: 3px 8px; border-radius: 8px; font-size: 11px; font-weight: 700; border: 1px solid; }
.b-pass    { background: #1c4025; color: #3fb950; border-color: #238636; }
.b-fail    { background: #3d1b1b; color: #f85149; border-color: #da3633; }
.b-run     { background: #1a1000; color: #e3b341; border-color: #d29922; }
.b-unknown { background: #21262d; color: #6e7681; border-color: #30363d; }
.blk { display: inline-block; margin-top: 6px; font-size: 11px; padding: 2px 8px; border-radius: 4px; border: 1px solid; font-family: monospace; font-weight: 600; }
.blk-allow  { background: #0d2010; color: #3fb950; border-color: #238636; }
.blk-opa    { background: #0d1f30; color: #56b6c2; border-color: #00b4d8; }
.blk-istio  { background: #1a0f28; color: #a371f7; border-color: #6e40c9; }
.blk-fail   { background: #3d1b1b; color: #f85149; border-color: #da3633; }
.no-cards   { padding: 24px; text-align: center; color: #484f58; font-style: italic; font-size: 13px; }

/* ── SVG topology ── */
.topo-scroll { flex: 1; overflow: hidden; display: flex; flex-direction: column; padding: 8px 12px; gap: 6px; }
.topo-hint { font-size: 12px; color: #484f58; font-style: italic; text-align: center; padding: 6px 0; }
.topo-svg { width: 100%; height: auto; display: block; }
.topo-section-lbl { font-size: 10px; font-weight: 700; color: #6e7681; text-transform: uppercase; letter-spacing: .6px; margin-bottom: 4px; }

.topo-node rect {
  fill: #0d1117; stroke: #30363d; stroke-width: 2;
  transition: fill .25s, stroke .25s, opacity .25s;
}
.topo-node text { font-family: 'Segoe UI', system-ui, sans-serif; transition: fill .25s, opacity .25s; }
.n-label { font-size: 11px; font-weight: 700; fill: #6e7681; }
.n-sub   { font-size: 9px;  fill: #484f58; }

.topo-node.n-inactive rect { fill: #0d1117; stroke: #21262d; }
.topo-node.n-inactive .n-label { fill: #484f58; }

.topo-node.n-passed rect  { fill: #0a1f12; stroke: #238636; }
.topo-node.n-passed .n-label { fill: #3fb950; }

.topo-node.n-allowed rect { fill: #0a2a1a; stroke: #2ea043; }
.topo-node.n-allowed .n-label { fill: #56d364; }

.topo-node.n-blocked rect { fill: #2a0c0c; stroke: #da3633; }
.topo-node.n-blocked .n-label { fill: #f85149; }
.topo-node.n-blocked { animation: nodepulse 1s ease-in-out 5; }
@keyframes nodepulse {
  0%,100% { filter: drop-shadow(0 0 0px rgba(218,54,51,0)); }
  50%      { filter: drop-shadow(0 0 8px rgba(218,54,51,.9)); }
}

.topo-node.n-unreachable rect { opacity: .08; }
.topo-node.n-unreachable text { opacity: .08; }

.topo-kc rect  { fill: #1a1000 !important; stroke: #d29922 !important; }
.topo-kc .n-label { fill: #e3b341 !important; }
.topo-kc .n-sub   { fill: #7d5a00 !important; }

.topo-edge { stroke: #30363d; stroke-width: 2; fill: none; transition: stroke .25s; }
.topo-edge.e-ok      { stroke: #238636; stroke-dasharray: 6,3; animation: flowdash 1.2s linear infinite; }
.topo-edge.e-blocked { stroke: #da3633; stroke-dasharray: 5,3; }
@keyframes flowdash { to { stroke-dashoffset: -18; } }
.topo-kc-edge { stroke: #d29922; stroke-width: 1.5; stroke-dasharray: 4,3; fill: none; opacity: .7; }
.e-label { fill: #484f58; font-size: 9px; font-family: monospace; }

@keyframes rpulse {
  0%   { box-shadow: 0 0 0 0   rgba(218,54,51,.6); }
  70%  { box-shadow: 0 0 0 10px rgba(218,54,51,0); }
  100% { box-shadow: 0 0 0 0   rgba(218,54,51,0); }
}

/* legend */
.legend { display: flex; gap: 14px; padding: 6px 2px; flex-wrap: wrap; }
.leg-item { display: flex; align-items: center; gap: 5px; font-size: 10px; color: #6e7681; }
.leg-dot { display: inline-block; width: 10px; height: 10px; border-radius: 2px; border: 1px solid; }
.ld-inactive { background: #0d1117; border-color: #21262d; }
.ld-passed   { background: #0a1f12; border-color: #238636; }
.ld-blocked  { background: #2a0c0c; border-color: #da3633; }
.ld-allowed  { background: #0a2a1a; border-color: #2ea043; }
.ld-dim      { background: #0d1117; border-color: #21262d; opacity: .3; }

.d-empty { color: #484f58; font-size: 13px; font-style: italic; }
.d-sec   { font-size: 11px; font-weight: 700; color: #6e7681; text-transform: uppercase; letter-spacing: .5px; margin-bottom: 7px; }
.d-desc  { font-size: 13px; color: #c9d1d9; line-height: 1.5; margin-bottom: 10px; }
.tags    { display: flex; flex-wrap: wrap; gap: 5px; margin-bottom: 12px; }
.tag     { padding: 3px 8px; border-radius: 10px; font-size: 11px; font-family: monospace; border: 1px solid; }
.t-m  { background: #0d2547; border-color: #1f6feb; color: #79c0ff; }
.t-p  { background: #1a1000; border-color: #d29922; color: #e3b341; }
.t-i  { background: #1f1235; border-color: #8957e5; color: #bc8cff; }
.t-r  { background: #0d2010; border-color: #238636; color: #3fb950; }
.t-ok { background: #0d2010; border-color: #238636; color: #3fb950; }
.t-ng { background: #2d0c0c; border-color: #da3633; color: #f85149; }
.t-sa { background: #1a0f00; border-color: #d29922; color: #e3b341; }
.verdict { font-size: 12px; font-family: monospace; padding: 10px 12px; border-radius: 5px; line-height: 1.5; margin-bottom: 6px; word-break: break-word; }
.v-deny  { background: #2a0c0c; border-left: 3px solid #da3633; color: #ffa198; }
.v-allow { background: #0a1f12; border-left: 3px solid #238636; color: #7ee787; }
.d-layer { font-size: 11px; color: #6e7681; margin-top: 4px; }
.d-make  { font-size: 11px; color: #484f58; margin-top: 10px; }
.journey { margin: 0 0 12px; }
.jstep { display: flex; align-items: flex-start; margin-left: 8px; padding: 5px 0 5px 16px; border-left: 2px solid #21262d; position: relative; }
.jstep:last-child { border-left-color: transparent; }
.jstep::before { content: ''; position: absolute; left: -5px; top: 10px; width: 8px; height: 8px; border-radius: 50%; border: 2px solid #30363d; background: #0d1117; }
.j-src::before   { border-color: #484f58; background: #21262d; }
.j-pass::before  { border-color: #238636; background: #0a1f12; }
.j-block::before { border-color: #da3633; background: #2a0c0c; }
.j-skip::before  { border-color: #21262d; opacity: .35; }
.jstep-body { flex: 1; }
.jstep-row  { display: flex; align-items: center; gap: 8px; }
.jstep-name { font-size: 13px; font-weight: 600; flex: 1; }
.j-src  .jstep-name { color: #8b949e; }
.j-pass .jstep-name { color: #3fb950; }
.j-block .jstep-name { color: #f85149; }
.j-skip .jstep-name { color: #484f58; }
.jstep-badge { font-size: 10px; padding: 1px 7px; border-radius: 8px; font-weight: 700; border: 1px solid; white-space: nowrap; }
.jb-src   { background: #21262d; color: #6e7681;  border-color: #30363d; }
.jb-pass  { background: #0d2010; color: #3fb950;  border-color: #238636; }
.jb-block { background: #2a0c0c; color: #f85149;  border-color: #da3633; }
.jb-skip    { background: transparent; color: #30363d; border-color: #21262d; }
.jb-pending { background: transparent; color: #484f58; border-color: #30363d; }
.j-pending::before { border-color: #30363d; background: #161b22; }
.j-pending .jstep-name { color: #6e7681; }
.j-reason { font-size: 12px; color: #ffa198; font-family: monospace; margin-top: 5px; padding: 5px 8px; background: #1e0e0e; border-radius: 4px; border-left: 2px solid #da3633; line-height: 1.5; word-break: break-word; }
.d-why { font-size: 13px; color: #c9d1d9; line-height: 1.65; margin-bottom: 12px; padding: 9px 11px; background: #0d1f38; border-radius: 5px; border-left: 3px solid #388bfd; }

/* ── right panel: top row (graph + journey) + detail ── */
.right-top     { flex: 1; display: flex; min-height: 0; }
.right-graph   { flex: 4; display: flex; flex-direction: column; overflow: hidden; border-right: 1px solid #21262d; min-height: 0; }
.right-journey { flex: 2; display: flex; flex-direction: column; overflow: hidden; border-right: 1px solid #21262d; min-height: 0; }
.right-detail  { flex: 1; display: flex; flex-direction: column; overflow: hidden; min-height: 0; border-top: 1px solid #21262d; }
.panel-hdr { flex-shrink: 0; padding: 6px 14px; background: #161b22; border-bottom: 1px solid #21262d; font-size: 11px; font-weight: 700; color: #6e7681; text-transform: uppercase; letter-spacing: .5px; }
.panel-body { flex: 1; overflow-y: auto; padding: 10px 14px; }
.panel-body::-webkit-scrollbar { width: 4px; }
.panel-body::-webkit-scrollbar-thumb { background: #21262d; border-radius: 2px; }

/* ── bottom 2-column ── */
.bot2 { flex: 3; border-top: 1px solid #21262d; display: flex; min-height: 0; max-height: 240px; }
.b2-col { display: flex; flex-direction: column; overflow: hidden; }
.b2-term { flex: 3; border-right: 1px solid #21262d; }
.b2-perf { flex: 5; }
.b3-hdr { flex-shrink: 0; padding: 6px 14px; background: #161b22; border-bottom: 1px solid #21262d; font-size: 11px; font-weight: 700; color: #6e7681; text-transform: uppercase; letter-spacing: .5px; }

/* ── terminal ── */
.term-bar  { flex-shrink: 0; display: flex; align-items: center; gap: 8px; padding: 7px 16px; background: #161b22; border-bottom: 1px solid #21262d; }
.dots span { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 3px; }
.d-r { background: #f85149; } .d-y { background: #e3b341; } .d-g { background: #3fb950; }
.term-ttl { font-size: 12px; color: #6e7681; font-family: monospace; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rbadge { font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: 9px; border: 1px solid; }
.rb-idle { background: #21262d; color: #6e7681; border-color: #30363d; }
.rb-run  { background: #1a1000; color: #e3b341; border-color: #d29922; animation: blink .9s infinite; }
.rb-ok   { background: #1c4025; color: #3fb950; border-color: #238636; }
.rb-ng   { background: #3d1b1b; color: #f85149; border-color: #da3633; }
@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: .4; } }
.term-body { flex: 1; overflow-y: auto; padding: 10px 16px; font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 13px; line-height: 1.7; }
.term-body::-webkit-scrollbar { width: 4px; }
.term-body::-webkit-scrollbar-thumb { background: #30363d; border-radius: 2px; }
.tl { display: block; white-space: pre-wrap; word-break: break-all; }
.c-pass { color: #3fb950; font-weight: 700; } .c-fail { color: #f85149; font-weight: 700; }
.c-hdr  { color: #f0f6fc; font-weight: 700; } .c-sep  { color: #30363d; }
.c-exp  { color: #79c0ff; } .c-res  { color: #e3b341; } .c-note { color: #d29922; }
.c-ok   { color: #3fb950; border-top: 1px solid #238636; margin-top: 5px; padding-top: 4px; }
.c-ng   { color: #f85149; border-top: 1px solid #da3633; margin-top: 5px; padding-top: 4px; }
.c-err  { color: #f85149; } .c-idle { color: #484f58; font-style: italic; }

/* ── perf table ── */
.perf-body { flex: 1; overflow-y: auto; padding: 8px 10px; }
.perf-body::-webkit-scrollbar { width: 4px; }
.perf-body::-webkit-scrollbar-thumb { background: #21262d; border-radius: 2px; }
.perf-tbl { width: 100%; border-collapse: collapse; font-size: 13px; }
.perf-tbl th { padding: 6px 9px; text-align: left; font-size: 11px; font-weight: 700; color: #6e7681; text-transform: uppercase; letter-spacing: .4px; border-bottom: 1px solid #21262d; white-space: nowrap; position: sticky; top: 0; background: #0d1117; z-index: 1; }
.perf-tbl td { padding: 6px 9px; border-bottom: 1px solid #161b22; font-family: monospace; vertical-align: middle; white-space: nowrap; }
.perf-tbl tr:hover td { background: #161b22; }
.pt-id    { color: #79c0ff; font-weight: 700; }
.pt-cat   { font-size: 12px; }
.pt-pipe  { color: #8b949e; }
.pt-code-ok  { color: #3fb950; }
.pt-code-ng  { color: #f85149; }
.pt-code-mismatch { color: #e3b341; }
.pt-layer { color: #a371f7; font-size: 12px; max-width: 160px; overflow: hidden; text-overflow: ellipsis; }
.pt-allow .pt-verdict { color: #3fb950; font-weight: 700; }
.pt-block .pt-verdict { color: #f85149; font-weight: 700; }
.pt-ms   { color: #e3b341; }
.pt-ts   { color: #484f58; font-size: 11px; }
.perf-empty { color: #484f58; font-size: 12px; font-style: italic; padding: 16px; text-align: center; }


/* ── bottom bar ── */
.bot { flex-shrink: 0; background: #161b22; border-top: 1px solid #21262d; padding: 7px 14px; display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.bot-lbl { font-size: 10px; color: #484f58; font-weight: 700; text-transform: uppercase; letter-spacing: .4px; white-space: nowrap; }
.bot-sep { color: #30363d; }
.bb { display: inline-flex; align-items: center; gap: 4px; padding: 4px 10px; font-size: 11px; font-weight: 600; cursor: pointer; border: 1px solid #30363d; border-radius: 5px; background: #0d1117; color: #8b949e; transition: all .15s; white-space: nowrap; }
.bb:hover  { border-color: #388bfd; color: #79c0ff; background: #0b1c36; }
.bb.bb-run { border-color: #d29922; color: #e3b341; background: #130f00; }
.bb.bb-ok  { border-color: #238636; color: #3fb950; background: #0a1f12; }
.bb.bb-ng  { border-color: #da3633; color: #f85149; background: #2a0c0c; }
.bot-ts { font-size: 10px; color: #484f58; margin-left: auto; }
.hidden { display: none !important; }
</style>
</head>
<body>

<div class="hdr">
  <div class="hdr-hex">&#x2B21;</div>
  <div class="hdr-h1">ZTA Security Dashboard</div>
  <div class="hdr-pipe">|</div>
  <div class="hdr-meta">Minsoo Ahn &middot; NIST SP&nbsp;800-207 &middot; Keycloak + Istio + OPA &middot; 18 Scenarios / 5 Attack Classes</div>
  <div class="stats">
    <div class="st-item"><span class="st-val" id="s-total">18</span><span class="st-lbl">Total</span></div>
    <div class="st-item"><span class="st-val st-p" id="s-pass">0</span><span class="st-lbl">Pass</span></div>
  </div>
  <div class="svc-links">
    <a class="svc-btn svc-kc"  href="http://localhost:18080" target="_blank">&#x1F511; Keycloak</a>
    <a class="svc-btn svc-gf"  href="http://localhost:20002" target="_blank">&#x1F4CA; Grafana</a>
    <a class="svc-btn svc-ki"  href="http://localhost:20000" target="_blank">&#x1F578; Kiali</a>
    <a class="svc-btn svc-pdf" href="/report.pdf" download="zta-research-report.pdf">&#x2B07; Report</a>
  </div>
</div>

<div class="warn hidden" id="warn">
  &#x26A0; Server offline &mdash; run from WSL: <code>python3 visualizer/server.py</code>
</div>

<div class="main-split">

  <!-- VERTICAL CATEGORY TABS -->
  <div class="vert-tabs" id="vert-tabs">
    <div class="vt-item active" data-f="all"><span class="vt-cat">All</span><span class="vt-cnt" id="cnt-all">18</span></div>
    <div class="vt-item" data-f="A"><span class="vt-cat">A</span><span class="vt-lbl">Lateral</span><span class="vt-cnt">5</span></div>
    <div class="vt-item" data-f="B"><span class="vt-cat">B</span><span class="vt-lbl">JWT</span><span class="vt-cnt">3</span></div>
    <div class="vt-item" data-f="C"><span class="vt-cat">C</span><span class="vt-lbl">Context</span><span class="vt-cnt">4</span></div>
    <div class="vt-item" data-f="D"><span class="vt-cat">D</span><span class="vt-lbl">Claim</span><span class="vt-cnt">4</span></div>
    <div class="vt-item" data-f="E"><span class="vt-cat">E</span><span class="vt-lbl">Posture</span><span class="vt-cnt">2</span></div>
  </div>

  <!-- SCENARIO CARDS -->
  <div class="cards-area">
    <div class="cards" id="cards">
      <div class="no-cards">Loading&hellip;</div>
    </div>
  </div>

  <!-- RIGHT: graph+journey top | detail bottom -->
  <div class="right">
    <div class="right-top">
    <div class="right-graph">
    <div class="topo-scroll">
        <div id="topo-hint" class="topo-hint">&#x2190; Click a scenario card to animate the ZTA traffic flow</div>

        <!-- North-South topology -->
        <div id="wrap-ns">
          <div class="topo-section-lbl">North-South &mdash; Client to Application</div>
          <svg id="svg-ns" class="topo-svg" viewBox="0 0 760 195" preserveAspectRatio="xMidYMid meet">
            <defs>
              <marker id="arh"    markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#30363d"/></marker>
              <marker id="arh-ok" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#238636"/></marker>
              <marker id="arh-ng" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#da3633"/></marker>
            </defs>

            <!-- Keycloak side node -->
            <g id="node-keycloak" class="topo-node topo-kc">
              <rect x="155" y="10" width="130" height="40" rx="5"/>
              <text x="220" y="27" text-anchor="middle" class="n-label">Keycloak</text>
              <text x="220" y="42" text-anchor="middle" class="n-sub">JWT issuer (JWKS)</text>
            </g>
            <!-- JWKS edge -->
            <line x1="220" y1="50" x2="220" y2="98" class="topo-kc-edge"/>
            <text x="226" y="78" class="e-label">JWKS</text>

            <!-- Main flow edges -->
            <line id="edge-istio-jwt"  x1="106" y1="128" x2="155" y2="128" class="topo-edge" marker-end="url(#arh)"/>
            <line id="edge-istio-deny" x1="290" y1="128" x2="330" y2="128" class="topo-edge" marker-end="url(#arh)"/>
            <line id="edge-opa"        x1="465" y1="128" x2="500" y2="128" class="topo-edge" marker-end="url(#arh)"/>
            <line id="edge-app"        x1="620" y1="128" x2="650" y2="128" class="topo-edge" marker-end="url(#arh)"/>

            <!-- Client -->
            <g id="node-client" class="topo-node n-inactive">
              <rect x="6" y="103" width="100" height="50" rx="6"/>
              <text x="56" y="125" text-anchor="middle" class="n-label">Client</text>
              <text x="56" y="141" text-anchor="middle" class="n-sub">Attacker</text>
            </g>

            <!-- Istio JWT Auth -->
            <g id="node-istio-jwt" class="topo-node n-inactive">
              <rect x="155" y="98" width="135" height="60" rx="6"/>
              <text x="222" y="120" text-anchor="middle" class="n-label">Istio JWT Auth</text>
              <text x="222" y="135" text-anchor="middle" class="n-sub">JWKS verify</text>
              <text x="222" y="150" text-anchor="middle" class="n-sub">RSA signature</text>
            </g>

            <!-- Istio DENY -->
            <g id="node-istio-deny" class="topo-node n-inactive">
              <rect x="330" y="98" width="135" height="60" rx="6"/>
              <text x="397" y="120" text-anchor="middle" class="n-label">Istio DENY</text>
              <text x="397" y="135" text-anchor="middle" class="n-sub">require-jwt</text>
              <text x="397" y="150" text-anchor="middle" class="n-sub">principal check</text>
            </g>

            <!-- OPA -->
            <g id="node-opa" class="topo-node n-inactive">
              <rect x="500" y="98" width="120" height="60" rx="6"/>
              <text x="560" y="120" text-anchor="middle" class="n-label">OPA Policy</text>
              <text x="560" y="135" text-anchor="middle" class="n-sub">Rego eval</text>
              <text x="560" y="150" text-anchor="middle" class="n-sub">role/path/posture</text>
            </g>

            <!-- App -->
            <g id="node-app" class="topo-node n-inactive">
              <rect x="650" y="103" width="104" height="50" rx="6"/>
              <text x="702" y="125" text-anchor="middle" class="n-label">App</text>
              <text x="702" y="141" text-anchor="middle" class="n-sub">Frontend svc</text>
            </g>
          </svg>
        </div>

        <!-- East-West topology -->
        <div id="wrap-ew" class="hidden">
          <div class="topo-section-lbl">East-West &mdash; Lateral Movement Defense</div>
          <svg id="svg-ew" class="topo-svg" viewBox="0 0 700 135" preserveAspectRatio="xMidYMid meet">
            <defs>
              <marker id="arh-ew"    markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#30363d"/></marker>
              <marker id="arh-ok-ew" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#238636"/></marker>
              <marker id="arh-ng-ew" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="#da3633"/></marker>
            </defs>
            <!-- Edges -->
            <line id="edge-mtls"    x1="116" y1="67" x2="158" y2="67" class="topo-edge" marker-end="url(#arh-ew)"/>
            <line id="edge-spiffe"  x1="278" y1="67" x2="325" y2="67" class="topo-edge" marker-end="url(#arh-ew)"/>
            <line id="edge-backend" x1="455" y1="67" x2="495" y2="67" class="topo-edge" marker-end="url(#arh-ew)"/>

            <!-- Rogue Pod -->
            <g id="node-rogue-pod" class="topo-node n-inactive">
              <rect x="6" y="42" width="110" height="50" rx="6"/>
              <text x="61" y="64" text-anchor="middle" class="n-label">Rogue Pod</text>
              <text x="61" y="80" text-anchor="middle" class="n-sub">no sidecar / bad SA</text>
            </g>

            <!-- mTLS -->
            <g id="node-mtls" class="topo-node n-inactive">
              <rect x="158" y="42" width="120" height="50" rx="6"/>
              <text x="218" y="64" text-anchor="middle" class="n-label">mTLS STRICT</text>
              <text x="218" y="80" text-anchor="middle" class="n-sub">cert handshake</text>
            </g>

            <!-- SPIFFE -->
            <g id="node-spiffe" class="topo-node n-inactive">
              <rect x="325" y="42" width="130" height="50" rx="6"/>
              <text x="390" y="64" text-anchor="middle" class="n-label">SPIFFE Allowlist</text>
              <text x="390" y="80" text-anchor="middle" class="n-sub">SA identity check</text>
            </g>

            <!-- Backend -->
            <g id="node-backend" class="topo-node n-inactive">
              <rect x="495" y="42" width="110" height="50" rx="6"/>
              <text x="550" y="64" text-anchor="middle" class="n-label">Backend</text>
              <text x="550" y="80" text-anchor="middle" class="n-sub">internal svc</text>
            </g>
          </svg>
        </div>

        <!-- Legend -->
        <div class="legend">
          <div class="leg-item"><span class="leg-dot ld-inactive"></span>Inactive</div>
          <div class="leg-item"><span class="leg-dot ld-passed"></span>Passed</div>
          <div class="leg-item"><span class="leg-dot ld-blocked"></span>Blocked</div>
          <div class="leg-item"><span class="leg-dot ld-allowed"></span>Allowed</div>
          <div class="leg-item"><span class="leg-dot ld-dim"></span>Unreachable</div>
        </div>
      </div>
    </div><!-- /right-graph -->

      <!-- Request Journey panel (right side of top row) -->
      <div class="right-journey">
        <div class="panel-hdr">Request Journey</div>
        <div class="panel-body" id="panel-journey">
          <div class="d-empty">&#x2190; Click a scenario card</div>
        </div>
      </div>
    </div><!-- /right-top -->

    <!-- Attack Detail full-width bottom -->
    <div class="right-detail">
      <div class="panel-hdr">Attack Detail &amp; Defense</div>
      <div class="panel-body" id="panel-why">
        <div class="d-empty">&#x2190; Click a scenario card</div>
      </div>
    </div>
  </div><!-- /right -->
</div><!-- /main-split -->

<!-- bottom 2-column: terminal + performance -->
<div class="bot2">
  <div class="b2-col b2-term">
    <div class="term-bar">
      <div class="dots"><span class="d-r"></span><span class="d-y"></span><span class="d-g"></span></div>
      <span class="term-ttl" id="term-ttl">$ click a scenario card or button to run</span>
      <span class="rbadge rb-idle" id="rbadge">idle</span>
    </div>
    <div class="term-body" id="term">
      <span class="tl c-idle">Waiting for command&hellip;</span>
    </div>
  </div>
  <div class="b2-col b2-perf">
    <div class="b3-hdr">Run History &amp; Performance</div>
    <div class="perf-body" id="perf-body">
      <div class="perf-empty">Run a scenario to see timing here.</div>
    </div>
  </div>
</div>

<!-- bottom bar -->
<div class="bot">
  <span class="bot-lbl">Run</span>
  <div class="bb" id="bb-test-all"    onclick="runW('test-all')">&#x1F9EA; test-all</div>
  <div class="bb" id="bb-jwt-refresh" onclick="runW('jwt-refresh')">jwt-refresh</div>
  <div class="bb" id="bb-logs-pretty" onclick="runW('logs-pretty')">opa-logs</div>
  <div class="bb" id="bb-cluster"     onclick="fetchCluster()">&#x1F5A7; cluster</div>
  <span class="bot-ts" id="bot-ts"></span>
</div>

<script type="application/json" id="zta-meta">ZTA_META_JSON</script>

<script>
var META = {};
(function() {
  try { META = JSON.parse(document.getElementById('zta-meta').textContent); }
  catch(e) { console.error('ZTA META parse error', e); }
})();

var NODE_NAMES = {
  'client':     'Client',
  'istio-jwt':  'Istio JWT Auth (JWKS verify)',
  'istio-deny': 'Istio DENY Policy (require-jwt)',
  'opa':        'OPA Policy Engine (Rego eval)',
  'app':        'Application (Flask)',
  'rogue-pod':  'Rogue Pod (compromised)',
  'mtls':       'mTLS STRICT (cert check)',
  'spiffe':     'SPIFFE Allowlist (SA check)',
  'backend':    'Backend Service',
};

var EDGE_IDS = {
  'istio-jwt':  'edge-istio-jwt',
  'istio-deny': 'edge-istio-deny',
  'opa':        'edge-opa',
  'app':        'edge-app',
  'mtls':       'edge-mtls',
  'spiffe':     'edge-spiffe',
  'backend':    'edge-backend',
};

var results     = {};
var filter      = 'all';
var selId       = null;
var animBusy    = false;
var sse         = null;
var running     = null;
var perfHistory = [];
var _runStart   = 0;
var _runExpect  = null;
var _runResult  = null;

function g(id) { return document.getElementById(id); }


function renderStats() {
  var ids  = Object.keys(META);
  var pass = ids.filter(function(id) { return results[id] && results[id].status === 'PASS'; }).length;
  g('s-total').textContent = ids.length;
  g('s-pass').textContent  = pass;
}

var CAT_COLOR = { 'A': '#8957e5', 'B': '#388bfd', 'C': '#3fb950', 'D': '#e3b341', 'E': '#f85149' };

function renderCards() {
  var ids = Object.keys(META);
  if (filter !== 'all') ids = ids.filter(function(id) { return id.indexOf(filter + '-') === 0; });
  if (!ids.length) { g('cards').innerHTML = '<div class="no-cards">No scenarios</div>'; return; }
  var html = '';
  for (var i = 0; i < ids.length; i++) {
    var id  = ids[i], m = META[id], r = results[id], rid = (running === id);
    var cat = id.charAt(0);
    var catColor = CAT_COLOR[cat] || '#30363d';
    var badgeCls, badgeTxt;
    if      (rid)                 { badgeCls='b-run';     badgeTxt='&#x25B6; ...'; }
    else if (!r)                  { badgeCls='b-unknown'; badgeTxt='&mdash;'; }
    else if (r.status === 'PASS') { badgeCls='b-pass';    badgeTxt='PASS'; }
    else                          { badgeCls='b-fail';    badgeTxt='FAIL'; }
    var blk;
    if (!rid && r && r.status === 'FAIL') blk='<span class="blk blk-fail">&#x2717; FAIL</span>';
    else if (!m.block_at)                 blk='<span class="blk blk-allow">&#x2713; ALLOW</span>';
    else if (m.block_at === 'opa')        blk='<span class="blk blk-opa">&#x2717; OPA</span>';
    else                                  blk='<span class="blk blk-istio">&#x2717; Istio</span>';
    var codes = r ? (r.expect + ' &rarr; ' + r.result) : (m.signals.method + ' ' + m.signals.path);
    html += '<div class="tc' + (selId===id?' sel':'') + (rid?' run':'') + '" data-id="' + id + '" onclick="pick(this.dataset.id)" style="border-left:3px solid ' + catColor + '">' +
      '<div class="tid">' + id + '</div>' +
      '<div class="ttitle">' + m.title + '</div>' +
      '<div class="tdesc">' + m.desc + '</div>' +
      '<div class="tc-row"><span class="codes">' + codes + '</span><span class="badge ' + badgeCls + '">' + badgeTxt + '</span></div>' +
      '<div>' + blk + '</div></div>';
  }
  g('cards').innerHTML = html;
}

g('vert-tabs').addEventListener('click', function(e) {
  var item = e.target.closest('.vt-item');
  if (!item) return;
  document.querySelectorAll('.vt-item').forEach(function(t) { t.classList.remove('active'); });
  item.classList.add('active');
  filter = item.dataset.f;
  renderCards();
});

function pick(id) {
  if (running) {
    var b = g('rbadge');
    b.style.outline = '2px solid #f85149';
    setTimeout(function() { b.style.outline = ''; }, 400);
    return;
  }
  selId = id;
  var m = META[id];
  if (!m) return;
  var ew = (m.pipeline === 'ew');
  g('wrap-ns').classList.toggle('hidden',  ew);
  g('wrap-ew').classList.toggle('hidden', !ew);
  g('topo-hint').classList.add('hidden');
  renderDetail(id, m);
  resetGraph(m.flow);
  renderCards();
  runCmd(id);
}

function ewMode() {
  return g('wrap-ew') && !g('wrap-ew').classList.contains('hidden');
}

function markerIds() {
  var sfx = ewMode() ? '-ew' : '';
  return { def: 'url(#arh' + sfx + ')', ok: 'url(#arh-ok' + sfx + ')', ng: 'url(#arh-ng' + sfx + ')' };
}

function resetGraph(flow) {
  flow.forEach(function(nid) {
    var el = g('node-' + nid);
    if (el) el.setAttribute('class', 'topo-node n-inactive');
  });
  var m = markerIds();
  Object.keys(EDGE_IDS).forEach(function(key) {
    var el = g(EDGE_IDS[key]);
    if (el) { el.setAttribute('class', 'topo-edge'); el.setAttribute('marker-end', m.def); }
  });
}

function applyNodeState(nid, state) {
  var el = g('node-' + nid);
  if (!el) return;
  var m = markerIds();
  var cls = { active: 'n-passed', passed: 'n-passed', blocked: 'n-blocked', unreachable: 'n-unreachable', allowed: 'n-allowed' };
  el.setAttribute('class', 'topo-node ' + (cls[state] || 'n-inactive'));
  var eid = EDGE_IDS[nid];
  if (!eid) return;
  var earr = g(eid);
  if (!earr) return;
  if (state === 'blocked') {
    earr.setAttribute('class', 'topo-edge e-blocked');
    earr.setAttribute('marker-end', m.ng);
  } else if (state === 'passed' || state === 'allowed') {
    earr.setAttribute('class', 'topo-edge e-ok');
    earr.setAttribute('marker-end', m.ok);
  }
}

function replayFlow(lines) {
  animBusy = true;
  var i = 0;
  var meta = META[selId] || {};
  function step() {
    if (i >= lines.length) { animBusy = false; return; }
    var line = lines[i++];
    var nm = line.match(/node=(\\S+)/);
    var sm = line.match(/state=(\\S+)/);
    if (nm && sm) {
      var nid = nm[1], state = sm[1];
      applyNodeState(nid, state);
      if (state === 'blocked') {
        updateJourneyStep(nid, 'blocked', meta.block_reason || '');
      } else if (state === 'unreachable') {
        updateJourneyStep(nid, 'unreachable');
      } else if (state === 'passed' || state === 'allowed') {
        updateJourneyStep(nid, state);
      }
    }
    setTimeout(step, 320);
  }
  setTimeout(step, 320);
}

function animateGraph(flow, blockAt) {
  animBusy = true;
  var i = 0;
  var m = markerIds();
  var meta = META[selId] || {};
  function step() {
    if (i >= flow.length) { animBusy = false; return; }
    var nid = flow[i];
    var el  = g('node-' + nid);
    if (!el) { i++; step(); return; }
    if (i > 0) {
      var eid = EDGE_IDS[nid];
      if (eid) {
        var earr = g(eid);
        if (earr) {
          var blocked = (nid === blockAt);
          earr.setAttribute('class', 'topo-edge ' + (blocked ? 'e-blocked' : 'e-ok'));
          earr.setAttribute('marker-end', blocked ? m.ng : m.ok);
        }
      }
    }
    if (nid === blockAt) {
      el.setAttribute('class', 'topo-node n-blocked');
      updateJourneyStep(nid, 'blocked', meta.block_reason || '');
      for (var j = i+1; j < flow.length; j++) {
        var e2 = g('node-' + flow[j]);
        if (e2) e2.setAttribute('class', 'topo-node n-unreachable');
        updateJourneyStep(flow[j], 'unreachable');
      }
      animBusy = false;
      return;
    }
    var nodeState = (i === flow.length-1 ? 'allowed' : 'passed');
    el.setAttribute('class', 'topo-node n-' + nodeState);
    if (i > 0) updateJourneyStep(nid, nodeState);
    i++;
    setTimeout(step, 320);
  }
  setTimeout(step, 320);
}

function renderPerf() {
  var el = g('perf-body');
  if (!perfHistory.length) {
    el.innerHTML = '<div class="perf-empty">Run a scenario to see performance metrics here.</div>';
    return;
  }
  var html = '<table class="perf-tbl"><thead><tr>' +
    '<th>#</th><th>Scenario</th><th>Cat</th><th>Pipeline</th>' +
    '<th>Expect HTTP</th><th>Actual HTTP</th><th>Match</th>' +
    '<th>Block Layer</th><th>Verdict</th><th>Duration</th><th>Exit</th><th>Time</th>' +
    '</tr></thead><tbody>';
  for (var i = perfHistory.length - 1; i >= 0; i--) {
    var row = perfHistory[i];
    var ok  = row.status === 'PASS';
    var cls = ok ? 'pt-allow' : 'pt-block';
    var ts  = row.ts.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
    var ms  = row.ms;
    var dur = ms >= 1000 ? (ms / 1000).toFixed(1) + 's' : ms + 'ms';
    var cat = row.id ? row.id.charAt(0) : '-';
    var pipe = (row.pipeline || '-').toUpperCase();
    var exp  = row.expectCode || (META[row.id] && META[row.id].signals ? (META[row.id].block_at ? '403' : '200') : '-');
    var res  = row.resultCode || '-';
    var match = (exp !== '-' && res !== '-') ? (exp === res ? '<span class="pt-code-ok">&#x2713;</span>' : '<span class="pt-code-mismatch">&#x2717;</span>') : '-';
    var codeExpCls = 'pt-code-' + (exp && exp[0] === '2' ? 'ok' : 'ng');
    var codeResCls = 'pt-code-' + (res !== '-' ? (res[0] === '2' ? 'ok' : 'ng') : 'ng');
    var blockLbl = row.blockAt ? row.blockAt : (ok ? '&mdash;' : '?');
    var layerLbl = row.layer ? row.layer.replace('Istio ','').replace(' Policy','') : (ok ? 'ALLOWED' : '&mdash;');
    html += '<tr class="' + cls + '">' +
      '<td style="color:#484f58">' + (i + 1) + '</td>' +
      '<td class="pt-id">' + row.id + '</td>' +
      '<td class="pt-cat">' + cat + '</td>' +
      '<td class="pt-pipe">' + pipe + '</td>' +
      '<td class="' + codeExpCls + '">' + exp + '</td>' +
      '<td class="' + codeResCls + '">' + res + '</td>' +
      '<td style="text-align:center">' + match + '</td>' +
      '<td class="pt-layer">' + layerLbl + '</td>' +
      '<td class="pt-verdict">' + (ok ? '&#x2713; PASS' : '&#x2717; FAIL') + '</td>' +
      '<td class="pt-ms">' + dur + '</td>' +
      '<td style="color:#484f58">' + (row.exitCode !== undefined ? row.exitCode : '-') + '</td>' +
      '<td class="pt-ts">' + ts + '</td>' +
      '</tr>';
  }
  html += '</tbody></table>';
  el.innerHTML = html;
}

function updateJourneyStep(nid, state, blockReason) {
  var el = document.querySelector('.jstep[data-nid="' + nid + '"]');
  if (!el) return;
  var sc, bc, bt;
  if      (state === 'blocked')     { sc='j-block'; bc='jb-block'; bt='&#x2717; BLOCKED HERE'; }
  else if (state === 'allowed')     { sc='j-pass';  bc='jb-pass';  bt='&#x2713; passed'; }
  else if (state === 'passed')      { sc='j-pass';  bc='jb-pass';  bt='&#x2713; passed'; }
  else if (state === 'unreachable') { sc='j-skip';  bc='jb-skip';  bt='skipped'; }
  else return;
  el.className = 'jstep ' + sc;
  var badge = el.querySelector('.jstep-badge');
  if (badge) { badge.className = 'jstep-badge ' + bc; badge.innerHTML = bt; }
  if (state === 'blocked' && blockReason) {
    var body = el.querySelector('.jstep-body');
    if (body && !body.querySelector('.j-reason')) {
      var rEl = document.createElement('div');
      rEl.className = 'j-reason'; rEl.textContent = blockReason;
      body.appendChild(rEl);
    }
  }
}

function renderDetail(id, m) {
  var journey = '';
  for (var fi = 0; fi < m.flow.length; fi++) {
    var nid = m.flow[fi], nLabel = NODE_NAMES[nid] || nid;
    var isSource = (fi === 0);
    var sc = isSource ? 'j-src' : 'j-pending';
    var bc = isSource ? 'jb-src' : 'jb-pending';
    var bt = isSource ? 'source' : '&middot;&middot;&middot;';
    journey += '<div class="jstep ' + sc + '" data-nid="' + nid + '"><div class="jstep-body">';
    journey += '<div class="jstep-row"><span class="jstep-name">' + nLabel + '</span>';
    journey += '<span class="jstep-badge ' + bc + '">' + bt + '</span></div>';
    journey += '</div></div>';
  }
  g('panel-journey').style.padding = '';
  g('panel-journey').innerHTML = '<div class="journey">' + journey + '</div>';

  var s = m.signals;
  var tags = '';
  if (s.method)   tags += '<span class="tag t-m">' + s.method + '</span>';
  if (s.path)     tags += '<span class="tag t-p">' + s.path + '</span>';
  if (s.identity) tags += '<span class="tag t-i">id:' + s.identity + '</span>';
  if (s.role)     tags += '<span class="tag t-r">role:' + s.role + '</span>';
  if (s.posture === 'enabled')  tags += '<span class="tag t-ok">fw:enabled</span>';
  if (s.posture === 'disabled') tags += '<span class="tag t-ng">fw:disabled</span>';
  if (s.sa)       tags += '<span class="tag t-sa">sa:' + s.sa + '</span>';
  var isDeny  = (m.block_at !== null && m.block_at !== undefined);
  var verdict = isDeny ? '&#x2717; BLOCKED' : '&#x2713; ALLOWED';
  var verdictCls = isDeny ? 'v-deny' : 'v-allow';
  var pipeLabel = (m.pipeline === 'ew') ? 'East-West &mdash; Pod-to-Pod mTLS' : 'North-South &mdash; Client &rarr; App';
  var layerVal  = m.defense_layer || (isDeny ? '?' : 'None &mdash; ALLOW path');
  var layerColor = m.defense_layer ? '#a371f7' : '#3fb950';
  var layerBorder = m.defense_layer ? '#6e40c9' : '#238636';
  var layerBg    = m.defense_layer ? '#1a0f28' : '#0d2010';

  /* LEFT column: identifiers, signals, verdict, block reason */
  var leftCol =
    '<div style="display:flex;align-items:baseline;gap:8px;margin-bottom:8px">' +
      '<span style="font-size:15px;font-weight:800;font-family:monospace;color:#79c0ff">' + id + '</span>' +
      '<span style="font-size:15px;font-weight:700;color:#f0f6fc">' + m.title + '</span>' +
    '</div>' +
    '<div style="font-size:13px;color:#8b949e;line-height:1.5;margin-bottom:10px">' + m.desc + '</div>' +
    '<div class="tags" style="margin-bottom:10px">' + tags + '</div>' +
    '<div style="display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:10px">' +
      '<div class="verdict ' + verdictCls + '" style="margin:0">' + verdict + '</div>' +
      '<span style="background:' + layerBg + ';color:' + layerColor + ';border:1px solid ' + layerBorder + ';padding:4px 10px;border-radius:10px;font-size:12px;font-weight:700">&#x1F6E1; ' + layerVal + '</span>' +
    '</div>' +
    '<div style="font-size:11px;color:#484f58;margin-bottom:10px">&#x21AA; ' + pipeLabel + '</div>' +
    (isDeny ? '<div style="font-size:12px;font-family:monospace;color:#ffa198;background:#1e0e0e;padding:8px 11px;border-radius:4px;border-left:3px solid #da3633;line-height:1.6;word-break:break-word">&#x2717; ' + m.block_reason + '</div>' : '') +
    '<div style="margin-top:12px;font-size:12px;color:#484f58">&#x1F9EA; <code style="color:#79c0ff">make ' + m.make + '</code></div>';

  /* RIGHT column: why / key insight — large readable text */
  var insightTitle = isDeny ? 'Why It Is Blocked' : 'Why It Is Allowed';
  var rightCol =
    '<div style="font-size:11px;font-weight:700;color:#6e7681;text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px">' + insightTitle + '</div>' +
    (m.why
      ? '<div style="font-size:14px;color:#c9d1d9;line-height:1.8;padding:12px 14px;background:#0d1f38;border-radius:6px;border-left:3px solid #388bfd">' + m.why + '</div>'
      : '<div style="color:#484f58;font-style:italic;font-size:13px">No explanation available.</div>');

  g('panel-why').style.padding = '0';
  g('panel-why').innerHTML =
    '<div style="display:flex;height:100%">' +
      '<div style="flex:1;min-width:0;padding:12px 14px;border-right:1px solid #21262d;overflow-y:auto">' + leftCol + '</div>' +
      '<div style="flex:1.4;min-width:0;padding:12px 16px;overflow-y:auto">' + rightCol + '</div>' +
    '</div>';
}

function runCmd(id, onDone) {
  var hadSse = !!sse;
  if (sse) { sse.close(); sse = null; }
  running = id;
  _runStart = Date.now();
  renderCards();
  var badge = g('rbadge');
  var label = META[id] ? META[id].make : id;
  badge.className = 'rbadge rb-run';
  badge.textContent = 'running';
  g('term-ttl').textContent = '$ make --no-print-directory ' + label;
  var term = g('term');
  term.innerHTML = '';
  addLine('$ make --no-print-directory ' + label, 'c-hdr');
  addLine('------------------------------------------', 'c-sep');
  var startDelay = hadSse ? 250 : 0;
  _runExpect = null; _runResult = null;
  setTimeout(function() { sse = new EventSource('/api/run/' + id); attachSse(); }, startDelay);
  function attachSse() {
  var flowLines = [];
  sse.onmessage = function(ev) {
    var d = JSON.parse(ev.data);
    if (d.done) {
      sse.close(); sse = null; running = null;
      var ok = (d.status === 'PASS');
      badge.className   = ok ? 'rbadge rb-ok' : 'rbadge rb-ng';
      badge.textContent = ok ? '✓ PASS' : '✗ FAIL';
      addLine('------------------------------------------', 'c-sep');
      addLine('Exit: ' + d.status + '  (code ' + d.exit_code + ')', ok ? 'c-ok' : 'c-ng');
      if (!results[id]) results[id] = {};
      results[id].status = d.status;
      var m = META[id] || {};
      perfHistory.push({
        id: id, status: d.status, ms: Date.now() - _runStart, ts: new Date(),
        expectCode: _runExpect, resultCode: _runResult,
        pipeline: m.pipeline || '-', blockAt: m.block_at || null,
        layer: m.defense_layer || null, exitCode: d.exit_code,
      });
      renderCards(); renderStats(); renderPerf();
      if (flowLines.length > 0) {
        replayFlow(flowLines);
      } else if (!animBusy && selId === id && META[id] && META[id].flow) {
        animateGraph(META[id].flow, META[id].block_at);
      }
      if (onDone) onDone();
      return;
    }
    if (d.line && d.line.indexOf('[ZTA:FLOW]') === 0) {
      flowLines.push(d.line);
      return;
    }
    if (d.line) {
      var em = d.line.match(/^EXPECT:\\s*(?:HTTP\\s*)?(\\d{3})/i);
      var rm = d.line.match(/^RESULT:\\s*(?:HTTP\\s*)?(\\d{3})/i);
      if (em) _runExpect = em[1];
      if (rm) _runResult = rm[1];
    }
    addLine(d.line);
  };
  sse.onerror = function() {
    if (sse) { sse.close(); sse = null; }
    running = null;
    badge.className = 'rbadge rb-idle'; badge.textContent = 'idle';
    addLine('ERROR: server unreachable or make not found', 'c-err');
    renderCards();
  };
  } // end attachSse
}

function runW(id) {
  if (running) {
    var b = g('rbadge');
    b.style.outline = '2px solid #f85149';
    setTimeout(function() { b.style.outline = ''; }, 400);
    return;
  }
  var el = g('bb-' + id);
  if (el) { el.classList.remove('bb-ok','bb-ng'); el.classList.add('bb-run'); }
  runCmd(id);
  var obs = new MutationObserver(function() {
    var b = g('rbadge');
    if (!b.classList.contains('rb-run')) {
      var ok = b.classList.contains('rb-ok');
      if (el) { el.classList.remove('bb-run'); el.classList.add(ok ? 'bb-ok' : 'bb-ng'); }
      obs.disconnect();
    }
  });
  obs.observe(g('rbadge'), { attributes: true, attributeFilter: ['class'] });
}

function fetchCluster() {
  var term = g('term');
  term.innerHTML = '';
  addLine('$ kubectl cluster status', 'c-hdr');
  addLine('------------------------------------------', 'c-sep');
  fetch('/api/cluster')
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (d.error) { addLine('ERROR: ' + d.error, 'c-err'); return; }
      addLine('PODS:', 'c-hdr');
      (d.pods || []).forEach(function(p) {
        var ok = p.status === 'Running';
        var line = '  ' + p.name + ' '.repeat(Math.max(1,36-p.name.length)) + p.ready + '   ' + p.status;
        addLine(line, ok ? 'c-pass' : 'c-fail');
      });
      if ((d.policies||[]).length) {
        addLine('', '');
        addLine('POLICIES:', 'c-hdr');
        d.policies.forEach(function(p) {
          addLine('  ' + p.name + ' '.repeat(Math.max(1,36-p.name.length)) + p.kind + (p.action&&p.action!=='-'?'   '+p.action:''), 'c-exp');
        });
      }
    })
    .catch(function(e) { addLine('ERROR: ' + String(e), 'c-err'); });
}

function addLine(text, cls) {
  var term = g('term');
  var s = document.createElement('span');
  s.className = 'tl ' + (cls || lineClass(text));
  s.innerHTML = text;
  term.appendChild(s);
  term.appendChild(document.createTextNode('\\n'));
  term.scrollTop = term.scrollHeight;
}

function lineClass(l) {
  if (!l) return '';
  if (l.indexOf('STATUS: PASS') >= 0) return 'c-pass';
  if (l.indexOf('STATUS: FAIL') >= 0) return 'c-fail';
  if (/^EXPECT:/.test(l)) return 'c-exp';
  if (/^RESULT:/.test(l)) return 'c-res';
  if (/^>>>/.test(l) || /^\\[.+\\]/.test(l)) return 'c-hdr';
  if (/^[=\\-]{3,}/.test(l)) return 'c-sep';
  if (/^(NOTE|WARNING):/.test(l)) return 'c-note';
  if (l.indexOf('SCENARIO') >= 0 && l.indexOf('PASS') >= 0) return 'c-pass';
  if (l.indexOf('SCENARIO') >= 0 && l.indexOf('FAIL') >= 0) return 'c-fail';
  return '';
}

function load() {
  fetch('/api/data')
    .then(function(r) { return r.json(); })
    .then(function(d) {
      results = d.results || {};
      g('warn').classList.add('hidden');
      g('bot-ts').textContent = 'updated ' + new Date().toLocaleTimeString();
      renderStats(); renderCards();
    })
    .catch(function() {
      g('warn').classList.remove('hidden');
      g('bot-ts').textContent = 'server offline';
    });
}

renderCards(); renderStats(); renderPerf();
load();
setInterval(load, 30000);
</script>
</body>
</html>"""


_cached_html = None


def build_html():
    meta_json = json.dumps(TEST_META, ensure_ascii=False)
    return _HTML_TMPL.replace("ZTA_META_JSON", meta_json)


def get_html():
    return build_html().encode("utf-8")


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
            payload = {"results": parse_test_summary(), "opa_logs": parse_opa_logs()}
            body = json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type",                "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length",              str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/api/cluster":
            payload = parse_cluster()
            body = json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type",                "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length",              str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/api/perf":
            perf_path = BASE / "evidence" / "perf-scenarios-latest.csv"
            rows = []
            if perf_path.exists():
                lines = perf_path.read_text(errors="replace").splitlines()
                if len(lines) > 1:
                    header = [h.strip() for h in lines[0].split(",")]
                    for ln in lines[1:]:
                        if not ln.strip():
                            continue
                        vals = [v.strip() for v in ln.split(",")]
                        rows.append(dict(zip(header, vals)))
            body = json.dumps({"rows": rows}, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type",                "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length",              str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/api/report-exists":
            exists = (BASE / "research_report.pdf").exists()
            body = json.dumps({"exists": exists}).encode()
            self.send_response(200)
            self.send_header("Content-Type",                "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length",              str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path == "/report.pdf":
            pdf_path = BASE / "research_report.pdf"
            if not pdf_path.exists():
                self.send_error(404, "research_report.pdf not found")
                return
            body = pdf_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type",        "application/pdf")
            self.send_header("Content-Disposition", "attachment; filename=\"zta-research-report.pdf\"")
            self.send_header("Content-Length",      str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif path.startswith("/api/run/"):
            self._sse(path[9:])

        else:
            self.send_error(404)

    def _sse(self, cmd_id):
        target = RUNNABLE.get(cmd_id)
        if not target:
            self.send_error(404, "Unknown: " + cmd_id)
            return
        self.send_response(200)
        self.send_header("Content-Type",                "text/event-stream")
        self.send_header("Cache-Control",               "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        def emit(obj):
            try:
                self.wfile.write(("data: " + json.dumps(obj) + "\n\n").encode())
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                raise

        proc = None
        try:
            proc = subprocess.Popen(
                ["make", "--no-print-directory", target],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                cwd=str(BASE), text=True, bufsize=1, errors="replace",
                start_new_session=True,
            )

            timed_out = {"v": False}
            def _watchdog():
                deadline = time.monotonic() + SUBPROCESS_TIMEOUT_SEC
                while proc.poll() is None:
                    if time.monotonic() > deadline:
                        timed_out["v"] = True
                        try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                        except Exception: pass
                        time.sleep(2)
                        try: os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        except Exception: pass
                        return
                    time.sleep(1)
            threading.Thread(target=_watchdog, daemon=True).start()

            for line in proc.stdout:
                emit({"line": line.rstrip()})
            proc.wait()
            if timed_out["v"]:
                emit({"line": "ERROR: timeout after %ds — process killed"
                              % SUBPROCESS_TIMEOUT_SEC})
            emit({"done": True, "status": "PASS" if proc.returncode == 0 else "FAIL",
                  "exit_code": proc.returncode})
        except (BrokenPipeError, ConnectionResetError):
            if proc:
                try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except Exception: pass
        except FileNotFoundError:
            emit({"line": "ERROR: 'make' not found. Run from WSL:"})
            emit({"line": "  python3 visualizer/server.py"})
            emit({"done": True, "status": "FAIL", "exit_code": 127})
        except Exception as e:
            emit({"line": "ERROR: " + str(e)})
            emit({"done": True, "status": "FAIL", "exit_code": 1})

    def log_message(self, fmt, *args):
        pass


def _self_check(html):
    """Startup sanity: META placeholder replaced + first scenario id present."""
    problems = []
    if "ZTA_META_JSON" in html:
        problems.append("template placeholder ZTA_META_JSON not replaced")
    if '"A-NS-1"' not in html:
        problems.append("META content missing (A-NS-1 not found in HTML)")
    return problems


if __name__ == "__main__":
    html = build_html()
    for p in _self_check(html):
        print("FATAL self-check:", p)
    if _self_check(html):
        raise SystemExit(1)
    print("ZTA Dashboard  ->  http://localhost:%d" % PORT)
    print("Project root   :  %s" % BASE)
    print("META scenarios :  %d loaded" % len(TEST_META))
    print("Run from WSL for 'make' to work. Ctrl+C to stop.\n")
    try:
        ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
