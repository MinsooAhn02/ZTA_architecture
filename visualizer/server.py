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


# ── HTML template
# Uses plain triple-quoted string (no f-string) so { } in CSS/JS are literal.
# META data is injected via .replace("ZTA_META_JSON", ...) — no escaping needed.
# ─────────────────────────────────────────────────────────────────────────────
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

/* ── header ── */
.hdr {
  flex-shrink: 0; background: #161b22; border-bottom: 1px solid #21262d;
  padding: 10px 20px; display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
}
.hdr-title h1 { font-size: 15px; font-weight: 700; color: #f0f6fc; }
.hdr-title .sub { font-size: 11px; color: #6e7681; margin-top: 1px; }
.stats { display: flex; gap: 16px; }
.stat .val { font-size: 20px; font-weight: 700; line-height: 1; }
.stat .lbl { font-size: 10px; color: #6e7681; text-transform: uppercase; letter-spacing: .4px; }
.st-t .val { color: #79c0ff; } .st-p .val { color: #3fb950; } .st-f .val { color: #f85149; }
.svc-links { display: flex; gap: 6px; margin-left: auto; }
.svc-btn {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 5px 11px; border-radius: 5px; font-size: 12px; font-weight: 600;
  text-decoration: none; border: 1px solid; transition: opacity .15s;
}
.svc-btn:hover { opacity: .75; }
.svc-kc { background: #1a1000; color: #e3b341; border-color: #d29922; }
.svc-gf { background: #1a0e00; color: #f89040; border-color: #d26911; }
.svc-ki { background: #0d1f38; color: #79c0ff; border-color: #388bfd; }

/* ── warn ── */
.warn { flex-shrink: 0; background: #2d1b00; border-bottom: 1px solid #d29922; padding: 6px 20px; font-size: 12px; color: #e3b341; }

/* ── split ── */
.split { flex: 1; display: flex; overflow: hidden; min-height: 0; }
.left  { width: 340px; min-width: 240px; flex-shrink: 0; display: flex; flex-direction: column; border-right: 1px solid #21262d; }
.right { flex: 1; display: flex; flex-direction: column; overflow: hidden; }

/* ── tabs ── */
.tabs {
  flex-shrink: 0; display: flex; background: #161b22; border-bottom: 1px solid #21262d;
  overflow-x: auto;
}
.tabs::-webkit-scrollbar { height: 2px; }
.tabs::-webkit-scrollbar-thumb { background: #30363d; }
.tab {
  padding: 8px 10px; font-size: 11px; font-weight: 500; color: #6e7681;
  cursor: pointer; border-bottom: 2px solid transparent; white-space: nowrap;
  user-select: none; flex-shrink: 0;
}
.tab:hover { color: #e6edf3; background: #0d1117; }
.tab.active { color: #f0f6fc; border-bottom-color: #388bfd; }
.tab .cnt {
  background: #21262d; color: #6e7681; font-size: 10px;
  padding: 1px 5px; border-radius: 6px; margin-left: 3px;
}
.tab.active .cnt { background: #1f3a6e; color: #79c0ff; }

/* ── cards ── */
.cards { flex: 1; overflow-y: auto; padding: 10px; }
.cards::-webkit-scrollbar { width: 4px; }
.cards::-webkit-scrollbar-thumb { background: #21262d; border-radius: 2px; }

.tc {
  background: #161b22; border: 1px solid #21262d; border-radius: 6px;
  padding: 11px 12px; cursor: pointer; margin-bottom: 8px;
  transition: border-color .15s, background .15s;
}
.tc:hover  { border-color: #388bfd; background: #0d1f38; }
.tc.sel    { border-color: #388bfd; background: #0d1f38; box-shadow: inset 0 0 0 1px #388bfd44; }
.tc.run    { border-color: #d29922; background: #130f00; }

.tc .tid   { font-size: 10px; font-weight: 700; font-family: monospace; color: #484f58; margin-bottom: 3px; }
.tc .ttitle { font-size: 12px; font-weight: 600; color: #e6edf3; margin-bottom: 4px; }
.tc .tdesc  { font-size: 11px; color: #8b949e; line-height: 1.4; margin-bottom: 8px; }
.tc-row { display: flex; align-items: center; justify-content: space-between; gap: 6px; }
.codes  { font-size: 10px; font-family: monospace; color: #484f58; }

.badge { padding: 2px 7px; border-radius: 8px; font-size: 10px; font-weight: 700; border: 1px solid; }
.b-pass    { background: #1c4025; color: #3fb950; border-color: #238636; }
.b-fail    { background: #3d1b1b; color: #f85149; border-color: #da3633; }
.b-run     { background: #1a1000; color: #e3b341; border-color: #d29922; }
.b-unknown { background: #21262d; color: #6e7681; border-color: #30363d; }

.blk {
  display: inline-block; margin-top: 5px; font-size: 10px; padding: 1px 6px;
  border-radius: 3px; border: 1px solid; font-family: monospace;
}
.blk-allow  { background: #0d2010; color: #3fb950; border-color: #238636; }
.blk-opa    { background: #0d1f30; color: #56b6c2; border-color: #00b4d8; }
.blk-istio  { background: #1a0f28; color: #a371f7; border-color: #6e40c9; }
.blk-fail   { background: #3d1b1b; color: #f85149; border-color: #da3633; }
.no-cards   { padding: 24px; text-align: center; color: #484f58; font-style: italic; font-size: 12px; }

/* ── pipeline ── */
.pipe-wrap  { flex-shrink: 0; padding: 14px 18px; border-bottom: 1px solid #21262d; }
.pipe-hdr   { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
.pipe-hdr h2 { font-size: 10px; font-weight: 700; color: #6e7681; text-transform: uppercase; letter-spacing: .7px; }
.pipe-dir    { font-size: 11px; color: #388bfd; font-weight: 500; }

.pl-row { display: flex; align-items: center; overflow-x: auto; padding: 2px 0; }
.pl-row::-webkit-scrollbar { height: 3px; }
.pl-row::-webkit-scrollbar-thumb { background: #30363d; }

.pln {
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  gap: 4px; min-width: 96px; padding: 12px 8px;
  border: 2px solid #30363d; border-radius: 8px; background: #0d1117;
  flex-shrink: 0; transition: border-color .22s, background .22s, opacity .22s;
}
.pln .ni  { font-size: 22px; line-height: 1; }
.pln .nl  { font-size: 11px; font-weight: 700; color: #6e7681; text-align: center; transition: color .22s; }
.pln .ns  { font-size: 9px;  color: #484f58; text-align: center; line-height: 1.3; }
.pl-arr   { padding: 0 6px; font-size: 18px; color: #30363d; flex-shrink: 0; transition: color .22s; user-select: none; }

.pln.inactive   { opacity: .22; }
.pln.active     { border-color: #388bfd; background: #0b1c36; } .pln.active .nl { color: #79c0ff; }
.pln.passed     { border-color: #238636; background: #0a1f12; } .pln.passed .nl { color: #3fb950; }
.pln.allowed    { border-color: #238636; background: #0a1f12; } .pln.allowed .nl { color: #3fb950; }
.pln.blocked    { border-color: #da3633; background: #2a0c0c; animation: rpulse .9s ease 4; } .pln.blocked .nl { color: #f85149; }
.pln.unreachable { opacity: .1; }
.pl-arr.ok      { color: #238636; }
.pl-arr.blocked { color: #21262d; }

@keyframes rpulse {
  0%   { box-shadow: 0 0 0 0   rgba(218,54,51,.6); }
  70%  { box-shadow: 0 0 0 10px rgba(218,54,51,0); }
  100% { box-shadow: 0 0 0 0   rgba(218,54,51,0); }
}

/* ── detail ── */
.detail { flex: 1; overflow-y: auto; padding: 14px 18px; }
.detail::-webkit-scrollbar { width: 4px; }
.detail::-webkit-scrollbar-thumb { background: #21262d; border-radius: 2px; }
.d-empty { color: #484f58; font-size: 12px; font-style: italic; }
.d-sec   { font-size: 10px; font-weight: 700; color: #6e7681; text-transform: uppercase; letter-spacing: .5px; margin-bottom: 7px; }
.d-desc  { font-size: 12px; color: #c9d1d9; line-height: 1.5; margin-bottom: 10px; }
.tags    { display: flex; flex-wrap: wrap; gap: 5px; margin-bottom: 12px; }
.tag     { padding: 3px 8px; border-radius: 10px; font-size: 11px; font-family: monospace; border: 1px solid; }
.t-m  { background: #0d2547; border-color: #1f6feb; color: #79c0ff; }
.t-p  { background: #1a1000; border-color: #d29922; color: #e3b341; }
.t-i  { background: #1f1235; border-color: #8957e5; color: #bc8cff; }
.t-r  { background: #0d2010; border-color: #238636; color: #3fb950; }
.t-ok { background: #0d2010; border-color: #238636; color: #3fb950; }
.t-ng { background: #2d0c0c; border-color: #da3633; color: #f85149; }
.t-sa { background: #1a0f00; border-color: #d29922; color: #e3b341; }
.verdict {
  font-size: 12px; font-family: monospace; padding: 10px 12px; border-radius: 5px;
  line-height: 1.5; margin-bottom: 6px; word-break: break-word;
}
.v-deny  { background: #2a0c0c; border-left: 3px solid #da3633; color: #ffa198; }
.v-allow { background: #0a1f12; border-left: 3px solid #238636; color: #7ee787; }
.d-layer { font-size: 11px; color: #6e7681; margin-top: 4px; }
.d-make  { font-size: 11px; color: #484f58; margin-top: 10px; }

/* ── terminal ── */
.term-wrap {
  flex-shrink: 0; border-top: 1px solid #21262d;
  display: flex; flex-direction: column; height: 200px;
}
.term-bar {
  flex-shrink: 0; display: flex; align-items: center; gap: 8px;
  padding: 6px 14px; background: #161b22; border-bottom: 1px solid #21262d;
}
.dots span {
  display: inline-block; width: 9px; height: 9px;
  border-radius: 50%; margin-right: 2px;
}
.d-r { background: #f85149; } .d-y { background: #e3b341; } .d-g { background: #3fb950; }
.term-ttl { font-size: 11px; color: #6e7681; font-family: monospace; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.rbadge { font-size: 11px; font-weight: 600; padding: 2px 9px; border-radius: 9px; border: 1px solid; }
.rb-idle { background: #21262d; color: #6e7681; border-color: #30363d; }
.rb-run  { background: #1a1000; color: #e3b341; border-color: #d29922; animation: blink .9s infinite; }
.rb-ok   { background: #1c4025; color: #3fb950; border-color: #238636; }
.rb-ng   { background: #3d1b1b; color: #f85149; border-color: #da3633; }
@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: .4; } }
.term-body { flex: 1; overflow-y: auto; padding: 8px 14px; font-family: monospace; font-size: 12px; line-height: 1.6; }
.term-body::-webkit-scrollbar { width: 4px; }
.term-body::-webkit-scrollbar-thumb { background: #30363d; border-radius: 2px; }
.tl { display: block; white-space: pre-wrap; word-break: break-all; }
.c-pass { color: #3fb950; font-weight: 700; } .c-fail { color: #f85149; font-weight: 700; }
.c-hdr  { color: #f0f6fc; font-weight: 700; } .c-sep  { color: #30363d; }
.c-exp  { color: #79c0ff; } .c-res  { color: #e3b341; } .c-note { color: #d29922; }
.c-ok   { color: #3fb950; border-top: 1px solid #238636; margin-top: 5px; padding-top: 4px; }
.c-ng   { color: #f85149; border-top: 1px solid #da3633; margin-top: 5px; padding-top: 4px; }
.c-err  { color: #f85149; } .c-idle { color: #484f58; font-style: italic; }

/* ── bottom bar ── */
.bot {
  flex-shrink: 0; background: #161b22; border-top: 1px solid #21262d;
  padding: 7px 14px; display: flex; align-items: center; gap: 6px; flex-wrap: wrap;
}
.bot-lbl { font-size: 10px; color: #484f58; font-weight: 700; text-transform: uppercase; letter-spacing: .4px; white-space: nowrap; }
.bot-sep { color: #30363d; }
.bb {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 4px 10px; font-size: 11px; font-weight: 600; cursor: pointer;
  border: 1px solid #30363d; border-radius: 5px; background: #0d1117; color: #8b949e;
  transition: all .15s; white-space: nowrap;
}
.bb:hover  { border-color: #388bfd; color: #79c0ff; background: #0b1c36; }
.bb.bb-run { border-color: #d29922; color: #e3b341; background: #130f00; }
.bb.bb-ok  { border-color: #238636; color: #3fb950; background: #0a1f12; }
.bb.bb-ng  { border-color: #da3633; color: #f85149; background: #2a0c0c; }
.bot-ts { font-size: 10px; color: #484f58; margin-left: auto; }

/* ── journey steps ── */
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
.jstep-name { font-size: 12px; font-weight: 600; flex: 1; }
.j-src  .jstep-name { color: #8b949e; }
.j-pass .jstep-name { color: #3fb950; }
.j-block .jstep-name { color: #f85149; }
.j-skip .jstep-name { color: #484f58; }
.jstep-badge { font-size: 10px; padding: 1px 7px; border-radius: 8px; font-weight: 700; border: 1px solid; white-space: nowrap; }
.jb-src   { background: #21262d; color: #6e7681;  border-color: #30363d; }
.jb-pass  { background: #0d2010; color: #3fb950;  border-color: #238636; }
.jb-block { background: #2a0c0c; color: #f85149;  border-color: #da3633; }
.jb-skip  { background: transparent; color: #30363d; border-color: #21262d; }
.j-reason { font-size: 10.5px; color: #ffa198; font-family: monospace; margin-top: 5px; padding: 5px 8px; background: #1e0e0e; border-radius: 4px; border-left: 2px solid #da3633; line-height: 1.5; word-break: break-word; }
/* ── security insight ── */
.d-why { font-size: 12px; color: #c9d1d9; line-height: 1.65; margin-bottom: 12px; padding: 9px 11px; background: #0d1f38; border-radius: 5px; border-left: 3px solid #388bfd; }

.hidden { display: none !important; }
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
    <a class="svc-btn svc-ki" href="http://localhost:20001" target="_blank">&#x1F578; Kiali</a>
  </div>
</div>

<!-- warning -->
<div class="warn hidden" id="warn">
  &#x26A0; Server offline or make not found &mdash; Animation works, but run from WSL for live make output:
  <code>python3 visualizer/server.py</code> then open <code>http://localhost:5001</code>
</div>

<!-- main split -->
<div class="split">

  <!-- LEFT: scenario cards -->
  <div class="left">
    <div class="tabs" id="tabs">
      <div class="tab active" data-f="all">All <span class="cnt" id="cnt-all">18</span></div>
      <div class="tab" data-f="A">A-Lateral <span class="cnt" id="cnt-A">5</span></div>
      <div class="tab" data-f="B">B-JWT <span class="cnt" id="cnt-B">3</span></div>
      <div class="tab" data-f="C">C-Context <span class="cnt" id="cnt-C">4</span></div>
      <div class="tab" data-f="D">D-Claim <span class="cnt" id="cnt-D">4</span></div>
      <div class="tab" data-f="E">E-Posture <span class="cnt" id="cnt-E">2</span></div>
    </div>
    <div class="cards" id="cards">
      <div class="no-cards">Loading metadata&hellip;</div>
    </div>
  </div>

  <!-- RIGHT: pipeline + detail -->
  <div class="right">

    <div class="pipe-wrap">
      <div class="pipe-hdr">
        <h2>ZTA Security Pipeline</h2>
        <span class="pipe-dir hidden" id="pl-dir"></span>
      </div>

      <!-- North-South pipeline -->
      <div class="pl-row" id="pl-ns">
        <div class="pln inactive" id="node-client">
          <div class="ni">&#x1F4BB;</div><div class="nl">Client</div><div class="ns">Attacker</div>
        </div>
        <div class="pl-arr" id="arr-ns-1">&#x2192;</div>
        <div class="pln inactive" id="node-istio-jwt">
          <div class="ni">&#x1F511;</div><div class="nl">Istio JWT</div><div class="ns">JWKS verify</div>
        </div>
        <div class="pl-arr" id="arr-ns-2">&#x2192;</div>
        <div class="pln inactive" id="node-istio-deny">
          <div class="ni">&#x1F6E1;</div><div class="nl">Istio DENY</div><div class="ns">require-jwt</div>
        </div>
        <div class="pl-arr" id="arr-ns-3">&#x2192;</div>
        <div class="pln inactive" id="node-opa">
          <div class="ni">&#x2696;</div><div class="nl">OPA Policy</div><div class="ns">Rego eval</div>
        </div>
        <div class="pl-arr" id="arr-ns-4">&#x2192;</div>
        <div class="pln inactive" id="node-app">
          <div class="ni">&#x1F5A5;</div><div class="nl">App</div><div class="ns">Flask svc</div>
        </div>
      </div>

      <!-- East-West pipeline -->
      <div class="pl-row hidden" id="pl-ew">
        <div class="pln inactive" id="node-rogue-pod">
          <div class="ni">&#x2620;</div><div class="nl">Rogue Pod</div><div class="ns">compromised</div>
        </div>
        <div class="pl-arr" id="arr-ew-1">&#x2192;</div>
        <div class="pln inactive" id="node-mtls">
          <div class="ni">&#x1F510;</div><div class="nl">mTLS</div><div class="ns">STRICT cert</div>
        </div>
        <div class="pl-arr" id="arr-ew-2">&#x2192;</div>
        <div class="pln inactive" id="node-spiffe">
          <div class="ni">&#x1FAAA;</div><div class="nl">SPIFFE</div><div class="ns">SA allowlist</div>
        </div>
        <div class="pl-arr" id="arr-ew-3">&#x2192;</div>
        <div class="pln inactive" id="node-backend">
          <div class="ni">&#x1F5A5;</div><div class="nl">Backend</div><div class="ns">internal svc</div>
        </div>
      </div>
    </div>

    <div class="detail" id="detail">
      <div class="d-empty">&#x2190; Click a scenario card to see attack details and defense decision</div>
    </div>

  </div><!-- /right -->
</div><!-- /split -->

<!-- terminal -->
<div class="term-wrap">
  <div class="term-bar">
    <div class="dots"><span class="d-r"></span><span class="d-y"></span><span class="d-g"></span></div>
    <span class="term-ttl" id="term-ttl">$ click a scenario card or workflow button to run</span>
    <span class="rbadge rb-idle" id="rbadge">idle</span>
  </div>
  <div class="term-body" id="term">
    <span class="tl c-idle">Waiting for command&hellip;</span>
  </div>
</div>

<!-- bottom bar -->
<div class="bot">
  <span class="bot-lbl">Workflow</span>
  <div class="bb" id="bb-all"         onclick="runW('all')">&#x2B21; all</div>
  <div class="bb" id="bb-step1"       onclick="runW('step1')">&#x1F3D7; step1</div>
  <div class="bb" id="bb-step2"       onclick="runW('step2')">&#x1F680; step2</div>
  <div class="bb" id="bb-step3"       onclick="runW('step3')">&#x1F6E1; step3</div>
  <div class="bb" id="bb-step4"       onclick="runW('step4')">&#x1F510; step4</div>
  <div class="bb" id="bb-test-all"    onclick="runW('test-all')">&#x1F9EA; test-all</div>
  <span class="bot-sep">|</span>
  <div class="bb" id="bb-ports"        onclick="runW('ports')">&#x1F50C; ports</div>
  <div class="bb" id="bb-status"       onclick="runW('status')">&#x1F4CB; status</div>
  <div class="bb" id="bb-jwt-refresh"  onclick="runW('jwt-refresh')">&#x1F504; jwt-refresh</div>
  <div class="bb" id="bb-logs-pretty"  onclick="runW('logs-pretty')">&#x1F4DC; opa-logs</div>
  <div class="bb" id="bb-setup-viewer" onclick="runW('setup-viewer')">&#x1F465; add-viewer</div>
  <span class="bot-ts" id="bot-ts"></span>
</div>

<!-- metadata — plain JSON, read by JS below (no escaping issues) -->
<script type="application/json" id="zta-meta">ZTA_META_JSON</script>

<script>
// ── init META from JSON script tag ────────────────────────────────────────
var META = {};
(function() {
  try {
    META = JSON.parse(document.getElementById('zta-meta').textContent);
  } catch(e) {
    console.error('ZTA: failed to parse META:', e);
  }
})();

// ── constants ─────────────────────────────────────────────────────────────
var ARROW = {
  'istio-jwt':'arr-ns-1', 'istio-deny':'arr-ns-2',
  'opa':'arr-ns-3',       'app':'arr-ns-4',
  'mtls':'arr-ew-1',      'spiffe':'arr-ew-2', 'backend':'arr-ew-3'
};
var NODE_NAMES = {
  'client':     'Client',
  'istio-jwt':  'Istio JWT Auth (JWKS verify)',
  'istio-deny': 'Istio DENY Policy (require-jwt)',
  'opa':        'OPA Policy Engine (Rego eval)',
  'app':        'Application Backend',
  'rogue-pod':  'Rogue Pod (compromised)',
  'mtls':       'mTLS STRICT (cert check)',
  'spiffe':     'SPIFFE Allowlist (SA check)',
  'backend':    'Backend Service'
};

// ── state ─────────────────────────────────────────────────────────────────
var results  = {};
var filter   = 'all';
var selId    = null;
var animBusy = false;
var sse      = null;
var running  = null;

// ── helpers ───────────────────────────────────────────────────────────────
function g(id) { return document.getElementById(id); }
function wait(ms) { return new Promise(function(r) { setTimeout(r, ms); }); }

// ── render stats ─────────────────────────────────────────────────────────
function renderStats() {
  var ids  = Object.keys(META);
  var pass = ids.filter(function(id) { return results[id] && results[id].status === 'PASS'; }).length;
  var fail = ids.filter(function(id) { return results[id] && results[id].status === 'FAIL'; }).length;
  g('s-total').textContent = ids.length;
  g('s-pass').textContent  = pass;
  g('s-fail').textContent  = fail;
}

// ── render cards ──────────────────────────────────────────────────────────
function renderCards() {
  var ids = Object.keys(META);
  if (filter !== 'all') {
    ids = ids.filter(function(id) { return id.indexOf(filter + '-') === 0; });
  }

  if (!ids.length) {
    g('cards').innerHTML = '<div class="no-cards">No scenarios</div>';
    return;
  }

  var html = '';
  for (var i = 0; i < ids.length; i++) {
    var id  = ids[i];
    var m   = META[id];
    var r   = results[id];
    var rid = (running === id);

    var badgeCls, badgeTxt;
    if      (rid)                    { badgeCls = 'b-run';     badgeTxt = '&#x25B6; ...'; }
    else if (!r)                     { badgeCls = 'b-unknown'; badgeTxt = '&mdash;'; }
    else if (r.status === 'PASS')    { badgeCls = 'b-pass';    badgeTxt = 'PASS'; }
    else                             { badgeCls = 'b-fail';    badgeTxt = 'FAIL'; }

    var blk;
    if (!rid && r && r.status === 'FAIL')
      blk = '<span class="blk blk-fail">&#x2717; FAIL</span>';
    else if (!m.block_at)
      blk = '<span class="blk blk-allow">&#x2713; ALLOW</span>';
    else if (m.block_at === 'opa')
      blk = '<span class="blk blk-opa">&#x2717; OPA</span>';
    else
      blk = '<span class="blk blk-istio">&#x2717; Istio</span>';

    var selCls = (selId === id) ? ' sel' : '';
    var runCls = rid ? ' run' : '';
    var codes  = r ? (r.expect + ' &rarr; ' + r.result) : (m.signals.method + ' ' + m.signals.path);

    html += '<div class="tc' + selCls + runCls + '" data-id="' + id + '" onclick="pick(this.dataset.id)">' +
      '<div class="tid">' + id + '</div>' +
      '<div class="ttitle">' + m.title + '</div>' +
      '<div class="tdesc">'  + m.desc  + '</div>' +
      '<div class="tc-row">' +
        '<span class="codes">' + codes + '</span>' +
        '<span class="badge ' + badgeCls + '">' + badgeTxt + '</span>' +
      '</div>' +
      '<div>' + blk + '</div>' +
    '</div>';
  }
  g('cards').innerHTML = html;
}

// ── tab click ─────────────────────────────────────────────────────────────
g('tabs').addEventListener('click', function(e) {
  var tab = e.target.closest('.tab');
  if (!tab) return;
  document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
  tab.classList.add('active');
  filter = tab.dataset.f;
  renderCards();
});

// ── pick scenario ─────────────────────────────────────────────────────────
function pick(id) {
  selId = id;
  var m = META[id];
  if (!m) { console.warn('META missing for', id); return; }

  var ew = (m.pipeline === 'ew');
  g('pl-ns').classList.toggle('hidden',  ew);
  g('pl-ew').classList.toggle('hidden', !ew);
  var dirEl = g('pl-dir');
  dirEl.classList.remove('hidden');
  dirEl.textContent = ew ? 'East-West (Lateral)' : 'North-South';

  renderDetail(id, m);
  resetPipeline(m.flow);
  if (!animBusy) animateFlow(m.flow, m.block_at);
  renderCards();
  runCmd(id);
}

// ── detail pane ───────────────────────────────────────────────────────────
function renderDetail(id, m) {
  var s = m.signals;

  // request signal tags
  var tags = '';
  if (s.method)   tags += '<span class="tag t-m">' + s.method + '</span>';
  if (s.path)     tags += '<span class="tag t-p">' + s.path + '</span>';
  if (s.identity) tags += '<span class="tag t-i">id:' + s.identity + '</span>';
  if (s.role)     tags += '<span class="tag t-r">role:' + s.role + '</span>';
  if (s.posture === 'enabled')  tags += '<span class="tag t-ok">fw:enabled</span>';
  if (s.posture === 'disabled') tags += '<span class="tag t-ng">fw:disabled</span>';
  if (s.sa)       tags += '<span class="tag t-sa">sa:' + s.sa + '</span>';

  // step-by-step request journey
  var journey = '';
  var reachedBlock = false;
  for (var fi = 0; fi < m.flow.length; fi++) {
    var nid    = m.flow[fi];
    var nLabel = NODE_NAMES[nid] || nid;
    var isBlock  = (nid === m.block_at);
    var isSource = (fi === 0);
    var isSkip   = reachedBlock;

    var stepCls, badgeCls, badgeTxt;
    if (isSource) {
      stepCls = 'j-src';   badgeCls = 'jb-src';   badgeTxt = 'source';
    } else if (isSkip) {
      stepCls = 'j-skip';  badgeCls = 'jb-skip';  badgeTxt = 'skipped';
    } else if (isBlock) {
      stepCls = 'j-block'; badgeCls = 'jb-block'; badgeTxt = '&#x2717; BLOCKED HERE';
    } else {
      stepCls = 'j-pass';  badgeCls = 'jb-pass';  badgeTxt = '&#x2713; passed';
    }

    journey += '<div class="jstep ' + stepCls + '"><div class="jstep-body">';
    journey += '<div class="jstep-row"><span class="jstep-name">' + nLabel + '</span>';
    journey += '<span class="jstep-badge ' + badgeCls + '">' + badgeTxt + '</span></div>';
    if (isBlock) {
      journey += '<div class="j-reason">' + m.block_reason + '</div>';
    }
    journey += '</div></div>';
    if (isBlock) reachedBlock = true;
  }

  var isDeny = (m.block_at !== null && m.block_at !== undefined);
  var verdict = isDeny ? '&#x2717; BLOCKED' : '&#x2713; ALLOWED';
  var vcls    = isDeny ? 'v-deny' : 'v-allow';

  var layer = m.defense_layer
    ? '<div class="d-layer">&#x1F6E1; Defense layer: <strong>' + m.defense_layer + '</strong></div>'
    : '';

  var insight = m.why
    ? '<div class="d-sec">Why it was blocked</div><div class="d-why">' + m.why + '</div>'
    : '';

  g('detail').innerHTML =
    '<div class="d-sec">Attack &mdash; ' + id + '</div>' +
    '<div class="d-desc">' + m.desc + '</div>' +
    '<div class="tags">' + tags + '</div>' +
    '<div class="d-sec">Request Journey</div>' +
    '<div class="journey">' + journey + '</div>' +
    '<div class="verdict ' + vcls + '">' + verdict + '</div>' +
    layer +
    insight +
    '<div class="d-make">&#x1F9EA; make target: <code style="color:#79c0ff">' + m.make + '</code></div>';
}

// ── run make command ──────────────────────────────────────────────────────
function runCmd(id) {
  if (sse) { sse.close(); sse = null; }

  running = id;
  renderCards();

  var badge = g('rbadge');
  var label = META[id] ? META[id].make : id;
  badge.className   = 'rbadge rb-run';
  badge.textContent = 'running';
  g('term-ttl').textContent = '$ make --no-print-directory ' + label;

  var term = g('term');
  term.innerHTML = '';
  addLine('$ make --no-print-directory ' + label, 'c-hdr');
  addLine('------------------------------------------', 'c-sep');

  sse = new EventSource('/api/run/' + id);

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
      renderCards();
      renderStats();
      return;
    }
    addLine(d.line);
  };

  sse.onerror = function() {
    if (sse) { sse.close(); sse = null; }
    running = null;
    badge.className   = 'rbadge rb-idle';
    badge.textContent = 'idle';
    addLine('ERROR: server unreachable or make not found', 'c-err');
    addLine('Run from WSL: python3 visualizer/server.py', 'c-err');
    renderCards();
  };
}

// ── workflow buttons ──────────────────────────────────────────────────────
function runW(id) {
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

// ── terminal line ─────────────────────────────────────────────────────────
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
  if (/^EXPECT:/.test(l))             return 'c-exp';
  if (/^RESULT:/.test(l))             return 'c-res';
  if (/^>>>/.test(l) || /^\\[.+\\]/.test(l)) return 'c-hdr';
  if (/^[=\\-]{3,}/.test(l))          return 'c-sep';
  if (/^(NOTE|WARNING):/.test(l))     return 'c-note';
  if (l.indexOf('SCENARIO') >= 0 && l.indexOf('PASS') >= 0) return 'c-pass';
  if (l.indexOf('SCENARIO') >= 0 && l.indexOf('FAIL') >= 0) return 'c-fail';
  return '';
}

// ── pipeline animation ────────────────────────────────────────────────────
function resetPipeline(flow) {
  flow.forEach(function(id) {
    var el = g('node-' + id);
    if (el) el.className = 'pln inactive';
  });
  Object.keys(ARROW).forEach(function(key) {
    var el = g(ARROW[key]);
    if (el) el.className = 'pl-arr';
  });
}

function animateFlow(flow, blockAt) {
  animBusy = true;
  var i = 0;
  function step() {
    if (i >= flow.length) { animBusy = false; return; }
    var nid = flow[i];
    var el  = g('node-' + nid);
    if (!el) { i++; step(); return; }

    if (i > 0) {
      var arr = g(ARROW[nid]);
      if (arr) arr.className = 'pl-arr ' + (nid === blockAt ? 'blocked' : 'ok');
    }

    if (nid === blockAt) {
      el.className = 'pln blocked';
      for (var j = i + 1; j < flow.length; j++) {
        var e = g('node-' + flow[j]);
        if (e) e.className = 'pln unreachable';
      }
      animBusy = false;
      return;
    } else {
      el.className = (i === flow.length - 1) ? 'pln allowed' : 'pln passed';
    }
    i++;
    setTimeout(step, 320);
  }
  setTimeout(step, 320);
}

// ── load test results from server ─────────────────────────────────────────
function load() {
  fetch('/api/data')
    .then(function(r) { return r.json(); })
    .then(function(d) {
      results = d.results || {};
      g('warn').classList.add('hidden');
      g('bot-ts').textContent = 'updated ' + new Date().toLocaleTimeString();
      renderStats();
      renderCards();
    })
    .catch(function() {
      g('warn').classList.remove('hidden');
      g('bot-ts').textContent = 'server offline';
    });
}

// ── startup ───────────────────────────────────────────────────────────────
renderCards();
renderStats();
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
            payload = {"results": parse_test_summary(), "opa_logs": parse_opa_logs()}
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
            emit({"line": "ERROR: 'make' not found. Run from WSL:"})
            emit({"line": "  python3 visualizer/server.py"})
            emit({"done": True, "status": "FAIL", "exit_code": 127})
        except Exception as e:
            emit({"line": "ERROR: " + str(e)})
            emit({"done": True, "status": "FAIL", "exit_code": 1})

    def log_message(self, fmt, *args):
        pass


# ── entry ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # quick sanity check
    html = build_html()
    assert "ZTA_META_JSON" not in html, "META injection failed!"
    assert '"A-NS-1"' in html, "META content missing!"
    print("ZTA Dashboard  ->  http://localhost:%d" % PORT)
    print("Project root   :  %s" % BASE)
    print("META scenarios :  %d loaded" % len(TEST_META))
    print("Run from WSL for 'make' to work. Ctrl+C to stop.\n")
    try:
        ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
