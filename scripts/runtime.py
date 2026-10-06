"""Scoped local Kubernetes runtime. All writes target the private v2 profile."""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import time
import urllib.request
from contextlib import contextmanager
import tempfile
import shutil
import ipaddress

import yaml

ROOT = Path(__file__).resolve().parents[1]
MODES = ('sidecar', 'mtls', 'jwt', 'opa-role', 'strict')


def redact(text):
    text = re.sub(r'\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\b', '[JWT REDACTED]', str(text))
    return re.sub(r'(?i)("(?:access_token|refresh_token|client_secret)"\s*:\s*)"[^"]*"', r'\1"[REDACTED]"', text)


class RuntimeError(Exception):
    pass


class Runtime:
    profile = namespace = 'zta-v2'
    keycloak_url = 'http://localhost:18081'
    issuer = keycloak_url + '/realms/zta-v2'

    def __init__(self):
        self.source_root = ROOT
        self.state = Path.home() / '.local/share/zta-v2'
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.env = dict(os.environ, MINIKUBE_HOME=str(self.state / 'minikube'), KUBECONFIG=str(self.state / 'kubeconfig'))
        self.mode = 'strict'
        self.image = None
        self.jwks = {'keys': []}
        self.config_ready = False
        if (self.state / 'jwks.json').exists():
            self.jwks = json.loads((self.state / 'jwks.json').read_text())
        if (self.state / 'mode').exists():
            self.mode = (self.state / 'mode').read_text().strip()
        self.istio_dir = ROOT / 'istio-1.28.3'
        if not self.istio_dir.is_dir():
            self.istio_dir = ROOT.parent.parent / 'zta-project/istio-1.28.3'
        self.istioctl = str(self.istio_dir / 'bin/istioctl')

    def run(self, argv, input=None, check=True, timeout=300, env=None):
        if str(argv[0]) == self.istioctl:
            argv = [*argv, '--context', self.profile]
        result = subprocess.run([str(x) for x in argv], input=input, text=True, capture_output=True,
                                env=env or self.env, cwd=ROOT, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(redact('Command failed: ' + str(argv[0]) + '\n' + result.stderr[-4000:] + result.stdout[-2000:]))
        return result

    def kubectl_argv(self, *args):
        if self.env.get('KUBECONFIG') != str(self.state / 'kubeconfig'):
            raise RuntimeError('Refusing Kubernetes command with an unscoped config')
        return ['minikube', '-p', self.profile, 'kubectl', '--', '--context', self.profile, '-n', self.namespace, *map(str, args)]

    def kubectl_process(self, *args, input=None, check=False, timeout=300):
        return self.run(self.kubectl_argv(*args), input=input, check=check, timeout=timeout)

    def kubectl(self, *args, input=None, json_output=False, check=True, timeout=300):
        argv = list(args)
        if json_output and '-o' not in argv and '--output' not in argv:
            argv += ['-o', 'json']
        result = self.kubectl_process(*argv, input=input, check=check, timeout=timeout)
        if json_output:
            return json.loads(result.stdout)
        return result.stdout

    def apply(self, objects):
        content = yaml.safe_dump_all(objects, sort_keys=False)
        self.kubectl('apply', '-f', '-', input=content)

    def bootstrap(self):
        print('Stopping original minikube profile (data retained)', flush=True)
        baseline_env = dict(os.environ)
        baseline_env.pop('MINIKUBE_HOME', None)
        baseline_env.pop('KUBECONFIG', None)
        result = self.run(['minikube', '-p', 'minikube', 'stop'], env=baseline_env)
        print(redact(result.stdout).strip(), flush=True)
        print('Starting isolated zta-v2 profile: Kubernetes1.34 / Calico / containerd / 4CPU8GB', flush=True)
        result = self.run(['minikube', '-p', self.profile, 'start', '--driver=docker', '--container-runtime=containerd',
                           '--cni=calico', '--cpus=4', '--memory=8192', '--kubernetes-version=v1.34.0'], timeout=900)
        print(redact(result.stdout[-4000:]), flush=True)
        current = self.kubectl('config', 'current-context').strip()
        if current != self.profile:
            raise RuntimeError('Wrong context: ' + current)

    def install_mesh(self):
        print('Installing isolated Istio and observability', flush=True)
        present = self.kubectl_process('get', 'deployment', 'istiod', '-n', 'istio-system')
        if present.returncode:
            self.run([self.istioctl, 'install', '--set', 'profile=demo', '--set',
                      'meshConfig.pathNormalization.normalization=DECODE_AND_MERGE_SLASHES', '-y'], timeout=600)
        addons = self.istio_dir / 'samples/addons'
        for name in ('prometheus.yaml', 'grafana.yaml', 'kiali.yaml'):
            self.kubectl('apply', '-n', 'istio-system', '-f', str(addons / name))
        self.apply([{'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': self.namespace,
                    'labels': {'istio-injection': 'enabled'}}}])
        cm = self.kubectl('get', 'configmap', 'istio', '-n', 'istio-system', json_output=True)
        mesh = yaml.safe_load(cm['data']['mesh'])
        providers = [p for p in mesh.get('extensionProviders', []) if p['name'] != 'opa-provider']
        providers.append({'name': 'opa-provider', 'envoyExtAuthzGrpc': {'service': 'opa.zta-v2.svc.cluster.local',
                          'port': '9191', 'timeout': '1s', 'failOpen': False}})
        mesh['extensionProviders'] = providers
        mesh['pathNormalization'] = {'normalization': 'DECODE_AND_MERGE_SLASHES'}
        mesh['accessLogFile'] = '/dev/stdout'
        mesh['accessLogEncoding'] = 'JSON'
        mesh['accessLogFormat'] = json.dumps({'time': '%START_TIME%', 'request_id': '%REQ(X-REQUEST-ID)%',
          'method': '%REQ(:METHOD)%', 'path': '%REQ(:PATH)%', 'response_code': '%RESPONSE_CODE%',
          'response_flags': '%RESPONSE_FLAGS%', 'response_code_details': '%RESPONSE_CODE_DETAILS%',
          'downstream_remote': '%DOWNSTREAM_REMOTE_ADDRESS%', 'upstream_transport_failure': '%UPSTREAM_TRANSPORT_FAILURE_REASON%'})
        cm['data']['mesh'] = yaml.safe_dump(mesh)
        cm.pop('status', None)
        self.kubectl('replace', '-n', 'istio-system', '-f', '-', input=json.dumps(cm))
        self.kubectl('rollout', 'restart', 'deployment/istiod', '-n', 'istio-system')
        self.kubectl('rollout', 'status', 'deployment/istiod', '-n', 'istio-system', '--timeout=300s')

    def build_image(self, context=None):
        context = Path(context or ROOT / 'app')
        files = sorted(p for p in context.rglob('*') if p.is_file() and '__pycache__' not in p.parts)
        digest = hashlib.sha256()
        for path in files:
            digest.update(str(path.relative_to(context.parent)).encode())
            digest.update(path.read_bytes())
        revision = self.run(['git', 'rev-parse', '--short=12', 'HEAD']).stdout.strip()
        self.image = 'zta-app:' + revision + '-' + digest.hexdigest()[:12]
        print('Building immutable app image ' + self.image, flush=True)
        self.run(['minikube', '-p', self.profile, 'image', 'build', '-t', self.image, str(context)], timeout=900)
        (self.state / 'image').write_text(self.image)
        images = json.loads(self.run(['minikube', '-p', self.profile, 'image', 'ls', '--format=json']).stdout)
        built = [item['id'] for item in images if any(tag.endswith('/' + self.image) or tag == self.image for tag in item.get('repoTags', []))]
        if len(built) != 1:
            raise RuntimeError('Native build image ID could not be confirmed')
        (self.state / 'image-id').write_text(built[0])
        return self.image

    def rendered_resources(self, mode):
        if mode not in MODES:
            raise RuntimeError('Unknown policy mode')
        image = self.image or (self.state / 'image').read_text().strip()
        text = (ROOT / 'k8s/v2-resources.yaml').read_text()
        text = text.replace('__APP_IMAGE__', image).replace('__ISSUER__', self.issuer)
        text = text.replace('__INLINE_JWKS__', json.dumps(self.jwks, separators=(',', ':')))
        resources = [r for r in yaml.safe_load_all(text) if r]
        output = []
        for item in resources:
            kind, spec = item['kind'], item.get('spec', {})
            if kind == 'RequestAuthentication':
                if mode in ('sidecar', 'mtls'):
                    continue
                for rule in spec.get('jwtRules', []):
                    rule['issuer'] = self.issuer
                    rule.pop('jwksUri', None)
                    rule['jwks'] = json.dumps(self.jwks)
            if kind == 'AuthorizationPolicy':
                if mode == 'sidecar':
                    continue
                if spec.get('action') == 'CUSTOM' and mode not in ('opa-role', 'strict'):
                    continue
                if item['metadata']['name'].startswith('require-jwt') and mode in ('sidecar', 'mtls'):
                    continue
                if mode == 'mtls' and item['metadata']['name'] == 'backend-allow-frontend-only':
                    for rule in spec.get('rules', []):
                        for source in rule.get('from', []):
                            source.get('source', {}).pop('requestPrincipals', None)
            if kind == 'PeerAuthentication':
                spec['mtls'] = {'mode': 'PERMISSIVE' if mode == 'sidecar' else 'STRICT'}
            output.append(item)
        for service in ('frontend', 'backend'):
            output.append({'apiVersion': 'networking.istio.io/v1', 'kind': 'DestinationRule',
             'metadata': {'name': service + '-tls', 'namespace': self.namespace},
             'spec': {'host': service, 'trafficPolicy': {'tls': {'mode': 'DISABLE' if mode == 'sidecar' else 'ISTIO_MUTUAL'}}}})
        output.append({'apiVersion': 'v1', 'kind': 'Service',
            'metadata': {'name': 'fortio-client', 'namespace': self.namespace},
            'spec': {'selector': {'app': 'fortio-client'}, 'ports': [{'port': 8080, 'targetPort': 8080}]}})
        trust = {'jwt_trust': {'issuer': self.issuer, 'jwks': self.jwks, 'mode': mode, 'posture_max_age': 120}}
        output += [{'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'jwt-trust', 'namespace': self.namespace},
                    'data': {'jwt_trust.json': json.dumps(trust)}},
                   {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'opa-policy', 'namespace': self.namespace},
                    'data': {'policy.rego': (ROOT / 'k8s/policy.rego').read_text(),
                             'mask.rego': (ROOT / 'k8s/mask.rego').read_text()}}]
        return output

    def apply_mode(self, mode):
        self.config_ready = False
        print('Applying isolated policy mode: ' + mode, flush=True)
        if not self.jwks.get('keys') and (self.state / 'jwks.json').exists():
            self.jwks = json.loads((self.state / 'jwks.json').read_text())
        # Remove previously generated security policies before applying the fixed desired state.
        self.kubectl('delete', 'authorizationpolicy,requestauthentication,peerauthentication,destinationrule',
                     '--all', '--ignore-not-found')
        self.apply(self.rendered_resources(mode))
        self.mode = mode
        (self.state / 'mode').write_text(mode)
        self.kubectl('rollout', 'restart', 'deployment/opa')
        self.wait_ready()

    def wait_ready(self):
        self.config_ready = False
        deployments = self.kubectl('get', 'deployments', json_output=True)['items']
        required = {'frontend', 'backend', 'keycloak', 'opa', 'curl-client', 'rogue-client', 'wrongsa-client', 'frontend-probe', 'fortio-client'}
        found = {d['metadata']['name'] for d in deployments}
        if not required <= found:
            raise RuntimeError('Missing deployments: ' + ','.join(sorted(required - found)))
        if any(d['metadata']['name'] in required and d['spec'].get('replicas', 1) < 1 for d in deployments):
            raise RuntimeError('Required deployment scaled to zero')
        for name in sorted(required):
            self.kubectl('rollout', 'status', 'deployment/' + name, '--timeout=300s', timeout=310)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            pods = self.kubectl('get', 'pods', json_output=True)['items']
            active = [p for p in pods if not p['metadata'].get('deletionTimestamp')]
            mesh_apps = required - {'opa', 'rogue-client'}
            injected = {p['metadata'].get('labels', {}).get('app') for p in active
                        if any(c['name'] == 'istio-proxy' for c in p['spec']['containers'] + p['spec'].get('initContainers', []))}
            if not mesh_apps <= injected:
                raise RuntimeError('Required proxy missing: ' + ','.join(sorted(mesh_apps - injected)))
            expected = {p['metadata']['name'] + '.' + self.namespace for p in pods
                        if any(c['name'] == 'istio-proxy' for c in p['spec']['containers'] + p['spec'].get('initContainers', [])) and not p['metadata'].get('deletionTimestamp')}
            status = self.run([self.istioctl, 'proxy-status', '-o', 'json'], check=False)
            try:
                try:
                    rows = json.loads(status.stdout)
                except ValueError:
                    # Istio delta-xDS currently returns a table even with --output=json.
                    rows = [{'proxy': line.split()[0]} for line in status.stdout.splitlines()[1:] if line.strip()]
                if isinstance(rows, dict):
                    rows = rows.get('syncStatus', rows.get('items', []))
                by_id = {r.get('proxy', r.get('proxyId', r.get('name', ''))): r for r in rows}
                # Older clients may return a different JSON shape: fall back to the actual config diff.
                ok = bool(expected) and expected <= set(by_id)
                if ok:
                    self.config_ready = True
                    for proxy_id in expected:
                        row = by_id[proxy_id]
                        found_ack = False
                        for key in ('cluster_sent', 'listener_sent', 'route_sent', 'endpoint_sent'):
                            ack = key.replace('_sent', '_acked')
                            if key in row:
                                found_ack = True
                                if row.get(key) != row.get(ack):
                                    ok = False
                        if not found_ack:
                            diff = self.run([self.istioctl, 'proxy-status', proxy_id], check=False, timeout=30)
                            if diff.returncode or not all(marker in diff.stdout for marker in
                                ('Clusters Match', 'Listeners Match', 'Routes Match')):
                                ok = False
                if ok:
                    print('Ready: all expected Envoy proxies acknowledged config', flush=True)
                    return
            except (ValueError, TypeError):
                pass
            time.sleep(3)
        raise RuntimeError('Expected proxy/config acknowledgement not confirmed within120s')

    def port_forwards(self):
        for label, namespace, service, mapping in [('keycloak', self.namespace, 'keycloak', '18081:8080'),
            ('kiali', 'istio-system', 'kiali', '20010:20001'), ('grafana', 'istio-system', 'grafana', '20012:3000')]:
            pidfile = self.state / (label + '.pid')
            if pidfile.exists():
                try:
                    pid = int(pidfile.read_text())
                    command = Path('/proc/' + str(pid) + '/cmdline').read_bytes().replace(b'\0', b' ').decode()
                    if 'port-forward' in command and mapping in command and self.profile in command:
                        os.kill(pid, 15)
                except (ValueError, FileNotFoundError, ProcessLookupError):
                    pass
            log = open(self.state / (label + '-forward.log'), 'a')
            process = subprocess.Popen(self.kubectl_argv('port-forward', '-n', namespace, 'svc/' + service,
                                       mapping, '--address=127.0.0.1'), env=self.env, stdout=log, stderr=log,
                                       start_new_session=True)
            log.close()
            pidfile.write_text(str(process.pid))
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(self.keycloak_url + '/realms/master', timeout=2) as response:
                    if response.status == 200:
                        return
            except OSError:
                time.sleep(1)
        raise RuntimeError('Keycloak localhost forwarding unavailable')

    def sync_jwks(self):
        from identity import fetch_jwks
        self.jwks = fetch_jwks(self)
        if not self.jwks.get('keys'):
            raise RuntimeError('Empty JWKS snapshot')
        (self.state / 'jwks.json').write_text(json.dumps(self.jwks))
        self.apply_mode(self.mode)
        observed = self.opa_query('data.jwt_trust')
        if observed['jwks'] != self.jwks:
            raise RuntimeError('OPA and Istio JWKS snapshots differ')
        print('JWKS shared fingerprint: ' + hashlib.sha256(json.dumps(self.jwks, sort_keys=True).encode()).hexdigest(), flush=True)

    def opa_query(self, query):
        # The query goes in a JSON request on stdin; credentials never enter argv.
        expression = 'http.send({"method":"POST","url":"http://127.0.0.1:8181/v1/query","body":input}).body'
        output = self.kubectl('exec', '-i', 'deploy/opa', '--', '/opa', 'eval', '--stdin-input', '--format=raw',
                             expression, input=json.dumps({'query': 'result = ' + query}))
        document = json.loads(output)
        if 'error' in document or 'code' in document:
            raise RuntimeError('OPA query failed')
        rows = document.get('result', [])
        if not rows:
            return None
        row = rows[0]
        if 'expressions' in row:
            return row['expressions'][0]['value']
        return next(iter(row.values()))

    def app_image_ids(self):
        pods = self.kubectl('get', 'pods', json_output=True)['items']
        return {p['metadata']['labels'].get('app'): c['imageID'] for p in pods
                if p['metadata']['labels'].get('app') in ('frontend', 'backend') and not p['metadata'].get('deletionTimestamp')
                for c in p.get('status', {}).get('containerStatuses', []) if c['name'] == 'app'}

    def network_drop_snapshot(self, app):
        if app != 'opa':
            raise RuntimeError('Unsupported network evidence target')
        pod_ip = str(ipaddress.ip_address(self.kubectl('get', 'pods', '-l', 'app=opa', '-o', 'jsonpath={.items[0].status.podIP}').strip()))
        route = self.run(['minikube', '-p', self.profile, 'ssh', '--', 'ip route get ' + pod_ip]).stdout
        match = re.search(r'dev (cali[a-zA-Z0-9]+)', route)
        if not match:
            raise RuntimeError('OPA Calico workload interface missing')
        chain = 'cali-tw-' + match[1]
        table = self.run(['minikube', '-p', self.profile, 'ssh', '--', 'sudo iptables-save -c']).stdout
        rules = [line for line in table.splitlines() if '-A ' + chain + ' ' in line and 'End of tier default. Drop if no policies passed packet' in line and line.endswith('-j DROP')]
        if len(rules) != 1:
            raise RuntimeError('OPA ingress DROP counter missing or ambiguous')
        counter = re.match(r'\[(\d+):(\d+)\] (.*)', rules[0])
        return {'pod_ip': pod_ip, 'chain': chain, 'drop_packets': int(counter[1]), 'rule_sha256': hashlib.sha256(counter[3].encode()).hexdigest()}

    def live_contract(self):
        observations = {}
        for name, audience in [('frontend', 'zta-frontend'), ('backend', 'zta-backend')]:
            pods = self.kubectl('get', 'pods', '-l', 'app=' + name, json_output=True)['items']
            pod = next(p['metadata']['name'] for p in pods if not p['metadata'].get('deletionTimestamp'))
            listeners = json.loads(self.run([self.istioctl, 'proxy-config', 'listeners', pod, '-n', self.namespace, '-o', 'json']).stdout)
            configs = [f['typedConfig'] for listener in listeners for chain in listener.get('filterChains', [])
                       if chain.get('filterChainMatch', {}).get('destinationPort') == 8080
                       for f in chain.get('filters', []) if 'httpFilters' in f.get('typedConfig', {})]
            if not configs:
                raise RuntimeError(name + ' inbound listener 8080 missing')
            for config in configs:
                filters = {f['name']: f for f in config['httpFilters']}
                if not {'envoy.filters.http.jwt_authn', 'envoy.filters.http.ext_authz', 'envoy.filters.http.rbac'} <= set(filters):
                    raise RuntimeError(name + ' live authentication/authorization filters missing')
                if not config.get('normalizePath') or not config.get('mergeSlashes') or config.get('pathWithEscapedSlashesAction') != 'UNESCAPE_AND_FORWARD':
                    raise RuntimeError(name + ' live path normalization differs')
                providers = filters['envoy.filters.http.jwt_authn']['typedConfig']['providers'].values()
                if not any(p.get('issuer') == self.issuer and audience in p.get('audiences', [])
                           and json.loads(p.get('localJwks', {}).get('inlineString', '{}')) == self.jwks for p in providers):
                    raise RuntimeError(name + ' live JWKS/issuer/audience differs from shared snapshot')
            observations[name] = {'listener': 8080, 'jwt': True, 'opa': True, 'path_normalization': 'DECODE_AND_MERGE_SLASHES'}
        images = json.loads(self.run(['minikube', '-p', self.profile, 'image', 'ls', '--format=json']).stdout)
        tag = self.image or (self.state / 'image').read_text().strip()
        built = next((item['id'] for item in images if any(t.endswith('/' + tag) or t == tag for t in item.get('repoTags', []))), None)
        deployed = self.app_image_ids()
        if not built or set(deployed) != {'frontend', 'backend'} or set(deployed.values()) != {built}:
            raise RuntimeError('Deployed app image IDs differ from native build')
        observations['app_image_ids'] = deployed
        code = 'import sys,json,importlib.metadata as m;print(json.dumps({"python":sys.version.split()[0],"flask":m.version("Flask"),"requests":m.version("requests")}))'
        versions = json.loads(self.kubectl('exec', 'deploy/backend', '-c', 'app', '--', 'python', '-B', '-c', code))
        if not versions['python'].startswith('3.12.') or versions['flask'] != '3.1.3' or versions['requests'] != '2.32.5':
            raise RuntimeError('Deployed Python/Flask/requests versions differ from contract')
        observations['app_versions'] = versions
        observations['clock_max_skew_seconds'] = abs(time.time() - self.opa_query('time.now_ns() / 1000000000'))
        if observations['clock_max_skew_seconds'] > 5:
            raise RuntimeError('OPA/issuance host clock skew exceeds 5 seconds')
        observations['keycloak_clock_skew_seconds'] = abs(time.time() - float(self.kubectl('exec', 'deploy/keycloak', '-c', 'keycloak', '--', 'date', '+%s').strip()))
        if observations['keycloak_clock_skew_seconds'] > 5:
            raise RuntimeError('Keycloak clock skew exceeds 5 seconds')
        return observations

    def app_unit_check(self, evidence_file):
        code = "import sys; __file__='/tests/test_app.py'; exec(compile(sys.stdin.read(),__file__,'exec'),globals())"
        result = self.kubectl_process('exec', '-i', 'deploy/backend', '-c', 'app', '--', 'python', '-B', '-c', code,
                                     input=(ROOT / 'tests/test_app.py').read_text(), check=False)
        text = result.stderr + result.stdout
        evidence_file.write_text(redact(text))
        if result.returncode or not re.search(r'Ran 4 tests', text) or not re.search(r'\bOK\b', text):
            raise RuntimeError('Deployed Python3.12 app unit regressions failed')
        self.app_unit_evidence = {'level': 'unit', 'kubectl_exit': result.returncode, 'cases': 4, 'evidence': evidence_file.name,
                                  'assertions': ['identity forwarding and upstream status/type preservation', 'timeout504 and connection502', 'bounded JSON object simulation', 'safe health']}
        return self.app_unit_evidence

    def rebuild_probe(self):
        original_image = self.image or (self.state / 'image').read_text().strip()
        before = self.app_image_ids()
        original_id = before.get('frontend')
        original_source = hashlib.sha256((ROOT / 'app/app.py').read_bytes()).hexdigest()
        try:
            with tempfile.TemporaryDirectory(prefix='zta-build-probe-', dir=self.state) as directory:
                context = Path(directory) / 'app'
                shutil.copytree(ROOT / 'app', context, ignore=shutil.ignore_patterns('__pycache__'))
                with (context / 'app.py').open('a') as source:
                    source.write('\n# isolated rebuild probe: ' + str(time.time_ns()) + '\n')
                changed = self.build_image(context)
                for name in ('frontend', 'backend'):
                    self.kubectl('set', 'image', 'deployment/' + name, 'app=' + changed)
                self.wait_ready()
                after = self.app_image_ids()
                from zta import canaries
                canaries(self)
                if changed == original_image or set(before) != {'frontend', 'backend'} or set(after) != set(before) or any(before[k] == after[k] for k in before) or set(after.values()) != {(self.state / 'image-id').read_text().strip()}:
                    raise RuntimeError('Source change did not produce and deploy a new image')
                return {'before_tag': original_image, 'after_tag': changed, 'before_ids': before, 'after_ids': after,
                        'original_source_unchanged': hashlib.sha256((ROOT / 'app/app.py').read_bytes()).hexdigest() == original_source}
        finally:
            self.image = original_image
            (self.state / 'image').write_text(original_image)
            if original_id:
                (self.state / 'image-id').write_text(original_id)
            for name in ('frontend', 'backend'):
                self.kubectl('set', 'image', 'deployment/' + name, 'app=' + original_image)
            self.wait_ready()
            from zta import canaries
            canaries(self)

    @contextmanager
    def fault(self, name):
        if name not in ('opa', 'backend', 'keycloak', 'frontend-probe'):
            raise RuntimeError('Unsupported fault target')
        deployment = self.kubectl('get', 'deployment', name, json_output=True)
        replicas = deployment['spec'].get('replicas', 1)
        try:
            self.kubectl('scale', 'deployment/' + name, '--replicas=0')
            self.kubectl('wait', '--for=delete', 'pod', '-l', 'app=' + name, '--timeout=120s')
            yield {'target': name, 'replicas_before': replicas, 'fault': 'scaled-to-zero'}
        finally:
            self.kubectl('scale', 'deployment/' + name, '--replicas=' + str(replicas))
            self.kubectl('rollout', 'status', 'deployment/' + name, '--timeout=300s', timeout=310)
            if name == 'keycloak':
                self.port_forwards()
            self.wait_ready()

    def start(self):
        self.bootstrap()
        self.install_mesh()
        self.build_image()
        # Empty trust is deliberately denying until identity provisioning completes.
        self.apply(self.rendered_resources('mtls'))
        self.wait_ready()
        self.port_forwards()
        from identity import provision
        provision(self)
        self.mode = 'strict'
        self.sync_jwks()

    def manifest(self):
        return {'profile': self.profile, 'namespace': self.namespace, 'mode': self.mode,
                'commit': self.run(['git', 'rev-parse', 'HEAD']).stdout.strip(), 'app_image': self.image or
                ((self.state / 'image').read_text().strip() if (self.state / 'image').exists() else None),
                'jwks_sha256': hashlib.sha256(json.dumps(self.jwks, sort_keys=True).encode()).hexdigest(),
                'cpu': 4, 'memory_mb': 8192, 'kubernetes': '1.34.0', 'istio': '1.28.3',
                'source_sha256': self.source_fingerprint()}

    def source_fingerprint(self):
        files = [p for directory in ('app','k8s','scripts','tests','visualizer') for p in (ROOT / directory).rglob('*')
                 if p.is_file() and '__pycache__' not in p.parts and (p.suffix in ('.py','.sh','.rego','.yaml','.html','.json','.txt') or p.name == 'Dockerfile')]
        files += [ROOT / 'Makefile', ROOT / 'Launch-ZTA.ps1']
        digest = hashlib.sha256()
        for file in sorted(files):
            digest.update(str(file.relative_to(ROOT)).encode())
            digest.update(file.read_bytes())
        return digest.hexdigest()

    def stop(self):
        self.run(['minikube', '-p', self.profile, 'stop'])


if __name__ == '__main__':
    import sys
    instance = Runtime()
    if sys.argv[1:] == ['bootstrap']:
        instance.bootstrap()
    elif sys.argv[1:] == ['install-mesh']:
        instance.install_mesh()
    else:
        print('Use scripts/zta.py')
