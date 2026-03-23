import sys, json
try:
    import yaml
except ImportError:
    import subprocess
    subprocess.run(['pip3', 'install', 'pyyaml', '-q'])
    import yaml

cm = json.load(sys.stdin)
mesh = yaml.safe_load(cm['data']['mesh'])
prov = [p for p in mesh.get('extensionProviders', []) if p.get('name') != 'opa-provider']
prov.append({
    'name': 'opa-provider',
    'envoyExtAuthzGrpc': {
        'service': 'opa.default.svc.cluster.local',
        'port': '9191'
    }
})
mesh['extensionProviders'] = prov
cm['data']['mesh'] = yaml.dump(mesh, default_flow_style=False)
json.dump(cm, sys.stdout)
