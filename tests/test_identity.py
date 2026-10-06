"""Keycloak component updates retain omitted fields; restoration must restore effective defaults."""
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('identity_regression', Path(__file__).resolve().parents[1] / 'scripts/identity.py')
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)


class IdentityRestorationTests(unittest.TestCase):
    def test_enabled_default_restored_before_temporary_signer_deleted(self):
        providers = {'old': {'id': 'old', 'name': 'rsa-generated', 'providerId': 'rsa-generated', 'config': {'priority': ['100']}}}

        def admin(_runtime, _token, method, path, data=None):
            if method == 'GET':
                if path == '/': return {'id': 'realm'}
                if path.startswith('/components?'): return copy.deepcopy(list(providers.values()))
                return copy.deepcopy(providers[path.rsplit('/', 1)[-1]])
            if method == 'POST':
                providers['new'] = {**copy.deepcopy(data), 'id': 'new'}
            elif method == 'PUT':
                # Reproduce Keycloak's retention of omitted component config fields.
                providers[path.rsplit('/', 1)[-1]]['config'].update(copy.deepcopy(data['config']))
            elif method == 'DELETE':
                self.assertEqual(providers['old']['config'].get('enabled', ['true']), ['true'])
                del providers[path.rsplit('/', 1)[-1]]

        def jwks(_runtime):
            return {'keys': [{'kid': key, 'alg': 'RS256'} for key, value in providers.items()
                             if value['config'].get('enabled', ['true']) == ['true']]}

        class Runtime:
            def sync_jwks(self): self.jwks = jwks(self)

        with patch.object(identity, '_admin_token', return_value='fixture'), patch.object(identity, '_admin', admin), patch.object(identity, 'fetch_jwks', jwks):
            with self.assertRaisesRegex(RuntimeError, 'injected failure'):
                with identity.rotate_keys(Runtime()):
                    providers['old']['config']['enabled'] = ['false']
                    raise RuntimeError('injected failure after retirement')
        self.assertEqual(set(providers), {'old'})
        self.assertEqual(providers['old']['config']['enabled'], ['true'])


if __name__ == '__main__':
    unittest.main()
