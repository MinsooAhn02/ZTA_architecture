"""Idempotent Keycloak demo-realm provisioning and short-lived JWT issuance."""

import json
import base64
import copy
import secrets
import time
from contextlib import contextmanager
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


REALM = "zta-v2"
ISSUER_PATH = "/realms/zta-v2"
CLIENTS = {
    "zta-app": {
        "secret": "zta-app-demo-secret",
        "lifespan": "300",
        "audiences": ("zta-frontend", "zta-backend"),
    },
    "zta-posture": {
        "secret": "zta-posture-demo-secret",
        "lifespan": "120",
        "audiences": ("zta-posture",),
    },
}
USERS = {
    "admin-user": ("adminpass", ("admin", "posture-healthy")),
    "viewer-user": ("viewerpass", ("viewer", "posture-healthy")),
    "unhealthy-admin": ("unhealthypass", ("admin",)),
    "unhealthy-viewer": ("unhealthypass", ("viewer",)),
    "missing-posture": ("unhealthypass", ("viewer",)),
}
USER_ALIASES = {"admin": "admin-user"}


class IdentityError(RuntimeError):
    pass


def _request(runtime, method, path, body=None, token=None, form=False):
    url = runtime.keycloak_url.rstrip("/") + path
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        if form:
            data = urlencode(body).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
    else:
        data = None
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=10) as response:
            raw = response.read()
            if not raw:
                return None
            return json.loads(raw)
    except HTTPError as error:
        # Never include a response body: Keycloak may echo posted credentials or tokens.
        raise IdentityError("Keycloak request failed (HTTP %s)" % error.code) from None
    except (URLError, TimeoutError, json.JSONDecodeError):
        raise IdentityError("Keycloak request failed") from None


def _admin_token(runtime):
    result = _request(
        runtime,
        "POST",
        "/realms/master/protocol/openid-connect/token",
        {"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"},
        form=True,
    )
    try:
        return result["access_token"]
    except (TypeError, KeyError):
        raise IdentityError("Keycloak admin authentication failed") from None


def _admin(runtime, token, method, path, body=None, realm=REALM):
    return _request(runtime, method, "/admin/realms/" + realm + path, body, token)


def _ensure_role(runtime, token, name, realm=REALM):
    try:
        _admin(runtime, token, "GET", "/roles/" + name, realm=realm)
    except IdentityError as error:
        if "HTTP 404" not in str(error):
            raise
        _admin(runtime, token, "POST", "/roles", {"name": name}, realm=realm)


def _client_mappers(audiences):
    return [
        {
            "name": "audience-" + audience,
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "consentRequired": False,
            "config": {
                "included.client.audience": audience,
                "id.token.claim": "false",
                "access.token.claim": "true",
            },
        }
        for audience in audiences
    ]


def _ensure_client(runtime, token, client_id, config, realm=REALM):
    result = _admin(runtime, token, "GET", "/clients?clientId=" + client_id, realm=realm)
    current = result[0] if result else None
    representation = {
        "clientId": client_id,
        "name": client_id,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "secret": config["secret"],
        "directAccessGrantsEnabled": True,
        "standardFlowEnabled": False,
        "serviceAccountsEnabled": False,
        "attributes": {"access.token.lifespan": config["lifespan"]},
        "protocolMappers": _client_mappers(config["audiences"]),
    }
    if current:
        _admin(runtime, token, "PUT", "/clients/" + current["id"], representation, realm=realm)
    else:
        _admin(runtime, token, "POST", "/clients", representation, realm=realm)


def _ensure_user(runtime, token, username, password, roles, realm=REALM):
    matches = _admin(runtime, token, "GET", "/users?username=" + username + "&exact=true", realm=realm)
    representation = {
        "username": username,
        "enabled": True,
    }
    if matches:
        user_id = matches[0]["id"]
        _admin(runtime, token, "PUT", "/users/" + user_id, representation, realm=realm)
    else:
        _admin(runtime, token, "POST", "/users", representation, realm=realm)
        matches = _admin(runtime, token, "GET", "/users?username=" + username + "&exact=true", realm=realm)
        if not matches:
            raise IdentityError("Keycloak user provisioning failed")
        user_id = matches[0]["id"]

    _admin(runtime, token, "PUT", "/users/" + user_id + "/reset-password", {
        "type": "password", "value": password, "temporary": False,
    }, realm=realm)

    current = _admin(runtime, token, "GET", "/users/" + user_id + "/role-mappings/realm", realm=realm) or []
    current_names = {role.get("name") for role in current}
    mappings = []
    for name in roles:
        role = _admin(runtime, token, "GET", "/roles/" + name, realm=realm)
        if name not in current_names:
            mappings.append(role)
    if mappings:
        _admin(runtime, token, "POST", "/users/" + user_id + "/role-mappings/realm", mappings, realm=realm)
    remove = [
        role for role in current
        if role.get("name") in {"admin", "viewer", "posture-healthy"} and role.get("name") not in roles
    ]
    if remove:
        _admin(runtime, token, "DELETE", "/users/" + user_id + "/role-mappings/realm", remove, realm=realm)


def provision(runtime):
    """Create/update the `zta-v2` realm and fixed demo principals without printing secrets."""
    token = _admin_token(runtime)
    try:
        _request(runtime, "GET", ISSUER_PATH)
    except IdentityError as error:
        if "HTTP 404" not in str(error):
            raise
        _request(runtime, "POST", "/admin/realms", {
            "realm": REALM,
            "enabled": True,
            "accessTokenLifespan": 300,
            "ssoSessionIdleTimeout": 600,
        }, token)
    realm = _admin(runtime, token, "GET", "")
    realm["accessTokenLifespan"] = 300
    realm["ssoSessionIdleTimeout"] = 600
    realm["enabled"] = True
    _admin(runtime, token, "PUT", "", realm)
    for role in ("admin", "viewer", "posture-healthy"):
        _ensure_role(runtime, token, role)
    for client_id, config in CLIENTS.items():
        _ensure_client(runtime, token, client_id, config)
    for username, (password, roles) in USERS.items():
        _ensure_user(runtime, token, username, password, roles)
    _verify_issuer(runtime)


def _verify_issuer(runtime):
    metadata = _request(runtime, "GET", ISSUER_PATH + "/.well-known/openid-configuration")
    if not isinstance(metadata, dict) or metadata.get("issuer") != runtime.issuer:
        raise IdentityError("Keycloak issuer does not match the configured JWT trust")


def fetch_jwks(runtime):
    """Return the parsed public signing-key set; private keys are never requested."""
    _verify_issuer(runtime)
    jwks = _request(runtime, "GET", ISSUER_PATH + "/protocol/openid-connect/certs")
    if not isinstance(jwks, dict) or not jwks.get("keys"):
        raise IdentityError("Keycloak returned an empty JWKS")
    return jwks


def issue_tokens(runtime, username="admin-user", kind="healthy"):
    """Issue user and optional posture JWTs; tokens are returned only to the caller."""
    username = USER_ALIASES.get(username, username)
    if kind not in {"healthy", "unhealthy", "missing"}:
        raise IdentityError("Unknown posture fixture")
    try:
        password, roles = USERS[username]
    except KeyError:
        raise IdentityError("Unknown demo identity") from None
    if kind == "healthy" and "posture-healthy" not in roles:
        raise IdentityError("Choose a healthy posture fixture identity")
    if kind == "unhealthy" and "posture-healthy" in roles:
        raise IdentityError("Choose an unhealthy posture fixture identity")
    access = _request(runtime, "POST", ISSUER_PATH + "/protocol/openid-connect/token", {
        "grant_type": "password",
        "client_id": "zta-app",
        "client_secret": CLIENTS["zta-app"]["secret"],
        "username": username,
        "password": password,
        "scope": "openid",
    }, form=True)
    posture = None
    if kind != "missing":
        posture = _request(runtime, "POST", ISSUER_PATH + "/protocol/openid-connect/token", {
            "grant_type": "password",
            "client_id": "zta-posture",
            "client_secret": CLIENTS["zta-posture"]["secret"],
            "username": username,
            "password": password,
            "scope": "openid",
        }, form=True)
    return {
        "access": access["access_token"],
        "posture": posture["access_token"] if posture else None,
        "refresh_access": access.get("refresh_token"),
        "refresh_posture": posture.get("refresh_token") if posture else None,
    }


def _jwt_part(token, index):
    try:
        part = token.split(".")[index]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (IndexError, ValueError, json.JSONDecodeError):
        raise IdentityError("Keycloak returned an invalid JWT") from None


def _client(runtime, token, client_id):
    matches = _admin(runtime, token, "GET", "/clients?clientId=" + quote(client_id))
    if not matches:
        raise IdentityError("Keycloak client is missing")
    return matches[0]


def _replace_client(runtime, token, representation):
    _admin(runtime, token, "PUT", "/clients/" + representation["id"], representation)


def _password_grant(runtime, username, password, client_id, client_secret, realm=REALM):
    return _request(runtime, "POST", "/realms/" + realm + "/protocol/openid-connect/token", {
        "grant_type": "password",
        "client_id": client_id,
        "client_secret": client_secret,
        "username": username,
        "password": password,
        "scope": "openid",
    }, form=True)


def _provision_fixture_realm(runtime, realm, admin_token):
    _request(runtime, "POST", "/admin/realms", {
        "realm": realm,
        "enabled": True,
        "accessTokenLifespan": 300,
        "ssoSessionIdleTimeout": 600,
    }, admin_token)
    for role in ("admin", "viewer", "posture-healthy"):
        _ensure_role(runtime, admin_token, role, realm)
    for client_id, config in CLIENTS.items():
        _ensure_client(runtime, admin_token, client_id, config, realm)
    for fixture_user, (password, roles) in USERS.items():
        _ensure_user(runtime, admin_token, fixture_user, password, roles, realm)


def _healthy_tokens(runtime, username):
    return issue_tokens(runtime, username, "healthy")


def _temporary_client(runtime, admin_token, client_id, secret, audiences):
    _admin(runtime, admin_token, "POST", "/clients", {
        "clientId": client_id,
        "name": client_id,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "secret": secret,
        "directAccessGrantsEnabled": True,
        "standardFlowEnabled": False,
        "fullScopeAllowed": True,
        "attributes": {"access.token.lifespan": "300"},
        "protocolMappers": _client_mappers(audiences),
    })


def _with_client_change(runtime, client_id, change, action):
    token = _admin_token(runtime)
    original = copy.deepcopy(_client(runtime, token, client_id))
    modified = copy.deepcopy(original)
    change(modified)
    try:
        _replace_client(runtime, token, modified)
        return action()
    finally:
        _replace_client(runtime, token, original)


def test_tokens(runtime, variant, username="admin-user"):
    """Create one controlled, signed negative JWT fixture for an integration case."""
    username = USER_ALIASES.get(username, username)
    try:
        password, roles = USERS[username]
    except KeyError:
        raise IdentityError("Unknown demo identity") from None

    if variant == "wrong_issuer":
        fixture_realm = "zta-v2-fixture-" + secrets.token_hex(4)
        admin_token = _admin_token(runtime)
        try:
            _provision_fixture_realm(runtime, fixture_realm, admin_token)
            access = _password_grant(runtime, username, password, "zta-app", CLIENTS["zta-app"]["secret"], fixture_realm)
            posture = _password_grant(runtime, username, password, "zta-posture", CLIENTS["zta-posture"]["secret"], fixture_realm)
            claims = _jwt_part(access["access_token"], 1)
            if claims.get("iss") == runtime.issuer:
                raise IdentityError("Temporary issuer realm reused the trusted issuer")
            return {
                "access": access["access_token"],
                "posture": posture["access_token"],
                "refresh_access": access.get("refresh_token"),
                "refresh_posture": posture.get("refresh_token"),
            }
        finally:
            try:
                _request(runtime, "DELETE", "/admin/realms/" + fixture_realm, token=admin_token)
            except IdentityError as error:
                if "HTTP 404" not in str(error):
                    raise IdentityError("Temporary issuer realm cleanup failed") from None

    if variant == "wrong_audience":
        admin_token = _admin_token(runtime)
        client_id = "zta-test-wrongaud-" + secrets.token_hex(4)
        secret = secrets.token_urlsafe(32)
        try:
            _temporary_client(runtime, admin_token, client_id, secret, ())
            client = _client(runtime, admin_token, client_id)
            mapper = {
                "name": "test-unrelated-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "consentRequired": False,
                "config": {
                    "included.custom.audience": "zta-unrelated",
                    "id.token.claim": "false",
                    "access.token.claim": "true",
                },
            }
            client["protocolMappers"] = [mapper]
            _replace_client(runtime, admin_token, client)
            access = _password_grant(runtime, username, password, client_id, secret)
            posture = _password_grant(runtime, username, password, "zta-posture", CLIENTS["zta-posture"]["secret"])
            audience = _jwt_part(access["access_token"], 1).get("aud", [])
            audiences = [audience] if isinstance(audience, str) else audience
            if {"zta-frontend", "zta-backend"} & set(audiences or []):
                raise IdentityError("Wrong-audience client emitted an allowed audience")
            return {
                "access": access["access_token"],
                "posture": posture["access_token"],
                "refresh_access": access.get("refresh_token"),
                "refresh_posture": posture.get("refresh_token"),
            }
        finally:
            matches = _admin(runtime, admin_token, "GET", "/clients?clientId=" + quote(client_id)) or []
            if matches:
                _admin(runtime, admin_token, "DELETE", "/clients/" + matches[0]["id"])

    if variant in ('expired', 'expired_posture'):
        def short_lived(client):
            client.setdefault("attributes", {})["access.token.lifespan"] = "1"

        tokens = _with_client_change(runtime, 'zta-app' if variant == 'expired' else 'zta-posture', short_lived, lambda: _healthy_tokens(runtime, username))
        claims = _jwt_part(tokens['access' if variant == 'expired' else 'posture'], 1)
        expiry, issued = claims.get("exp"), claims.get("iat")
        if not isinstance(expiry, (int, float)) or not isinstance(issued, (int, float)):
            raise IdentityError("Keycloak access token has no expiry")
        if expiry - issued > 2:
            raise IdentityError("Keycloak ignored the temporary one-second token lifetime")
        time.sleep(max(0, expiry - time.time() + 1))
        return tokens

    if variant == "rotation_old":
        def extended_access(client):
            client.setdefault("attributes", {})["access.token.lifespan"] = "900"

        tokens = _with_client_change(runtime, "zta-app", extended_access, lambda: _healthy_tokens(runtime, username))
        claims = _jwt_part(tokens["access"], 1)
        iat, expiry = claims.get("iat"), claims.get("exp")
        if not isinstance(iat, (int, float)) or not isinstance(expiry, (int, float)) or not 360 < expiry - iat <= 900:
            raise IdentityError("Keycloak ignored the temporary rotation-token lifespan")
        return tokens

    if variant == "future_nbf":
        future_nbf = int(time.time()) + 120

        def add_future_nbf(client):
            mappers = list(client.get("protocolMappers", []))
            mappers.append({
                "name": "test-future-nbf",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-hardcoded-claim-mapper",
                "consentRequired": False,
                "config": {
                    "claim.name": "nbf",
                    "claim.value": str(future_nbf),
                    "jsonType.label": "long",
                    "id.token.claim": "false",
                    "access.token.claim": "true",
                    "userinfo.token.claim": "false",
                },
            })
            client["protocolMappers"] = mappers

        tokens = _with_client_change(runtime, "zta-app", add_future_nbf, lambda: _healthy_tokens(runtime, username))
        if _jwt_part(tokens["access"], 1).get("nbf", 0) <= int(time.time()):
            raise IdentityError("Keycloak v23 did not emit the temporary future-nbf claim; use the signed OPA unit fixture")
        return tokens

    if variant == "stale_posture":
        if "posture-healthy" not in roles:
            raise IdentityError("Stale posture requires a healthy posture fixture user")

        def long_posture(client):
            client.setdefault("attributes", {})["access.token.lifespan"] = "300"

        tokens = _with_client_change(runtime, "zta-posture", long_posture, lambda: _healthy_tokens(runtime, username))
        claims = _jwt_part(tokens["posture"], 1)
        iat, expiry = claims.get("iat"), claims.get("exp")
        if not isinstance(iat, (int, float)) or not isinstance(expiry, (int, float)) or expiry - iat <= 120:
            raise IdentityError("Keycloak ignored the temporary 300-second posture-token lifespan")
        time.sleep(max(0, iat + 121 - time.time()))
        now = time.time()
        if now - iat <= 120 or now >= expiry:
            raise IdentityError("Posture token expired before its age could be tested")
        return tokens

    raise IdentityError("Unknown JWT fixture variant")


class _KeyRotation:
    def __init__(self, old_key_ids, new_key_ids, overlap_seconds, retire):
        self.old_key_ids = sorted(old_key_ids)
        self.new_key_ids = sorted(new_key_ids)
        self.retired_key_ids = []
        self.overlap_seconds = overlap_seconds
        self._retire = retire
        self.retired = False
        self.started = time.monotonic()
        self.retired_after_seconds = None

    def __repr__(self):
        return "<KeyRotation old_key_ids=%r new_key_ids=%r retired=%r>" % (
            self.old_key_ids, self.new_key_ids, self.retired,
        )

    def retire(self):
        if not self.retired:
            self.retired_key_ids = self._retire()
            self.retired = True
            self.retired_after_seconds = time.monotonic() - self.started
        return {"old_key_ids": self.old_key_ids, "new_key_ids": self.new_key_ids,
                "retired_key_ids": self.retired_key_ids, "overlap_seconds": self.overlap_seconds}


@contextmanager
def rotate_keys(runtime, overlap_seconds=360):
    """Temporarily add a higher-priority Keycloak RSA signer; always restore the saved provider state."""
    if overlap_seconds < 360:
        raise IdentityError("Key retirement requires at least 360 seconds of overlap")
    admin_token = _admin_token(runtime)
    realm = _admin(runtime, admin_token, "GET", "/")
    component_path = "/components"
    query = "?" + urlencode({"parent": realm["id"], "type": "org.keycloak.keys.KeyProvider"})
    components = _admin(runtime, admin_token, "GET", component_path + query) or []
    providers = [
        item for item in components
        if item.get("providerId") == "rsa-generated"
        and item.get("config", {}).get("algorithm", ["RS256"])[0] == "RS256"
        and item.get("config", {}).get("enabled", ["true"])[0].lower() == "true"
    ]
    if not providers:
        raise IdentityError("No enabled Keycloak RS256 generated-key provider")
    old_component = copy.deepcopy(max(
        providers,
        key=lambda item: int(item.get("config", {}).get("priority", ["0"])[0]),
    ))
    # Component updates retain omitted settings; make effective defaults explicit for restoration.
    old_component.setdefault('config', {}).setdefault('enabled', ['true'])
    old_component['config'].setdefault('active', ['true'])
    initial_jwks = fetch_jwks(runtime)
    old_key_ids = {key["kid"] for key in initial_jwks["keys"] if key.get("kid") and key.get("alg") == "RS256"}
    if not old_key_ids:
        raise IdentityError("Keycloak did not publish an RS256 signing key")
    name = "zta-v2-rotation-" + secrets.token_hex(4)
    new_component_id = None
    try:
        # Keep only non-secret generation settings; provider secret material stays in Keycloak.
        config = {
            key: value for key, value in old_component.get("config", {}).items()
            if key.lower() not in {"privatekey", "publickey", "secret", "keymaterial"}
        }
        max_priority = max(int(item.get("config", {}).get("priority", ["0"])[0]) for item in providers)
        config.update({"priority": [str(max_priority + 100)], "enabled": ["true"], "active": ["true"], "algorithm": ["RS256"]})
        _admin(runtime, admin_token, "POST", component_path, {
            "name": name,
            "providerId": "rsa-generated",
            "providerType": "org.keycloak.keys.KeyProvider",
            "parentId": realm["id"],
            "config": config,
        })
        generated = _admin(runtime, admin_token, "GET", component_path + query) or []
        new_component = next((item for item in generated if item.get("name") == name), None)
        if not new_component:
            raise IdentityError("Keycloak did not create the temporary RSA key provider")
        new_component_id = new_component["id"]
        runtime.sync_jwks()
        rotated_jwks = fetch_jwks(runtime)
        rotated_ids = {key["kid"] for key in rotated_jwks["keys"] if key.get("kid") and key.get("alg") == "RS256"}
        new_key_ids = rotated_ids - old_key_ids
        if not new_key_ids or not old_key_ids <= rotated_ids:
            raise IdentityError("Keycloak rotation snapshot did not retain old and publish new keys")
    except Exception:
        # The context's finally block owns cleanup after the component id is known.
        try:
            cleanup_token = _admin_token(runtime)
            if new_component_id is None:
                generated = _admin(runtime, cleanup_token, "GET", component_path + query) or []
                temp = next((item for item in generated if item.get("name") == name), None)
                new_component_id = temp.get("id") if temp else None
            if new_component_id:
                _admin(runtime, cleanup_token, "DELETE", component_path + "/" + new_component_id)
                runtime.sync_jwks()
        except Exception:
            raise IdentityError("Temporary RSA key-provider cleanup failed") from None
        raise

    started = time.monotonic()

    def retire_old_key():
        time.sleep(max(0, overlap_seconds - (time.monotonic() - started)))
        retire_token = _admin_token(runtime)
        current = _admin(runtime, retire_token, "GET", component_path + "/" + old_component["id"])
        current.setdefault("config", {})["enabled"] = ["false"]
        _admin(runtime, retire_token, "PUT", component_path + "/" + old_component["id"], current)
        runtime.sync_jwks()
        remaining_ids = {key["kid"] for key in fetch_jwks(runtime)["keys"] if key.get("kid")}
        retired_ids = old_key_ids - remaining_ids
        if not retired_ids:
            raise IdentityError("Disabled Keycloak signing key remained in the JWKS snapshot")
        return sorted(retired_ids)

    rotation = _KeyRotation(old_key_ids, new_key_ids, overlap_seconds, retire_old_key)
    try:
        yield rotation
    finally:
        cleanup_error = None
        try:
            cleanup_token = _admin_token(runtime)
        except Exception:
            cleanup_token = None
            cleanup_error = IdentityError("Keycloak signing provider restoration failed")
        try:
            if cleanup_token:
                _admin(runtime, cleanup_token, "PUT", component_path + "/" + old_component["id"], old_component)
                current_components = _admin(runtime, cleanup_token, "GET", component_path + query) or []
                temp = next((item for item in current_components if item.get("id") == new_component_id), None)
                if temp:
                    _admin(runtime, cleanup_token, "DELETE", component_path + "/" + new_component_id)
        except Exception as error:
            cleanup_error = error
        try:
            if cleanup_token:
                _admin(runtime, cleanup_token, "PUT", component_path + "/" + old_component["id"], old_component)
        except Exception as error:
            cleanup_error = cleanup_error or error
        try:
            runtime.sync_jwks()
        except Exception as error:
            cleanup_error = cleanup_error or error
        if cleanup_error:
            raise IdentityError("Keycloak signing provider restoration failed") from None
