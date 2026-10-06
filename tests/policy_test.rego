package istio.authz_test

import data.istio.authz

fixture_private_key := {
	"kty": "RSA",
	"kid": "unit-test",
	"alg": "RS256",
	"n": "qI6VWzPHNpzehrDifbWIkAeUZHoTe-2Ac8dAYR2soH5ksCqN4Uno6sM5u0FTiBZY5MkFrkBOMINQpZkWn_qSn_aVFA8Ci7D39i5kUFYBmW71hJguXxFZtdDsmGnO04id5XOFZ5idFWN0SfJySFLCIv_UTc95Jbtz9xXG7pnmKBHSzn6CmazJEO4TdpMJ82bMOSgsNJKznYqcWrL91avWWYZCog2p9PgmkV-9O6zgsdcSQ-_mJ7BQjNWFAs6tMPq70Az2Mn4rmiXT0qzwT4cPojMCWmTx5Kk-UerriyqOqJMkib03gHW-9r_mvQ7cI0TGm8rTO9-FSvk9gPyT3lGBGw",
	"e": "AQAB",
	"d": "EKeR-2J41x0V4bIdlvU2aqDNGUZ0oWScshPoeRARDAShF0UFItMGOBgVHrr8MXCf1O9F5-tDrohzEgG32hPMpBCdt08qXbodLg50a_mri8kKalENF-ijeBMOJZsizATuMQtCjbNnJgNfLKVPhHTk6MdlZ1DONBu7ABl_P_kl5CSBgfaj72Kt-KSxqFg0upyXXE6AtiUD8xG2RMbFijMU8uHjJ5SBL_4PK21UEDS4iapJe_2bCLxFy7VU6QH-pmvdJl9AU_ZTVWr_9HUt-b8-xRf3i-mge0iRt681osERt277hkRpZBZki2ZspLsFBwslE9SFY-1SXExFXkc60IWpXQ",
	"p": "4cWswDNvNzXYM1i9fjxXtqDrgXrUGH8EJ4DI5x5ZHB7fLAUIKZfJAH4X8-guHfvaFYEhPGw7SDbGj3_hTjRRkoKCvCrhZHa12hgc_Kq1WG_LOHG25pPsToIKgh-HKa8xjAhhPstmlOoN13PZW_n-LfQ640z2FSrk01DBQf0xym0",
	"q": "vx_ck2miyBA7XHfRbm2IkoFVKEI-xS3_ClkcvRMim_Kg_6pWiOdD7-AQju8CW8AEVa5ON5_t_AWuePeTMEgC5lz2Q6DCdiToH4talX9VJPz3Y5nDjf9RB5nqhQ5Pn7OEd06Usi3m_izqq45n-ZEGY4_WkzqcQcmEAvvipGpnxKc",
	"dp": "XXt8DBk_85xX6OrVi29w4i2_Vd2F9J6jGbg5d3kZbItb3N44gwBWOd38DQIWFlQx-LV_DYXDBiOoE8Lfh4IiRIfFmiQnL3H32lYhqn0EmZmwi66KDO8y6U7vCvIDBT-FRHYzzcxqrT48fPl7Bpp8pIp716IGQr2AAf9uBeTQuQ",
	"dq": "XK3ypHlBOorEfl6L7GSpKYIV7WPSVIOtfTMhQH6a9cx-Tfwn4lNjGlspLGayWhOPBo1z2H1xRhjrNjW35l3FKjhCIyE9q1TSSxmkX4JTo5AX1vClZ6I7hNgaZVM_QU4oGkK80Hp53R-i3HY97UNqObVydAqj4zL5FQlYKip_D1k",
	"qi": "FfFv_uTRDmdYu4MH_9xgsccjT8dNLXSBesr3hN6j7rgYiiNNXv29Dlw0Nxv1pwjOH15_8KoTmPYu4UBzNPK18qLWIJ0zEzbwB6DfErLBVuD-IktDU0tmpi4M111ccpTYaofHI9JCCsyl0qNTvFn_BfnKlvyCKZH2LwGiw5pgtLo",
}

fixture_public_key := {
	"kty": "RSA",
	"kid": "unit-test",
	"use": "sig",
	"alg": "RS256",
	"n": fixture_private_key.n,
	"e": fixture_private_key.e,
}

fixture_trust := {
	"issuer": "https://issuer.test/realms/zta-v2",
	"jwks": {"keys": [fixture_public_key]},
	"mode": "strict",
	"posture_max_age": 120,
}

fixture_now := floor(time.now_ns() / 1000000000)

make_token(payload) = token {
	token := io.jwt.encode_sign({"alg": "RS256", "kid": "unit-test"}, payload, fixture_private_key)
}

access_token(sub, roles) = token {
	token := access_token_with(sub, roles, fixture_trust.issuer, ["zta-frontend", "zta-backend"], fixture_now - 10, fixture_now + 290)
}

access_token_with(sub, roles, issuer, audience, iat, exp) = token {
	token := make_token({
		"iss": issuer,
		"sub": sub,
		"aud": audience,
		"iat": iat,
		"exp": exp,
		"realm_access": {"roles": roles},
	})
}

access_token_with_nbf(sub, roles, nbf) = token {
	token := make_token({
		"iss": fixture_trust.issuer,
		"sub": sub,
		"aud": ["zta-frontend", "zta-backend"],
		"iat": fixture_now - 10,
		"exp": fixture_now + 290,
		"nbf": nbf,
		"realm_access": {"roles": roles},
	})
}

posture_token(sub, iat, exp, nbf) = token {
	token := make_token({
		"iss": fixture_trust.issuer,
		"sub": sub,
		"aud": "zta-posture",
		"iat": iat,
		"exp": exp,
		"nbf": nbf,
		"realm_access": {"roles": ["posture-healthy"]},
	})
}

posture_token_without_nbf(sub) = token {
	token := make_token({
		"iss": fixture_trust.issuer,
		"sub": sub,
		"aud": "zta-posture",
		"iat": fixture_now - 10,
		"exp": fixture_now + 110,
		"realm_access": {"roles": ["posture-healthy"]},
	})
}

request(method, path, access, posture) = req {
	req := {
		"attributes": {
			"request": {"http": {
				"method": method,
				"path": path,
				"headers": {
					"authorization": sprintf("Bearer %s", [access]),
					"x-zta-posture": posture,
				},
			}},
		},
	}
}

allow(req) {
	authz.allow with input as req
		with data.jwt_trust as fixture_trust
}

allow_mode(req, mode) {
	trust := object.union(fixture_trust, {"mode": mode})
	authz.allow with input as req
		with data.jwt_trust as trust
}

test_admin_read_write_and_viewer_read_allowed {
	admin := access_token("alice", ["admin"])
	viewer := access_token("bob", ["viewer"])
	admin_posture := posture_token("alice", fixture_now - 10, fixture_now + 110, fixture_now - 10)
	viewer_posture := posture_token("bob", fixture_now - 10, fixture_now + 110, fixture_now - 10)
	allow(request("GET", "/api/admin", admin, admin_posture))
	allow(request("POST", "/api/write", admin, admin_posture))
	allow(request("GET", "/api/data", viewer, viewer_posture))
	allow(request("GET", "/api/data?case=1", viewer, viewer_posture))
	not allow(request("HEAD", "/api/data", viewer, viewer_posture))
	not allow(request("OPTIONS", "/api/data", viewer, viewer_posture))
}

test_role_and_path_denials {
	viewer := access_token("bob", ["viewer"])
	posture := posture_token("bob", fixture_now - 10, fixture_now + 110, fixture_now - 10)
	admin := access_token("alice", ["admin"])
	admin_posture := posture_token("alice", fixture_now - 10, fixture_now + 110, fixture_now - 10)
	not allow(request("GET", "/api/admin", viewer, posture))
	not allow(request("POST", "/api/write", viewer, posture))
	not allow(request("DELETE", "/api/data", admin, admin_posture))
	not allow(request("GET", "/api/unknown", admin, admin_posture))
}

test_access_issuer_audience_expiry_and_nbf {
	posture := posture_token("alice", fixture_now - 10, fixture_now + 110, fixture_now - 10)
	wrong_issuer := access_token_with("alice", ["admin"], "https://other.test/realms/zta-v2", ["zta-frontend", "zta-backend"], fixture_now - 10, fixture_now + 290)
	wrong_audience := access_token_with("alice", ["admin"], fixture_trust.issuer, ["zta-unrelated"], fixture_now - 10, fixture_now + 290)
	expired := access_token_with("alice", ["admin"], fixture_trust.issuer, ["zta-frontend", "zta-backend"], fixture_now - 10, fixture_now - 1)
	future_nbf := access_token_with_nbf("alice", ["admin"], fixture_now + 30)
	not allow(request("GET", "/api/data", wrong_issuer, posture))
	not allow(request("GET", "/api/data", wrong_audience, posture))
	not allow(request("GET", "/api/data", expired, posture))
	not allow(request("GET", "/api/data", future_nbf, posture))
}

test_posture_is_subject_bound_fresh_and_expiring {
	admin := access_token("alice", ["admin"])
	alice_posture := posture_token("alice", fixture_now - 10, fixture_now + 110, fixture_now - 10)
	bob_posture := posture_token("bob", fixture_now - 10, fixture_now + 110, fixture_now - 10)
	old_posture := posture_token("alice", fixture_now - 130, fixture_now + 300, fixture_now - 130)
	future_posture := posture_token("alice", fixture_now - 10, fixture_now + 110, fixture_now + 30)
	expired_posture := posture_token("alice", fixture_now - 130, fixture_now - 1, fixture_now - 130)
	decoded := io.jwt.decode(alice_posture)
	wrong_issuer := make_token(object.union(decoded[1], {"iss": "https://other.test/realms/zta-v2"}))
	wrong_audience := make_token(object.union(decoded[1], {"aud": ["zta-unrelated"]}))
	parts := split(alice_posture, ".")
	wrong_signature := sprintf("%s.%s.AA", [parts[0], parts[1]])
	allow(request("GET", "/api/data", admin, alice_posture))
	not allow(request("GET", "/api/data", admin, bob_posture))
	not allow(request("GET", "/api/data", admin, old_posture))
	not allow(request("GET", "/api/data", admin, future_posture))
	not allow(request("GET", "/api/data", admin, expired_posture))
	not allow(request("GET", "/api/data", admin, wrong_issuer))
	not allow(request("GET", "/api/data", admin, wrong_audience))
	not allow(request("GET", "/api/data", admin, wrong_signature))
	not allow({"attributes": {"request": {"http": {"method": "GET", "path": "/api/data", "headers": {"authorization": sprintf("Bearer %s", [admin]), "role": "admin", "x-device-firewall": "enabled"}}}}})
}

test_health_and_mode_exceptions {
	allow({"attributes": {"request": {"http": {"method": "GET", "path": "/healthz", "headers": {}}}}})
	viewer := access_token("bob", ["viewer"])
	allow_mode(request("GET", "/api/data", viewer, ""), "opa-role")
	allow(request("GET", "/api/data", viewer, posture_token_without_nbf("bob")))
}

test_decision_logs_mask_both_jwts {
	data.system.log.mask[_] == "/input/attributes/request/http/headers/authorization"
	data.system.log.mask[_] == "/input/attributes/request/http/headers/x-zta-posture"
}
