package istio.authz

import input.attributes.request.http as http_request

request_path := split(http_request.path, "?")[0]

default allow = false

healthz {
	http_request.method == "GET"
	request_path == "/healthz"
}

allow {
	healthz
}

access_token := token {
	bearer := http_request.headers.authorization
	regex.match("^Bearer [A-Za-z0-9._~-]+$", bearer)
	token := trim_prefix(bearer, "Bearer ")
}

access_claims := payload {
	token := access_token
	decoded := io.jwt.decode_verify(token, {
		"cert": json.marshal(data.jwt_trust.jwks),
		"iss": data.jwt_trust.issuer,
		"aud": "zta-frontend",
	})
	decoded[0] == true
	header := decoded[1]
	payload := decoded[2]
	header.alg == "RS256"
	payload.iss == data.jwt_trust.issuer
	is_number(payload.exp)
	is_number(payload.iat)
	now := time.now_ns() / 1000000000
	payload.exp > now
	payload.iat <= now
	audience_contains(payload.aud, "zta-frontend")
	audience_contains(payload.aud, "zta-backend")
}

audience_contains(aud, wanted) {
	aud == wanted
}

audience_contains(aud, wanted) {
	aud[_] == wanted
}

posture_claims := payload {
	token := http_request.headers["x-zta-posture"]
	regex.match("^[A-Za-z0-9._~-]+$", token)
	decoded := io.jwt.decode_verify(token, {
		"cert": json.marshal(data.jwt_trust.jwks),
		"iss": data.jwt_trust.issuer,
		"aud": "zta-posture",
	})
	decoded[0] == true
	header := decoded[1]
	payload := decoded[2]
	header.alg == "RS256"
	payload.iss == data.jwt_trust.issuer
	payload.sub == access_claims.sub
	payload.realm_access.roles[_] == "posture-healthy"
	audience_contains(payload.aud, "zta-posture")
	max_age := data.jwt_trust.posture_max_age
	now := time.now_ns() / 1000000000
	is_number(payload.iat)
	is_number(payload.exp)
	payload.iat <= now
	now - payload.iat <= max_age
	payload.exp > now
	nbf_ok(payload, now)
}

nbf_ok(payload, _now) {
	nbf := object.get(payload, "nbf", 0)
	nbf == 0
}

nbf_ok(payload, now) {
	nbf := object.get(payload, "nbf", 0)
	is_number(nbf)
	nbf <= now
}

posture_ok {
	data.jwt_trust.mode == "opa-role"
}

posture_ok {
	data.jwt_trust.mode == "strict"
	posture_claims
}

role_admin {
	access_claims.realm_access.roles[_] == "admin"
}

role_viewer {
	access_claims.realm_access.roles[_] == "viewer"
	not role_admin
}

read_path {
	request_path == "/"
}

read_path {
	request_path == "/api/data"
}

admin_path {
	request_path == "/api/admin"
}

write_path {
	request_path == "/api/write"
}

route_allowed {
	http_request.method == "GET"
	read_path
	role_viewer
}

route_allowed {
	http_request.method == "GET"
	read_path
	role_admin
}

route_allowed {
	http_request.method == "GET"
	admin_path
	role_admin
}

route_allowed {
	http_request.method == "POST"
	write_path
	role_admin
}

allow {
	access_claims
	posture_ok
	route_allowed
}
