#!/usr/bin/env bash
# Live check of the SSO baseline (M7) against the running Docker stack: a real Keycloak login
# through the OIDC Authorization Code + PKCE front door, then one admitted and one denied
# service request under the same policies as the ZK gateway.
#
#   cd p3 && docker compose up -d --build && scripts/sso-live-check.sh
#
# Uses the DEV-ONLY demo users from baseline/keycloak/realm-zkag.json. Exit 0 only if every
# step behaves as expected.
set -euo pipefail

UI="${UI_URL:-http://localhost:8088}"
REALM_FILE="$(cd "$(dirname "$0")/.." && pwd)/baseline/keycloak/realm-zkag.json"
TMP="$(mktemp -d)"
trap "rm -rf '$TMP'" EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok   $*"; }

password_of() { # username -> dev password from the realm file
  node -e '
    const r = require(process.argv[1]);
    const u = r.users.find((x) => x.username === process.argv[2]);
    process.stdout.write(u.credentials.find((c) => c.type === "password").value);
  ' "$REALM_FILE" "$1"
}

# login <user> <cookie-jar>: drive the browser flow with curl.
login() {
  local user="$1" jar="$2" page action
  page="$(curl -sS -L -c "$jar" -b "$jar" "$UI/sso/login?returnTo=/compare")"
  action="$(grep -oE 'action="[^"]+"' <<<"$page" | head -1 | sed -e 's/^action="//' -e 's/"$//' -e 's/&amp;/\&/g')"
  [ -n "$action" ] || fail "$user: no Keycloak login form (is keycloak up on :8080?)"
  pass "$user: /sso/login redirected to the Keycloak login form"
  curl -sS -L -o /dev/null -c "$jar" -b "$jar" \
    --data-urlencode "username=$user" --data-urlencode "password=$(password_of "$user")" \
    --data-urlencode "credentialId=" "$action"
}

me() { curl -sS -b "$1" "$UI/sso/me"; }
status() { curl -sS -o /dev/null -w '%{http_code}' -b "$1" "$UI$2"; }

curl -sSf "$UI/sso/health/keycloak" >/dev/null || fail "SSO gateway cannot reach Keycloak"
pass "SSO gateway reaches Keycloak"

# alice: engineer, clearance 2 -> wiki allowed, admin panel denied.
A="$TMP/alice"
login alice "$A"
me "$A" | grep -q '"authenticated":true' || fail "alice: no SSO session after the callback"
me "$A" | grep -q '"username":"alice"' || fail "alice: session identity is not alice"
pass "alice: token exchange + JWT validation succeeded, session established"
[ "$(status "$A" /sso/svc/wiki/)" = 200 ] || fail "alice: wiki not admitted"
pass "alice: wiki admitted (200)"
[ "$(status "$A" /sso/svc/admin-panel/)" = 403 ] || fail "alice: admin panel not denied"
pass "alice: admin panel denied by policy (403)"

# wrong password: no session.
W="$TMP/wrong"
page="$(curl -sS -L -c "$W" -b "$W" "$UI/sso/login")"
action="$(grep -oE 'action="[^"]+"' <<<"$page" | head -1 | sed -e 's/^action="//' -e 's/"$//' -e 's/&amp;/\&/g')"
curl -sS -L -o /dev/null -c "$W" -b "$W" --data-urlencode "username=alice" \
  --data-urlencode "password=not-the-password" "$action"
me "$W" | grep -q '"authenticated":false' || fail "wrong password produced a session"
pass "wrong password: no session"

# no session at all: service refused.
[ "$(status /dev/null /sso/svc/wiki/)" = 401 ] || fail "anonymous request to wiki not refused"
pass "anonymous: wiki refused (401)"

echo "SSO live check: all steps passed"
