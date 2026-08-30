#!/usr/bin/env bash
# The compose end-to-end half of the parity gate (kotsmile/keyway#29): the
# unchanged clients against the Go server, on a schema shaped the way the
# Rust server left deployed databases (the frozen e2e/rust-migrations
# fixtures). Run from anywhere; needs docker, go, python3 and pnpm (or npm).
set -euo pipefail
cd "$(dirname "$0")/.."

if docker compose version > /dev/null 2>&1; then
  COMPOSE=(docker compose -f e2e/docker-compose.yml)
else
  COMPOSE=(docker-compose -f e2e/docker-compose.yml)
fi
PSQL=(docker exec -i keyway-e2e-postgres psql -qtA -v ON_ERROR_STOP=1 -U keyway -d keyway)
BASE=http://127.0.0.1:18080
OUT=e2e/out
mkdir -p "$OUT"

KEYWAY_E2E_AES_KEY="$(openssl rand -base64 32)"
export KEYWAY_E2E_AES_KEY

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
json_get() { python3 -c 'import json,sys; print(json.load(sys.stdin)['"$1"'])'; }
fields() { python3 e2e/fields.py "$@"; }
status_of() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

cleanup() {
  [ -n "${DASH_PID:-}" ] && { kill "$DASH_PID" 2>/dev/null; wait "$DASH_PID" 2>/dev/null; } || true
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- 1. postgres:18, migrated the way the Rust server left it ---------------
step "1. postgres:18, simulating a database the Rust server migrated"
"${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
"${COMPOSE[@]}" up -d --wait postgres

# The Rust server's own migration files, raw — no goose markers anywhere near
# them, exactly as sqlx applied them. Frozen in e2e/rust-migrations since the
# crates were deleted at the cutover (#30); see the README there.
for file in e2e/rust-migrations/0001_init.sql \
            e2e/rust-migrations/0002_own_store.sql \
            e2e/rust-migrations/0003_audit_secret_id.sql; do
  if grep -q '+goose' "$file"; then
    fail "$file carries goose markers; wanted the sqlx originals"
  fi
  "${PSQL[@]}" < "$file" > /dev/null
done

# The history table as sqlx recorded it (the shape adoptSqlxHistory in
# internal/postgres/postgres.go reads: only `version` matters to Go).
"${PSQL[@]}" > /dev/null <<'SQL'
CREATE TABLE _sqlx_migrations (
    version        BIGINT PRIMARY KEY,
    description    TEXT NOT NULL,
    installed_on   TIMESTAMPTZ NOT NULL DEFAULT now(),
    success        BOOLEAN NOT NULL,
    checksum       BYTEA NOT NULL,
    execution_time BIGINT NOT NULL
);
INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) VALUES
    (1, 'init', true, '\x00', 0),
    (2, 'own store', true, '\x00', 0),
    (3, 'audit secret id', true, '\x00', 0);
SQL

tables_before="$(echo "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> 'goose_db_version' ORDER BY 1" | "${PSQL[@]}")"

# --- 2. keywayd migrate adopts and applies nothing ---------------------------
step "2. keywayd migrate adopts the sqlx history and applies nothing new"
"${COMPOSE[@]}" run --rm keywayd migrate -c /etc/keyway/config.yml 2>&1 | tee "$OUT/migrate.log"
grep -q "schema is up to date" "$OUT/migrate.log" || fail "migrate did not finish"

adopted="$(echo "SELECT string_agg(version_id::text, ',' ORDER BY version_id) FROM goose_db_version WHERE version_id > 0 AND is_applied" | "${PSQL[@]}")"
[ "$adopted" = "1,2,3" ] || fail "goose holds versions [$adopted], wanted exactly 1,2,3 adopted"

tables_after="$(echo "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename <> 'goose_db_version' ORDER BY 1" | "${PSQL[@]}")"
[ "$tables_before" = "$tables_after" ] || fail "migrate changed the schema on an up-to-date database"
echo "OK: sqlx history adopted as goose versions 1,2,3; no migration re-applied"

# --- 3. keywayd serve --------------------------------------------------------
step "3. keywayd serve (dev mode, one keyway own Store)"
"${COMPOSE[@]}" up -d --wait keywayd
# The container is healthy before the host port forward settles; retry briefly.
for _ in $(seq 30); do
  [ "$(curl -fsS $BASE/healthz 2>/dev/null || true)" = "ok" ] && break
  sleep 1
done
[ "$(curl -fsS $BASE/healthz)" = "ok" ] || fail "healthz"
# The scrape endpoint answers on its own port. The keyway_backend_* series
# appear after the first Store call, so their names are asserted later.
curl -fsS http://127.0.0.1:19090/metrics > /dev/null || fail "the metrics listener"
[ "$(curl -fsS http://127.0.0.1:19090/healthz)" = "ok" ] || fail "metrics healthz"
echo "OK: serving"

# --- 4. a token, minted over HTTP as the dev user ----------------------------
step "4. minting an API token as the dev user"
minted="$(curl -fsS -X POST -H 'content-type: application/json' \
  -d '{"name":"e2e","days":1}' $BASE/api/tokens)"
echo "$minted" | fields id name token expires_at:ts
TOKEN="$(echo "$minted" | json_get '"token"')"
TOKEN_ID="$(echo "$minted" | json_get '"id"')"
case "$TOKEN" in kw-*) ;; *) fail "a token spells kw-<id>-<secret>, got: $TOKEN";; esac
echo "OK: $TOKEN_ID"

# --- 5. the Go CLI -----------------------------------------------------------
step "5. the Go CLI end-to-end"
go build -o "$OUT/keyway" ./cmd/cli
kw() { "$OUT/keyway" --url "$BASE" --token "$TOKEN" "$@"; }

# An API token carries no roles (ADR-0004), in Rust and in Go alike — so
# `create` over the token is refused, and the parity IS the refusal.
if kw create --store local --name never --value x 2> "$OUT/cli-create-refused.log"; then
  fail "create over a role-less token should be refused"
fi
grep -qi "forbidden" "$OUT/cli-create-refused.log" || fail "the refusal names itself"
echo "OK: create over a role-less token is forbidden, as under Rust"

# Created as the dev browser actor (create role); the token then acts as its
# holder `dev`, who owns it — list/get/view/patch/delegate all open.
created="$(curl -fsS -X POST -H 'content-type: application/json' \
  -d '{"store":"local","name":"db-creds","value":"{\"db_password\":\"hunter2\",\"api_key\":\"abc\"}","note":"seeded by e2e"}' \
  $BASE/api/secrets)"
echo "$created" | fields id store name level basis latest_version
ID="$(echo "$created" | json_get '"id"')"
[ "$(echo "$created" | json_get '"basis"')" = "owner" ] || fail "whoever made it owns it"

kw list | tee "$OUT/cli-list.txt" | grep -q db-creds || fail "list shows the secret"
kw list --store local | grep -q db-creds || fail "list --store filters in"
kw list --json | fields --item id store name level basis

[ "$(kw get "$ID" --key db_password)" = "hunter2" ] || fail "get --key answers the raw value"
kw get "$ID" | python3 -c 'import json,sys; body=json.load(sys.stdin); assert body["db_password"]=="hunter2", body' \
  || fail "get answers the whole kv payload as flat json"

kw view "$ID" | tee "$OUT/cli-view.txt" | grep -q db-creds || fail "view names the secret"
kw view "$ID" --json | fields id store name level basis
[ "$(kw view "$ID" --json | json_get '"basis"')" = "owner" ]

patched="$(kw patch "$ID" --value '{"db_password":"hunter3","api_key":"abc"}' --note rotated --json)"
echo "$patched" | fields id state
[ "$(echo "$patched" | json_get '"id"')" = "2" ] || fail "the second version is 2"
[ "$(kw get "$ID" --key db_password)" = "hunter3" ] || fail "the new version wins"

# The CLI's Grant wire type carries exactly what the Rust one did — id,
# subject_kind, subject, level, keys, granted_by, and deliberately no
# timestamps (cmd/cli/internal/wire). The timestamped view is asserted over
# raw HTTP in step 6.
grant="$(kw delegate "$ID" --group "SRE Team" --level read --key db_password --days 7 --note "on call" --json)"
echo "$grant" | fields id subject_kind subject level keys granted_by
[ "$(echo "$grant" | json_get '"subject_kind"')" = "group" ]
[ "$(echo "$grant" | json_get '"subject"')" = "SRE Team" ]
[ "$(echo "$grant" | json_get '"granted_by"')" = "dev" ]
GRANT_ID="$(echo "$grant" | json_get '"id"')"
echo "OK: list, get, view, patch, delegate all answered (grant $GRANT_ID)"

# The Store calls above make the backend metrics exist; the Rust metric names
# carry over because the dashboards already exist.
curl -fsS http://127.0.0.1:19090/metrics | grep -q keyway_backend_calls_total \
  || fail "keyway_backend_calls_total on the scrape endpoint"

# --- 6. the unchanged dashboard ----------------------------------------------
step "6. the unchanged dashboard: build, serve, and the api.ts contract"
# Not one line of keyway-dashboard changes for the port (ADR-0006). pnpm 10,
# because pnpm-lock.yaml is the lockfile the repo ships (there is no
# package-lock.json for npm ci to hold on to) and its pnpm-workspace.yaml
# speaks pnpm 10's `allowBuilds`.
(cd keyway-dashboard && npx -y pnpm@10 install --frozen-lockfile --silent && npx -y pnpm@10 build) \
  > "$OUT/dashboard-build.log" 2>&1 || { tail -20 "$OUT/dashboard-build.log"; fail "dashboard build"; }
[ -f keyway-dashboard/dist/index.html ] || fail "no build output"
python3 -m http.server 18090 --directory keyway-dashboard/dist > /dev/null 2>&1 &
DASH_PID=$!
sleep 1
curl -fsS http://127.0.0.1:18090/ | grep -q '<script' || fail "serving the build output"
echo "OK: built and served"

# Every endpoint api.ts constructs, with its exact path, method and body —
# asserting the field names its interfaces destructure.
echo "-- api.me"
curl -fsS $BASE/api/me | fields handle groups roles is_admin may_create directory \
  branding.name branding.logo branding.favicon branding.accent
[ "$(curl -fsS $BASE/api/me | json_get '"is_admin"')" = "True" ] || fail "dev holds admin"

echo "-- api.stores"
curl -fsS $BASE/api/stores | fields --item id title allow

echo "-- api.secrets / api.secret"
curl -fsS $BASE/api/secrets | fields --item id store name level basis
curl -fsS "$BASE/api/secrets/$ID" | fields id store name level basis latest_version

echo "-- api.versions"
curl -fsS "$BASE/api/secrets/$ID/versions" | fields --item id state

echo "-- api.history (timestamps parse; equality is semantic, never bytes)"
curl -fsS "$BASE/api/secrets/$ID/history" | fields --item id at:ts actor action store secret secret_id

echo "-- api.reveal, uncacheable"
reveal_headers="$(curl -fsS -D - -o "$OUT/reveal.txt" "$BASE/api/secrets/$ID/value?key=db_password")"
grep -qi 'cache-control: no-store' <<<"$reveal_headers" || fail "a reveal must be no-store"
[ "$(cat "$OUT/reveal.txt")" = "hunter3" ] || fail "reveal answers the raw value"

echo "-- api.create / api.patch (the dashboard's exact bodies)"
dashed="$(curl -fsS -X POST -H 'content-type: application/json' \
  -d '{"store":"local","name":"dash-made","value":"s3cret","note":""}' $BASE/api/secrets)"
echo "$dashed" | fields id store name level basis
DASH_ID="$(echo "$dashed" | json_get '"id"')"
curl -fsS -X POST -H 'content-type: application/json' \
  -d '{"value":"s3cret2","note":"from the dialog"}' "$BASE/api/secrets/$DASH_ID/versions" \
  | fields id state

echo "-- api.grants / api.delegate / api.revoke"
curl -fsS "$BASE/api/secrets/$ID/grants" | fields --item id subject_kind subject level granted_by granted_at:ts
dash_grant="$(curl -fsS -X POST -H 'content-type: application/json' \
  -d '{"subject_kind":"user","subject":"bob","level":"read","keys":[],"days":30,"note":"dash"}' \
  "$BASE/api/secrets/$DASH_ID/grants")"
echo "$dash_grant" | fields id subject_kind subject level granted_by granted_at:ts expires_at:ts
DASH_GRANT_ID="$(echo "$dash_grant" | json_get '"id"')"
[ "$(status_of -X DELETE "$BASE/api/secrets/$DASH_ID/grants/$DASH_GRANT_ID")" = "204" ] || fail "revoke is 204"

echo "-- api.audit (admin-fenced: 403 to the role-less token, 200 to dev)"
[ "$(status_of -H "Authorization: Bearer $TOKEN" "$BASE/api/audit?limit=200")" = "403" ] || fail "the token holds no roles"
curl -fsS "$BASE/api/audit?limit=200" | fields --item id at:ts actor action store secret

echo "-- api.tokens / api.mintToken / api.revokeToken"
curl -fsS $BASE/api/tokens | fields --item id name created_at:ts
doomed="$(curl -fsS -X POST -H 'content-type: application/json' -d '{"name":"doomed","days":1}' $BASE/api/tokens)"
echo "$doomed" | fields id name token expires_at:ts
[ "$(status_of -X DELETE "$BASE/api/tokens/$(echo "$doomed" | json_get '"id"')")" = "204" ] || fail "token revoke is 204"

echo "-- api.remove"
[ "$(status_of -X DELETE "$BASE/api/secrets/$DASH_ID")" = "204" ] || fail "remove is 204"
echo "OK: every api.ts endpoint answers the shape the dashboard reads"

# --- probes the transport port flagged ---------------------------------------
step "probes: addresses, malformed bodies, non-object reveals, error JSON"
[ "$(status_of "$BASE/api/secrets/db-creds")" = "400" ] || fail "a name is not an address"
[ "$(status_of "$BASE/api/secrets/00000000-0000-4000-8000-000000000000")" = "404" ] || fail "an unknown uuid is 404"

# axum's Json extractor split: wrong/missing Content-Type 415, JSON that does
# not parse 400, JSON of the wrong shape 422.
[ "$(status_of -X POST -d '{}' $BASE/api/secrets)" = "415" ] || fail "no json content-type is 415"
[ "$(status_of -X POST -H 'content-type: text/plain' -d '{}' $BASE/api/secrets)" = "415" ] || fail "text/plain is 415"
[ "$(status_of -X POST -H 'content-type: application/json' -d '{"broken' $BASE/api/secrets)" = "400" ] || fail "unparseable json is 400"
[ "$(status_of -X POST -H 'content-type: application/json' -d '{"name":"x","value":"y"}' $BASE/api/secrets)" = "422" ] || fail "a missing field is 422"
[ "$(status_of -X POST -H 'content-type: application/json' -d '{"store":5,"name":"x","value":"y"}' $BASE/api/secrets)" = "422" ] || fail "a wrong type is 422"
[ "$(status_of -X POST -H 'content-type: application/json' -d '{"value":null}' "$BASE/api/secrets/$ID/versions")" = "422" ] || fail "a null required field is 422"

# ?key= on a payload that is valid JSON but not an object: 404, like
# serde_json's Value::get answering None.
listy="$(curl -fsS -X POST -H 'content-type: application/json' \
  -d '{"store":"local","name":"listy","value":"[1,2,3]","note":""}' $BASE/api/secrets)"
LISTY_ID="$(echo "$listy" | json_get '"id"')"
[ "$(status_of "$BASE/api/secrets/$LISTY_ID/value?key=x")" = "404" ] || fail "a non-object payload has no keys: 404"
[ "$(curl -fsS "$BASE/api/secrets/$LISTY_ID/value")" = "[1,2,3]" ] || fail "the whole payload still reveals"
[ "$(status_of -X DELETE "$BASE/api/secrets/$LISTY_ID")" = "204" ]

# Failures are `{ error }`, the shape api.ts request() reads.
curl -s -X POST -H 'content-type: application/json' -d '{"name":"x","days":-1}' $BASE/api/tokens \
  | python3 -c 'import json,sys; assert json.load(sys.stdin)["error"] == "days cannot be negative"' \
  || fail 'failures carry { "error": <sentence> }'

# A revoked token stops working — deleting it is the only revocation here.
[ "$(status_of -X DELETE "$BASE/api/tokens/$TOKEN_ID")" = "204" ]
[ "$(status_of -H "Authorization: Bearer $TOKEN" $BASE/api/me)" = "401" ] || fail "a revoked token is 401"
echo "OK: every probe answered the Rust statuses"

echo
echo "NOTE: no live OIDC issuer runs in this compose file, so the sign-in"
echo "callback flow stays covered by unit tests only (internal/identity)."

# --- 7. the Rust CLI (removed at cutover) ------------------------------------
step "7. the Rust CLI"
echo "SKIPPED: the Rust crates were removed at the cutover (kotsmile/keyway#30);"
echo "         there is no Rust CLI to build. Its wire behaviour stays pinned by"
echo "         the cmd/cli/internal/wire and cmd/cli/internal/output tests."

# --- 8. the differential probe (removed at cutover) --------------------------
step "8. Rust server vs Go server"
echo "SKIPPED: the Rust server was removed at the cutover (kotsmile/keyway#30);"
echo "         there is nothing left to diff against. The same cases are pinned"
echo "         Go-side against the Rust sources as they last shipped: basis wire"
echo "         string + ?key= semantics in internal/transport/http/secrets_test.go,"
echo "         statuses and two-caller flows in internal/transport/http/"
echo "         parity_test.go, golden Rust ciphertext/token vectors in the"
echo "         crypto and tokens entity tests."

step "PASSED: the e2e gate is green"
