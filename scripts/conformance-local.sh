#!/usr/bin/env bash
# conformance-local.sh — run the backendkit conformance suite against a Socrate
# built from source, the same way the Conformance workflow does.
#
#   SOCRATE_SRC=../go-oauth2 \
#   CONFORMANCE_DATABASE_URL=postgres://user:pass@127.0.0.1:5432/socrate_conf?sslmode=disable \
#   scripts/conformance-local.sh [packages…]
#
# It wipes the database's public schema, builds Socrate from SOCRATE_SRC,
# starts it on loopback (migrating the schema), seeds three clients and one user
# per suite package with conformance/testdata/socrate-seed, then runs
# the live tests (`go test -tags conformance -run '^TestConformance'`, default
# packages ./...) with the SOCRATE_* variables the suite reads. Every secret is generated for the run; nothing is written to
# either repository except a temporary seed directory in SOCRATE_SRC, removed on
# exit. The server log is kept in $CONFORMANCE_WORKDIR (default: a temp dir).
#
# Variables:
#   SOCRATE_SRC               Socrate source tree (ovander/go-oauth2) — required
#   CONFORMANCE_DATABASE_URL  scratch PostgreSQL database — required, WIPED
#   CONFORMANCE_PORT          public port (default 18080); admin port is +1
#   CONFORMANCE_WORKDIR       where the binary, keys and server.log go
#   SOCRATE_BIN               a Socrate server binary already built from
#                             SOCRATE_SRC (skips the build; the workflow builds
#                             it with Socrate's own Go)
#   CONFORMANCE_SERVE=1       boot and seed, print the environment, and keep the
#                             server running until interrupted (no tests)
set -euo pipefail

die() { echo "conformance-local: $*" >&2; exit 1; }

[ -n "${SOCRATE_SRC:-}" ] || die "SOCRATE_SRC (a go-oauth2 checkout) is required"
[ -f "$SOCRATE_SRC/go.mod" ] || die "SOCRATE_SRC=$SOCRATE_SRC is not a Go module"
grep -q '^module github.com/ovander/go-oauth2$' "$SOCRATE_SRC/go.mod" ||
  die "SOCRATE_SRC=$SOCRATE_SRC is not github.com/ovander/go-oauth2"
[ -n "${CONFORMANCE_DATABASE_URL:-}" ] || die "CONFORMANCE_DATABASE_URL (a scratch database) is required"
command -v psql >/dev/null || die "psql is required"
command -v openssl >/dev/null || die "openssl is required"

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SOCRATE_SRC=$(cd "$SOCRATE_SRC" && pwd)
PORT=${CONFORMANCE_PORT:-18080}
ADMIN_PORT=$((PORT + 1))
WORKDIR=${CONFORMANCE_WORKDIR:-$(mktemp -d)}
mkdir -p "$WORKDIR/keys"
SEED_DIR="$SOCRATE_SRC/.conformance-seed-$$"
SERVER_PID=""

cleanup() {
  status=$?
  if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    for _ in $(seq 1 20); do kill -0 "$SERVER_PID" 2>/dev/null || break; sleep 0.5; done
    kill -9 "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$SEED_DIR"
  if [ "$status" -ne 0 ] && [ -f "$WORKDIR/server.log" ]; then
    echo "--- last 80 lines of the Socrate log ($WORKDIR/server.log) ---" >&2
    tail -80 "$WORKDIR/server.log" >&2 || true
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

rand() { openssl rand -hex "$1"; }

# --- the run's configuration (throwaway values) ------------------------------
export SOCRATE_ISSUER="http://127.0.0.1:$PORT"
export SOCRATE_ADMIN_URL="http://127.0.0.1:$ADMIN_PORT"
export SOCRATE_PLAIN_CLIENT_ID="conformance-plain"
export SOCRATE_PLAIN_CLIENT_SECRET="cs-$(rand 24)"
export SOCRATE_DUAL_CLIENT_ID="conformance-dual"
export SOCRATE_DUAL_CLIENT_SECRET="cs-$(rand 24)"
export SOCRATE_CLAIMS_CLIENT_ID="conformance-claims"
export SOCRATE_CLAIMS_CLIENT_SECRET="cs-$(rand 24)"
export SOCRATE_REDIRECT_URI="http://127.0.0.1:9/callback"
export SOCRATE_AUDIENCE="https://api.conformance.test"
SOCRATE_TENANT_ID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen | tr 'A-Z' 'a-z')
export SOCRATE_TENANT_ID
# The suite asserts the policy decision point runs in this mode.
export SOCRATE_POLICY_MODE=off
# 12–72 characters with every class the password policy asks for.
export SOCRATE_USER_PASSWORD="Pw-$(rand 12)-aZ9!"

# --- a clean schema ------------------------------------------------------------
echo "conformance-local: wiping the public schema of the scratch database"
psql "$CONFORMANCE_DATABASE_URL" -q -v ON_ERROR_STOP=1 -c 'SET client_min_messages TO warning' \
  -c 'DROP SCHEMA IF EXISTS public CASCADE' -c 'CREATE SCHEMA public' >/dev/null

# --- build and start Socrate -----------------------------------------------------
REV=$(git -C "$SOCRATE_SRC" rev-parse --short HEAD 2>/dev/null || echo 'not a git tree')
if [ -n "${SOCRATE_BIN:-}" ]; then
  [ -x "$SOCRATE_BIN" ] || die "SOCRATE_BIN=$SOCRATE_BIN is not executable"
  echo "conformance-local: using $SOCRATE_BIN (source $SOCRATE_SRC at $REV)"
  [ "$SOCRATE_BIN" -ef "$WORKDIR/socrate" ] || cp "$SOCRATE_BIN" "$WORKDIR/socrate"
else
  echo "conformance-local: building Socrate from $SOCRATE_SRC ($REV)"
  (cd "$SOCRATE_SRC" && go build -o "$WORKDIR/socrate" ./cmd/server)
fi

echo "conformance-local: starting Socrate on $SOCRATE_ISSUER (admin $SOCRATE_ADMIN_URL)"
(
  cd "$WORKDIR"
  # The suite asserts AUDIENCE_MODE=dual (aud = client_id + registered
  # audiences) and DPOP_MODE=observe (a valid proof binds the token, no proof
  # is still accepted). Rate limits are lifted: the suite signs in many times.
  # exec: SERVER_PID is the server itself, so the cleanup stops it.
  exec env ENV=development PORT="$PORT" ADMIN_PORT="$ADMIN_PORT" ADMIN_BIND_HOST=127.0.0.1 \
    DATABASE_URL="$CONFORMANCE_DATABASE_URL" OAUTH_ISSUER="$SOCRATE_ISSUER" \
    SECRET_KEY_BASE="$(rand 32)" KEYS_PATH="$WORKDIR/keys" AUTO_MIGRATE=true \
    AUDIENCE_MODE=dual DPOP_MODE=observe POLICY_MODE="$SOCRATE_POLICY_MODE" LOG_LEVEL=info \
    RATE_LIMIT_LOGIN=1000000 RATE_LIMIT_SIGNUP=1000000 RATE_LIMIT_TOKEN=1000000 \
    "$WORKDIR/socrate" >"$WORKDIR/server.log" 2>&1
) &
SERVER_PID=$!
for i in $(seq 1 60); do
  if curl -fs -o /dev/null "$SOCRATE_ISSUER/health"; then
    echo "conformance-local: Socrate up after ${i}s"
    break
  fi
  kill -0 "$SERVER_PID" 2>/dev/null || die "Socrate exited during start-up"
  [ "$i" -lt 60 ] || die "Socrate did not become healthy"
  sleep 1
done

# --- seed ------------------------------------------------------------------------
mkdir -p "$SEED_DIR"
cp "$ROOT/conformance/testdata/socrate-seed/main.go" "$SEED_DIR/main.go"
(
  cd "$SOCRATE_SRC"
  env DATABASE_URL="$CONFORMANCE_DATABASE_URL" \
    CONFORMANCE_PLAIN_CLIENT_ID="$SOCRATE_PLAIN_CLIENT_ID" CONFORMANCE_PLAIN_CLIENT_SECRET="$SOCRATE_PLAIN_CLIENT_SECRET" \
    CONFORMANCE_DUAL_CLIENT_ID="$SOCRATE_DUAL_CLIENT_ID" CONFORMANCE_DUAL_CLIENT_SECRET="$SOCRATE_DUAL_CLIENT_SECRET" \
    CONFORMANCE_CLAIMS_CLIENT_ID="$SOCRATE_CLAIMS_CLIENT_ID" CONFORMANCE_CLAIMS_CLIENT_SECRET="$SOCRATE_CLAIMS_CLIENT_SECRET" \
    CONFORMANCE_REDIRECT_URI="$SOCRATE_REDIRECT_URI" CONFORMANCE_AUDIENCE="$SOCRATE_AUDIENCE" \
    CONFORMANCE_TENANT_ID="$SOCRATE_TENANT_ID" CONFORMANCE_USER_PASSWORD="$SOCRATE_USER_PASSWORD" \
    CONFORMANCE_USERS="conf-fixtures,conf-mfa,conf-jwtauth,conf-socrate,conf-bff,conf-pep" \
    go run "./$(basename "$SEED_DIR")"
)
rm -rf "$SEED_DIR"

if [ "${CONFORMANCE_SERVE:-}" = "1" ]; then
  echo "conformance-local: serving; export these to run the suite yourself:"
  env | grep '^SOCRATE_' | grep -v '^SOCRATE_SRC=' | sed 's/^/  export /'
  echo "conformance-local: Ctrl-C to stop"
  wait "$SERVER_PID"
  exit 0
fi

# --- the suite ---------------------------------------------------------------------
cd "$ROOT"
if [ "$#" -eq 0 ]; then set -- ./...; fi
echo "conformance-local: go test -tags conformance -run '^TestConformance' $*"
go test -tags conformance -count=1 -race -timeout=300s -run '^TestConformance' "$@"
