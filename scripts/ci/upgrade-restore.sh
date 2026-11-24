#!/usr/bin/env bash
# CI: upgrade, migration and restore test.
#
# For the previous release and the oldest 1.x release:
#   1. PostgreSQL upgrade: the old server creates its schema and an
#      administrator, the current server migrates the same database.
#   2. SQLite import: the old server runs on SQLite, the current server
#      starts on an empty PostgreSQL database and imports the file.
# Then the current server backs up the upgraded database (PostgreSQL -> SQLite
# file) and restores it into a new SQLite and a new PostgreSQL database.
# A database counts as carried over when /setup redirects (an administrator exists).
#
# Needs PostgreSQL (PGHOST, PGUSER, PGPASSWORD), psql, curl and the release tags.
set -euo pipefail

work="$(mktemp -d)"
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  git worktree prune
}
trap cleanup EXIT

export PATCHMAN_LOG_LEVEL=warn PATCHMAN_UPDATE_CHECK_URL=off PATCHMAN_KEV_URL=off PATCHMAN_EPSS_URL=off \
  PATCHMAN_EOL_URL=off PATCHMAN_MSRC_URL=off PATCHMAN_OSV_URL=http://127.0.0.1:9 GOTOOLCHAIN=local CGO_ENABLED=0
pgurl() { echo "postgres://${PGUSER}:${PGPASSWORD}@${PGHOST}:5432/$1?sslmode=disable"; }
newdb() { psql -q -d postgres -c "DROP DATABASE IF EXISTS $1" -c "CREATE DATABASE $1"; }

# build <git ref or HEAD> <output>
build() {
  if [ "$1" = HEAD ]; then
    go build -o "$2" ./cmd/netio-patchman-server
  else
    git worktree add -q --detach "$work/src-$1" "$1"
    (cd "$work/src-$1" && go build -o "$2" ./cmd/netio-patchman-server)
  fi
}

port=18100
# start <binary> <data dir> <database url>: runs the server until it is healthy.
start() {
  port=$((port + 1))
  mkdir -p "$2"
  PATCHMAN_DATA_DIR="$2" PATCHMAN_DATABASE_URL="$3" PATCHMAN_HTTP_ADDR="127.0.0.1:$port" \
    PATCHMAN_BASE_URL="http://127.0.0.1:$port" "$1" >"$2/server.log" 2>&1 &
  pid=$!
  pids+=("$pid")
  for _ in $(seq 1 120); do
    if curl -fsS "http://127.0.0.1:$port/healthz" 2>/dev/null | grep -q '"status":"ok"'; then return 0; fi
    if ! kill -0 "$pid" 2>/dev/null; then break; fi
    sleep 0.5
  done
  echo "::error::server did not start ($1, $3)"; cat "$2/server.log"; exit 1
}
stop() { kill -TERM "$pid"; wait "$pid" 2>/dev/null || true; }

create_admin() {
  code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$port/setup" \
    --data-urlencode "name=CI Yönetici" --data-urlencode "email=ci@example.test" \
    --data-urlencode "password=ci-parola-1234567" --data-urlencode "password_confirm=ci-parola-1234567")"
  [ "$code" = 303 ] || { echo "::error::setup returned $code"; exit 1; }
}
expect_admin() {
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/setup")"
  [ "$code" = 302 ] || { echo "::error::$1: the administrator is missing (setup returned $code)"; exit 1; }
  echo "ok: $1"
}

head_tags="$(git tag --points-at HEAD)"
previous="$(git tag -l 'v*' --sort=-v:refname | grep -vxF -e "${head_tags:-none}" | head -n1)"
oldest="$(git tag -l 'v1.*' --sort=v:refname | head -n1)"
releases="$(printf '%s\n%s\n' "$previous" "$oldest" | awk 'NF && !seen[$0]++')"
echo "Upgrading from: $(echo "$releases" | tr '\n' ' ')"

build HEAD "$work/current"
for rel in $releases; do
  db="up_${rel//[.v]/_}"
  build "$rel" "$work/server-$rel"

  # 1. PostgreSQL schema written by the old release, migrated by the current one.
  newdb "$db"
  start "$work/server-$rel" "$work/data-$db-old" "$(pgurl "$db")"
  create_admin
  stop
  start "$work/current" "$work/data-$db-new" "$(pgurl "$db")"
  expect_admin "PostgreSQL upgrade from $rel"
  stop

  # 2. SQLite file of the old release imported into PostgreSQL.
  imp="imp_${rel//[.v]/_}"
  newdb "$imp"
  start "$work/server-$rel" "$work/data-$imp" sqlite
  create_admin
  stop
  start "$work/current" "$work/data-$imp" "$(pgurl "$imp")"
  expect_admin "SQLite import from $rel"
  stop
  ls "$work/data-$imp"/netio-patchman.db.imported-* >/dev/null
done

# Backup of the upgraded PostgreSQL database and restore into new databases.
last="up_${previous//[.v]/_}"
mkdir -p "$work/backup-src" "$work/restore-sqlite" "$work/restore-pg"
PATCHMAN_DATA_DIR="$work/backup-src" PATCHMAN_DATABASE_URL="$(pgurl "$last")" "$work/current" backup -out "$work/backup.db"
test -s "$work/backup.db"

PATCHMAN_DATA_DIR="$work/restore-sqlite" PATCHMAN_DATABASE_URL=sqlite "$work/current" restore -in "$work/backup.db"
start "$work/current" "$work/restore-sqlite" sqlite
expect_admin "restore into SQLite"
stop

newdb restored
PATCHMAN_DATA_DIR="$work/restore-pg" PATCHMAN_DATABASE_URL="$(pgurl restored)" "$work/current" restore -in "$work/backup.db"
start "$work/current" "$work/restore-pg" "$(pgurl restored)"
expect_admin "restore into PostgreSQL"
stop

echo "Upgrade, migration and restore: all passed"
