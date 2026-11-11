#!/bin/sh
# Synthetic IT4US VA records only. No scanner or network target is invoked.
set -eu

usage() {
  echo "Usage: $0 seed|clear|status" >&2
  exit 2
}

[ "$#" -eq 1 ] || usage
case "$1" in seed|clear|status) ;; *) usage ;; esac

container=${IT4US_PG_CONTAINER:-it4us-va-postgres-1}
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if ! docker inspect "$container" >/dev/null 2>&1; then
  echo "PostgreSQL container not found: $container" >&2
  exit 1
fi

case "$1" in
  seed)
    docker exec -i "$container" sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -1' < "$script_dir/seed-va-demo-20261111.sql"
    ;;
  clear)
    docker exec -i "$container" sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -1' < "$script_dir/clear-va-demo-20261111.sql"
    ;;
  status)
    docker exec "$container" sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT (SELECT count(*) FROM companies WHERE nkey=\$\$demo-infra-va-20261111\$\$), (SELECT count(*) FROM tasks WHERE name=\$\$DEMO - VA Infra (dados ficticios)\$\$), (SELECT count(*) FROM assets WHERE extra @> \$\$ {\"demo\":true} \$\$::jsonb), (SELECT count(*) FROM findings WHERE worker=\$\$demo:synthetic\$\$)"' | awk -F '|' '{printf "companies=%s tasks=%s assets=%s findings=%s\n", $1, $2, $3, $4}'
    ;;
esac
