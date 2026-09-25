#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${MARID_APP_PASSWORD:-}" ]]; then
  echo "MARID_APP_PASSWORD is required" >&2
  exit 1
fi

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=app_password="$MARID_APP_PASSWORD" <<'EOSQL'
SELECT format('CREATE ROLE marid_app LOGIN PASSWORD %L', :'app_password') \gexec
EOSQL
