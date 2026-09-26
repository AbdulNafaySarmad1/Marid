#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${MARID_APP_PASSWORD:-}" || -z "${MARID_WORKER_PASSWORD:-}" ]]; then
  echo "MARID_APP_PASSWORD and MARID_WORKER_PASSWORD are required" >&2
  exit 1
fi

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=app_password="$MARID_APP_PASSWORD" \
  --set=worker_password="$MARID_WORKER_PASSWORD" <<'EOSQL'
SELECT format('CREATE ROLE marid_app LOGIN PASSWORD %L', :'app_password') \gexec
SELECT format('CREATE ROLE marid_worker LOGIN PASSWORD %L', :'worker_password') \gexec
EOSQL
