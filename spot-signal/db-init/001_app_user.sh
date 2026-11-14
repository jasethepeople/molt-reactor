#!/bin/sh
set -eu

if [ -z "${APP_DB_PASSWORD:-}" ]; then
  printf '%s\n' 'APP_DB_PASSWORD is required.' >&2
  exit 1
fi

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\set QUIET on
CREATE EXTENSION IF NOT EXISTS postgis;
\getenv app_password APP_DB_PASSWORD
\getenv app_database POSTGRES_DB

SELECT format('CREATE ROLE spotsignal_app LOGIN PASSWORD %L', :'app_password') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO spotsignal_app', :'app_database') \gexec
GRANT USAGE, CREATE ON SCHEMA public TO spotsignal_app;
SQL
