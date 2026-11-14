# Deployment notes

## Current default: local only

`compose.yaml` binds the web app to `127.0.0.1:${HOST_PORT:-8080}` and does not publish Postgres. It is intended for a local review, not a public launch. The activity feature is off. No real report data is included.

## Prerequisites and startup

Use Docker Compose v2 and a host with enough disk for the PostGIS image and database volume. Copy `.env.example` to `.env`; generate separate 32-byte hex values for `POSTGRES_PASSWORD`, `APP_DB_PASSWORD`, and `APP_HMAC_SECRET`; generate `MODERATION_TOKEN` and `BOT_INGEST_TOKEN` separately if needed. Do not commit `.env` or put secrets in command-line arguments or logs.

```sh
cp .env.example .env
# Fill the blank secrets in .env using a local secret manager or `openssl rand -hex 32`.
docker compose up --build -d
docker compose ps
curl --fail http://127.0.0.1:8080/api/health
```

The database entrypoint creates PostGIS and a non-superuser `spotsignal_app` role from the two database secrets. The app waits for PostgreSQL health, applies the idempotent schema migration using that role, and then serves the PWA/API. Stop it with `docker compose down`; `docker compose down -v` also permanently deletes the local database volume. To run the optional Telegram bot, configure both bot secrets and start the `telegram` profile:

```sh
docker compose --profile telegram up --build -d
```

The bot polls Telegram only after it is explicitly enabled. It accepts private-chat fixed-format commands and does not forward raw messages to the API.

## HTTPS and reverse proxies

Do not expose this MVP directly to the internet. A future reviewed deployment needs an HTTPS reverse proxy, `SECURE_COOKIES=true`, a narrowly configured trusted-proxy boundary before relying on client-IP rate limits, restrictive firewall rules, backup/retention policy, monitoring that never records request bodies or raw coordinates, and an incident/deletion process. Do not enable `ACTIVITY_ALERTS_ENABLED` or issue Telegram credentials until that review is complete. No domain, DNS, public port, or hosted service has been configured by this repository.

## Checks

```sh
npm ci
npm test
npm audit --omit=dev
```

For a disposable local PostGIS database named with a `_test` suffix, set `TEST_DATABASE_URL` only for the test command to run the database integration test. The test refuses a database whose name does not end in `_test` and removes its fixture rows. See `test/postgres.test.mjs`.
