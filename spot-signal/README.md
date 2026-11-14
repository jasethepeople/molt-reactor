# SpotSignal MVP

SpotSignal is a local-only, anonymous field guide for **resources and environmental conditions**. It is deliberately not a people-finder. It uses a Fastify API, PostgreSQL/PostGIS, a small installable PWA, and an optional Telegram bot.

## Privacy defaults

- No accounts, free-text notes, names, photos, or browser geolocation.
- Sensitive categories (`spot`, `full`, `activity`) are stored at 0.003° cells; hazards and resources use 0.001° cells. Coordinates are snapped before persistence. The 0.0005° base unit is multiplied to widen the sensitive-category cell.
- Reports are delayed and expire by category. Activity reports and their in-app view are off by default; a reporter and each viewer must opt in separately. The bot rejects activity reports.
- Street tiles are off until the visitor chooses “Load street map”; the page discloses that this contacts OpenStreetMap.
- The container port binds to `127.0.0.1` only. Do not publish real reports or expose the app publicly without a local safety/privacy review.

See [`docs/PRIVACY.md`](docs/PRIVACY.md) and [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) before any use with real data.

## Run locally

Requires Node.js 22+ and Docker Compose v2. Copy `.env.example` to `.env`, set distinct 32-byte hex values for `POSTGRES_PASSWORD`, `APP_DB_PASSWORD`, and `APP_HMAC_SECRET`; set `SECURE_COOKIES=true` only when HTTPS is correctly terminated in front of the app.

```sh
npm ci
docker compose up --build -d
```

Open `http://127.0.0.1:8080`. The database port is not published, and the web app uses a separate, non-superuser database role. `ACTIVITY_ALERTS_ENABLED` stays `false` unless explicitly reviewed. `docker compose down -v` deletes the local database volume.

To enable the optional Telegram bot, configure `TELEGRAM_BOT_TOKEN` and a separate 32-byte hex `BOT_INGEST_TOKEN` in the private `.env`, then run `docker compose --profile telegram up --build -d`. The bot accepts private-chat, fixed-format non-activity reports only. It does not store Telegram sender IDs or forward message text.

## Development and tests

```sh
npm test
npm audit --omit=dev
```

The suite exercises the in-memory API, privacy/abuse controls, bot parser, and PostGIS storage. The PostGIS integration test runs when `TEST_DATABASE_URL` points to a disposable database whose name ends in `_test`; it applies the migration and deletes its fixture rows. It is skipped if that variable is absent.

## MVP boundaries

Activity “alerts” are an opt-in, coarse in-app view, not push notifications. Rate limits and proof-of-work are friction, not Sybil resistance. Storage is single-instance. This repository does not include real reports, bot credentials, a public deployment, or an emergency-response service.
