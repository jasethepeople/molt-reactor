# SpotSignal MVP — Final Report

## Delivered

SpotSignal lives in `spot-signal/` as a separate Node 22/Fastify application with a PostGIS store, migrations, a small installable PWA, a fixed-format optional Telegram bot, and local-first Compose configuration. The app is explicitly framed as a guide to resources and environmental conditions—not a map of people.

Privacy defaults include no accounts, free-text notes, browser geolocation, analytics, or request-body logging; HMACed daily pseudonyms; one-use client-bound proof-of-work challenges; rate limits; 15-minute default publication delay (configurable, with a 5-minute lower bound); short per-category retention; and broad coordinate cells before storage. Sensitive categories use 0.003° cells, resources and hazards 0.001° cells. Activity reports and their in-app view are disabled by default and require separate report and viewer opt-ins. The bot refuses activity reports and stores no Telegram sender ID or message text. OpenStreetMap tiles are not fetched until the visitor opts in, with an on-page IP/privacy disclosure.

The PostGIS schema separates the database bootstrap/superuser from a limited application role. The service is bound to loopback in Compose by default. `.env.example` contains blank secrets; secrets are not included in the repository.

## Verification

- Rust reactor: 58 integration tests, all eight v1.1 conformance vectors, release build, strict Clippy, formatting, and escrow demo passed.
- SpotSignal: 17 tests passed against a disposable PostGIS database. This included schema initialization, an API report write as the non-superuser app role, verification that PostGIS stored only the coarsened cell, activity visibility, voting, and expiry cleanup.
- The PWA loaded in a browser; a synthetic `(0, 0)` report was accepted and delayed. The temporary app, database, role, and test data were removed.
- `npm audit --omit=dev` reported zero production dependency vulnerabilities. Compose YAML parsed successfully.

## Blockers and known limits

Docker and Docker Compose are not installed in this environment, so the container image and Compose stack could not be launched here. The Telegram bot code and parser are tested, but no bot token is configured and live Telegram polling was not attempted. The PWA/API was tested locally; no public URL, hosted service, domain, or DNS change was made.

Activity alerts are an opt-in in-app view, not push notifications. Rate limiting and proof-of-work are abuse friction, not Sybil resistance. The challenge and rate-limit ledgers are in memory, so this MVP is single-instance and restarts clear them. No real reports or emergency-response workflow are included.

## Recommended next steps

1. Keep real reports out of the system until a qualified local partner reviews the safety model, categories, moderation, retention, legal obligations, and response process.
2. On an authorized host with Docker Compose, configure distinct secrets in a private `.env`, start the local stack, and verify health and backups before any public launch.
3. Only if the community explicitly wants Telegram, configure the bot and ingest tokens separately and test it with synthetic reports.
4. Keep activity reports disabled unless the local review explicitly approves them; do not expose precise or live locations of people sleeping rough.
