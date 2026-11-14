# SpotSignal privacy and safety notes

## Purpose boundary

SpotSignal is for nearby resources and environmental conditions, never for finding, tracking, or identifying an individual. Do not submit a person's location, a sleeping place, names, photos, contact details, or free-text descriptions. The fixed categories are `spot`, `full`, `hazard`, `activity`, and `resource`; the API rejects unknown fields and stores no note.

## Data minimization

- The PWA does not call the browser geolocation API. A visitor selects an approximate point manually.
- Before any database write, the server snaps coordinates to the center of a grid cell. Sensitive categories use 0.003° cells; resource and hazard reports use 0.001° cells. These are approximate north/south spans of 333 m and 111 m; east/west spans vary by latitude. Raw coordinates are discarded in the request handler.
- Public responses contain only a category, the coarse cell, confidence, report ID, and day-level dates. They exclude reporter identifiers, exact times, notes, votes' device hashes, and alert preferences.
- Browser tokens are random, HttpOnly, SameSite=Strict, and expire after one day. Persistent identifiers are keyed daily hashes. IPs are used only in-memory to compute keyed rate-limit buckets; request logging is off.
- Reports are delayed and deleted after their category TTL. The database stores only the already-coarsened location. Moderation deletion cascades to votes.
- OpenStreetMap tiles are not loaded until a visitor explicitly selects “Load street map”; that request reveals the visitor IP and requested tile area to the tile provider.

## Activity reports

Activity reports are globally disabled unless `ACTIVITY_ALERTS_ENABLED=true`. Enabling the server flag alone does not expose them: the submitter must check an explicit opt-in, each viewer must separately opt into a coarse alert area, and the report is held for at least one hour. Alert-area records are coarse, associated only with the browser's daily pseudonym, and expire within one day. The MVP offers an opt-in activity view, not push notifications. The Telegram bot does not accept activity reports.

## Abuse and limits

Writes require a one-use, client-bound SHA-256 proof-of-work challenge. IP rate-limit keys are HMACed with `APP_HMAC_SECRET`; per-device report and vote limits use daily pseudonyms. These are friction controls, not a guarantee against a determined attacker or Sybil activity. Moderation routes fail closed unless a strong bearer secret is configured.

## Residual risk

A coarse, delayed cell can still reveal a sensitive area when combined with outside information or repeated observations. The MVP is local-only by default and contains no real reports. Do not populate it with real people's locations or expose it publicly until a qualified local partner reviews the threat model, data retention, categories, response procedures, and applicable law. Changing the grid size alone is not a substitute for that review.
