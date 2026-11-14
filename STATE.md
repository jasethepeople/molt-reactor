# State

## Repository
- Repository: `jasethepeople/molt-reactor`, branch `main`.
- Phases 1–3 are committed and pushed. Phase 4 implementation and verification are complete; the Phase 4 commit/push and final ZIP remain.

## Phase 1 — SPEC v1.1
- Complete. The specification pins canonical JSON/i64 boundaries, strict verified-range and replay-marker validation, stable error codes, trigger-depth and `escrow_action` deliver semantics, and `Engine::verify`.

## Phase 2 — Rust alignment
- Complete. 58 integration tests, the escrow demo, release build, formatting, and strict Clippy pass.

## Phase 3 — Conformance
- Complete. Eight versioned JSON vectors cover emit, gas, conflict, depth, replay, deliver scoping, orphan markers, and out-of-i64 payloads; the harness passes.

## Phase 4 — SpotSignal local MVP
- Implemented in `spot-signal/`: Fastify API, PostGIS migration with a least-privilege app role, privacy-first PWA, optional fixed-format Telegram bot, Compose files, tests, and deployment/privacy docs.
- Verified 17 SpotSignal tests against a disposable local PostGIS database, plus a browser/API smoke test; synthetic data and temporary database objects were removed.
- Docker/Compose and a Telegram bot token are unavailable here. The Compose YAML was parsed, but the container stack and Telegram polling were not launched. No public deployment or real report data was created. See `spot-signal/docs/FINAL_REPORT.md`.

## Next
Commit and push the verified Phase 4 files, create and inspect `molt-reactor.zip`, then record the final archive path.
