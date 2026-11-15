# State

## Repository
- Repository: `jasethepeople/molt-reactor`, branch `main`.
- Phases 1–4 are implemented and pushed; no public deployment was made.

## Phase 1 — SPEC v1.1
- Complete. The specification pins canonical JSON/i64 boundaries, strict verified-range and replay-marker validation, stable error codes, trigger-depth and `escrow_action` delivery semantics, and `Engine::verify`.

## Phase 2 — Rust alignment
- Complete. 58 integration tests, the escrow demo, release build, formatting, and strict Clippy pass.

## Phase 3 — Conformance
- Complete. Eight versioned JSON vectors cover emit, gas, conflict, depth, replay, delivery scoping, orphan markers, and out-of-i64 values. The conformance target passes.

## Phase 4 — SpotSignal local MVP
- Implemented in `spot-signal/`: Fastify API, PostGIS migration with a least-privilege app role, privacy-first PWA, optional fixed-format Telegram bot, Compose files, and privacy/deployment documentation.
- Current `npm test`: 16 passed, 1 PostGIS integration test skipped because no test database is configured. The prior disposable-PostGIS verification is recorded in `spot-signal/docs/FINAL_REPORT.md`.
- `npm audit --omit=dev`: zero vulnerabilities. Docker/Compose and a Telegram bot token are unavailable here. No real report data or public service was created.

## Verification
- The documented single-command Rust acceptance chain passed, including the expected HashMap-reactor rejection.
- Rust: 58 integration tests plus the eight-vector conformance target; demo, formatting, Clippy, and release build passed.

## Delivery
- Full source ZIP: `/home/workspace/molt-reactor-2026-11-12.zip` (generated without `.git`, build output, or `node_modules`).
