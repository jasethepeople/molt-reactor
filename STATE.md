# State

## Baseline
- Repository: `jasethepeople/molt-reactor`, clean `main`, synchronized with `origin/main`.
- Baseline checks: `cargo test` — 39 passed; `cargo run -- demo` — ✅, 4 inputs → 3 outputs, replay-identical.

## Phase 1 — SPEC v1.1
- Status: complete; spec is version 1.1 and now pins the JSON array range shape, canonical JSON, replay marker, chain depth, error taxonomy, and required semantic details.
- Verification: `cargo test` — 39 passed; `cargo run -- demo` — passed; `git diff --check` — passed.
- Known spec/implementation gaps are tracked in Phase 2; this phase intentionally changed documentation only.

## Phase 2 — Rust alignment
- Status: not started.

## Phase 3 — Conformance vectors
- Status: not started.

## Phase 4 — SpotSignal
- Status: not started. No Telegram bot token or production database credentials have been found.
- Public deployment: intentionally not attempted; rough-sleeper location data requires a privacy/safety review and explicit deployment authorization.

## Acceptance status
- MOLT v1.1 documentation: complete.
- Rust implementation aligned: pending Phase 2.
- Eight conformance vectors: pending.
- SpotSignal local MVP: pending.

## Next
Commit Phase 1, then start Phase 2 after re-reading STATE.md, TASKS.md, and DECISIONS.md.
