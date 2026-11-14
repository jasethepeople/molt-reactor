# State

## Baseline
- Repository: `jasethepeople/molt-reactor`, clean `main`, synchronized with `origin/main`.
- Baseline checks: `cargo test` — 39 passed; `cargo run -- demo` — ✅, 4 inputs → 3 outputs, replay-identical.

## Phase 1 — SPEC v1.1
- Status: complete; spec is version 1.1 and now pins the JSON array range shape, canonical JSON, replay marker, chain depth, error taxonomy, and required semantic details.
- Verification: `cargo test` — 39 passed; `cargo run -- demo` — passed; `git diff --check` — passed.
- Known spec/implementation gaps are tracked in Phase 2; this phase intentionally changed documentation only.

## Phase 2 — Rust alignment
- Status: complete; implementation, tests, and documentation are verified. Phase 2 will be committed and pushed before Phase 3 starts.
- `cargo test --all-targets`: 58 integration tests passed.
- `cargo run --quiet -- demo`: passed; 4 inputs → 3 outputs, replay identical, gas 82/256.
- `cargo build --release`, `cargo fmt --all -- --check`, and `cargo clippy --all-targets --all-features -- -D warnings`: passed.
- Canonical JSON/i64 boundaries, strict range and replay-marker validation, stable error codes, chain depth and deliver scoping, and `Engine::verify` are implemented.

## Phase 3 — Conformance vectors
- Status: not started.

## Phase 4 — SpotSignal
- Status: not started. No Telegram bot token or production database credentials have been found.
- Public deployment: intentionally not attempted; rough-sleeper location data requires a privacy/safety review and explicit deployment authorization.

## Acceptance status
- MOLT v1.1 documentation: complete.
- Rust implementation aligned: complete; all 58 integration tests pass.
- Eight conformance vectors: pending.
- SpotSignal local MVP: pending.

## Next
Commit and push the verified Phase 2 changes, then re-read STATE.md, TASKS.md, and DECISIONS.md before starting Phase 3.
