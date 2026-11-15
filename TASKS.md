# Tasks

## Phase 1 — SPEC.md v1.1
- [x] Correct the VerifiedRange JSON-array schema/example and pin canonical JSON.
- [x] Specify the exact replay marker, chain-depth semantics, stable error taxonomy, and semantic pins.
- [x] Review spec claims against the current implementation; carry implementation gaps into Phase 2.
- [x] Run baseline tests and demo; commit the documentation phase.

## Phase 2 — Rust alignment
- [x] Gate the `deliver` state exception to `escrow_action`; add its regression test.
- [x] Add current depth and both conflicting reactor names to structured errors.
- [x] Enforce i64-only payload/definition numbers and implement canonical JSON bytes.
- [x] Validate strict VerifiedRange shape and exact replay metadata; add `Engine::verify`.
- [x] Add regression tests; 58 Rust integration tests, demo, release build, formatting, and strict Clippy pass.

## Phase 3 — Conformance vectors
- [x] Add eight versioned JSON vectors covering emit, gas, conflict, depth, replay, deliver scoping, orphan marker, and out-of-i64.
- [x] Add `tests/conformance.rs` and `docs/CONFORMANCE.md`; all vectors match expected output/error behavior.

## Phase 4 — SpotSignal local MVP
- [x] Build the API, PostGIS migration and least-privilege bootstrap, optional Telegram bot, PWA, and privacy/deployment docs.
- [x] Run 17 app tests with PostGIS; clean npm install; syntax checks; zero production dependency advisories; browser/API and DB-storage smoke checks.
- [x] Parse/inspect Compose configuration; record Docker/Compose absence and missing Telegram token in `spot-signal/docs/FINAL_REPORT.md`.
- [x] Keep the default local-only and activity reports off; no real data or public deployment.
- [x] Confirm the latest public `main` contains Phase 4 and run the available Rust and Node test suites.
- [x] Refresh the documented acceptance chain and prepare the workspace ZIP; no public service was deployed.
