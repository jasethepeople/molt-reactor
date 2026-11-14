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
- [x] Add regression tests; `cargo test --all-targets` passes 58 integration tests; demo, release build, formatting, and strict Clippy pass.

## Phase 3 — Conformance vectors
- [x] Add eight versioned JSON vectors covering emit, gas, conflict, depth, replay, deliver scoping, orphan marker, and out-of-i64.
- [x] Add `tests/conformance.rs` and `docs/CONFORMANCE.md`; run the conformance target and commit.

## Phase 4 — SpotSignal local MVP
- [ ] Build the API, database migrations, bot, PWA, and deployment docs with privacy safeguards.
- [ ] Run available tests and local stack checks; record any infrastructure/token blockers.
- [ ] Do not publicly deploy location-bearing reports without an explicit privacy/safety review.
