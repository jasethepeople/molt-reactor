# MOLT Reactor v1.1 conformance vectors

The versioned fixtures in `conformance/v1.1/` pin the public behavior of SPEC v1.1. Each JSON file has `vector_version: 1`, `spec_version: "1.1"`, an `id`, an `operation`, the reactor definitions and/or `VerifiedRange`, a fixed test signer where needed, and exact expected output. Test signer seeds are deterministic fixtures only; never reuse them for real ledger events.

Run the vectors with:

```sh
cargo test --test conformance
```

The integration test loads every JSON fixture, checks the version fields, rejects duplicate/missing vector IDs, executes the requested operation, and compares the complete result. Successful `run` vectors pin emitted event fields (including hash and Ed25519 signature), state, and gas. Failure vectors pin stable `EngineError::code()` values and transactional results; human-readable error messages are intentionally not part of the cross-version contract.

## Vector inventory

| ID | Behavior pinned | Expected result |
| --- | --- | --- |
| `emit-basic` | Canonical event hash/signature, output metadata, state, and gas | One deterministic signed event |
| `gas-budget` | Gas is charged before transaction commit | `E_GAS`, no state or event commit |
| `conflict` | Two reactors claiming the same state-key field conflict atomically | `E_CONFLICT`, no state or event commit |
| `trigger-depth` | Self-trigger chains stop at the configured maximum depth | `E_DEPTH`, no state or event commit |
| `replay` | A complete output-inclusive range reconstructs state without new events | Verification succeeds, zero new output |
| `deliver-scope` | `action: "deliver"` on a non-`escrow_action` trigger does not set `delivered` | State contains no compatibility-only field |
| `orphan-marker` | A replay marker without an earlier matching trigger is rejected | `E_MARKER_INVALID` |
| `out-of-i64` | Payload integers outside signed 64-bit range are rejected at parse time | `E_PARSE` |

## Updating vectors

A behavior change requires an explicit SPEC version decision and review of all affected vectors. Keep IDs stable when the behavior is unchanged; add a new `vector_version` directory for an incompatible vector-schema revision. Never regenerate expected signatures silently: changes to canonical JSON, hash input ordering, signer identity, or event envelope fields require a documented protocol change.
