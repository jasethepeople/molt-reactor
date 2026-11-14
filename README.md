# molt-reactor

A deterministic, gas-metered Rust engine that turns verified MOLT ledger events into derived events and replayable state. Reactors are strict JSON programs interpreted by a small DSL—there is no arbitrary contract code to execute across nodes.

## Run the escrow demo

Requires a current stable Rust toolchain.

```sh
cargo run -- demo
cargo test
cargo run --release -- analyze --reactor demos/nondet-hashmap.json
```

The demo command exits successfully and ends with a `✅` summary. The last analyze command is expected to exit nonzero: it proves that the deliberately unsafe HashMap reactor is rejected. The companion float and clock traps are `demos/nondet-float.json` and `demos/nondet-clock.json`.

## Write a reactor in under a minute

1. Copy `demos/escrow.json` to `my-reactor.json`.
2. Set a unique `name`, `trigger.event_type`, and one or more `state_key` JSON Pointers.
3. Add ordered `rules`. Each has a `when` condition and one `emit` template. For example, emit a notification when an input has `action: "paid"`:

```json
{
  "name": "payment-notice",
  "version": 1,
  "gas_budget": 128,
  "trigger": { "event_type": "payment_action" },
  "state_key": ["/invoice_id"],
  "rules": [
    {
      "when": { "op": "payload_eq", "path": "/action", "value": "paid" },
      "emit": {
        "type": "invoice.paid",
        "claims": ["status"],
        "payload": {
          "invoice_id": { "field": "payload:/invoice_id" },
          "payer": { "field": "actor" },
          "amount": { "field": "payload:/amount" }
        }
      }
    }
  ]
}
```

4. Check it before registering or running:

```sh
cargo run -- analyze --reactor my-reactor.json
```

The DSL supports `payload_eq`, integer-only `payload_cmp`, `state_eq`, `and`, `or`, `not`, field references, and checked integer `add`/`sub`. Rules emit in array order. Full semantics and examples are in `SPEC.md`.

## CLI

- `cargo run -- register --reactor FILE`: validate and register in memory (no persistent registry).
- `cargo run -- run --reactor FILE --range RANGE.json --identity IDENTITY.json`: run on a JSON `VerifiedRange` and print generated events, state, and gas. Identity JSON is `{ "actor": "...", "seed_hex": "<64 hex chars>" }`; do not commit a private seed.
- `cargo run -- verify --reactor FILE --range OUTPUT_INCLUSIVE_RANGE.json --identity IDENTITY.json`: call `Engine::verify` on an output-inclusive range. It rejects missing outputs without committing anything and requires the original signer identity.
- `cargo run -- analyze --reactor FILE`: validate and print the deterministic analysis result.
- `cargo run -- demo`: run the complete escrow example.

Ranges must already have passed the upstream MOLT verification layers. This crate checks shape and reactor semantics; it does not replace signature, policy, revocation, schema, or consensus verification. `SchemaCheck` and `PolicyCheck` traits are the integration seams, with permissive stubs only for the demo.

## What the trap tests prove

The 58 integration tests include all four requested traps:

1. `analyze_rejects_nondeterministic_reactor` rejects HashMap-derived emission order, float values/arithmetic, and `SystemTime::now()` before execution.
2. `replay_same_range_twice_emits_zero_second_time` proves same-engine idempotency; `replay_complete_output_inclusive_range_reconstructs_state` proves restart replay when prior outputs are in the range.
3. `atomic_batch_rolls_back_on_invalid_third_event` proves a bad third output commits neither the first two events nor reactor state/head. Missing-signer and policy failures are also atomic; replay tests also reject forged or mismatched recorded outputs.
4. `gas_budget_enforced_precommit` and `self_trigger_cycle_aborted` prove gas and depth bounds; `conflicting_reactors_aborted_together` proves competing field claims abort together.

Output events retain the standard MOLT event structure. A reserved `_molt_reactor` payload member carries firing identity so a fresh engine can reconstruct the already-fired set from the complete output-inclusive ledger. An input-only range has no evidence of outputs committed elsewhere; see the exact idempotency boundary in `SPEC.md`.

`canonical_json` exposes the pinned MOLT payload serializer; `parse_verified_range` enforces the array-form head, strict range shape, and i64 payload-number bound. See `SPEC.md` Version 1.1 for byte-level canonical JSON, stable error codes, and replay semantics.

The eight v1.1 JSON conformance vectors and their update policy are documented in [docs/CONFORMANCE.md](docs/CONFORMANCE.md).

Dedicated to Aaron Swartz and to a best friend lost in 2025.
