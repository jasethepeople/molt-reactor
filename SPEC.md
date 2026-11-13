# molt-reactor specification

Version 1.0. This document defines the behavior of the Rust reactor DSL and engine in this crate.

## 1. Purpose and MOLT boundary

A reactor consumes a `VerifiedRange` and derives deterministic events and state. The upstream MOLT layers remain responsible for event authorization, revocation, signatures, causal verification, and canonical ledger acceptance. `molt-reactor` does not re-verify input signatures or recompute input event hashes. It checks that the range's event sequence is contiguous and that `head` equals the final event's `(seq, hash)`; cryptographic and policy trust must come from the upstream verifier.

The interoperable event structure is:

```rust
pub struct MoltEvent {
    pub seq: u64,
    pub ts: u64,
    pub r#type: String,
    pub payload: serde_json::Value,
    pub actor: String,
    pub prev_hash: String,
    pub pub_key: String,
    pub sig: String,
    pub hash: String,
}
```

`GENESIS_HASH` is 64 zeroes. To build an event hash, concatenate `seq.to_be_bytes()`, `ts.to_be_bytes()`, UTF-8 event-type bytes, compact `payload.to_string()` UTF-8 bytes, actor bytes, previous-hash string bytes, and public-key string bytes, in that order; SHA-256 the concatenation. The Ed25519 signature signs the resulting 32 digest bytes. JSON objects are serialized with lexicographically ordered keys by the crate's default `serde_json::Map` configuration. Outputs use the triggering event's timestamp, the configured reactor signer, a sequence immediately following the ledger head, and the head hash as `prev_hash`.

The `VerifiedRange.head` denotes the inclusive last `(seq, hash)`. An empty range uses `(0, GENESIS_HASH)` and its first output has sequence zero. A nonempty range begins output sequence at `head.seq + 1`.

## 2. DSL

A reactor definition is strict JSON: unknown fields are rejected, and no arbitrary code is accepted.

```json
{
  "name": "escrow",
  "version": 1,
  "gas_budget": 256,
  "max_trigger_depth": 4,
  "trigger": { "event_type": "escrow_action" },
  "state_key": ["/escrow_id"],
  "rules": [
    {
      "when": { "op": "payload_eq", "path": "/action", "value": "fund" },
      "emit": {
        "type": "balance.delta",
        "claims": ["balance"],
        "payload": {
          "account": { "field": "actor" },
          "delta": { "sub": [0, { "field": "payload:/amount" }] }
        }
      }
    }
  ]
}
```

Required fields are `name`, `version` (positive integer), `gas_budget` (positive integer), `trigger.event_type`, `state_key` (one or more JSON Pointers), and `rules`. `max_trigger_depth` defaults to 8 and must be positive when specified. Reactor JSON is limited to 1 MiB; condition and expression nesting is limited to 64 levels.

### Conditions

Conditions are tagged objects with these operations:

- `payload_eq`: compare a payload JSON Pointer with a JSON literal.
- `payload_cmp`: compare a payload value as an integer using `eq`, `ne`, `gt`, `gte`, `lt`, or `lte` against an integer `value`. Non-integer or missing payload values do not match.
- `state_eq`: compare accumulated reactor state at a JSON Pointer with a JSON literal.
- `and`: evaluate `conditions` left-to-right and stop at the first false result.
- `or`: evaluate `conditions` left-to-right and stop at the first true result.
- `not`: negate one `condition`.

`and` and `or` require at least one child. Rules are evaluated in their array order; each matching rule emits exactly one event unless its deterministic firing identity has already been recorded.

### State

`state_key` pointer values are collected from each triggering input and compact-JSON-encoded as an ordered array, partitioning state by reactor name and key. For each trigger, object-valued input payload fields merge into that reactor's state (new input fields replace same-named old ones). A scalar payload is stored under `_value`. An `escrow_action` with action `deliver` additionally sets state field `delivered` to `true`. State is updated transactionally and is reconstructible by replaying the trigger inputs in ledger order.

A `state:/pointer` expression reads the current accumulated state after the triggering event has been merged. Missing state-key values are errors; missing condition paths simply do not match.

### Emission templates

An emitted event has a `type`, a `payload` expression, and optional `claims` (unique field names used by conflict detection). Payload expressions support:

- JSON literals, objects, and arrays;
- `{ "field": "actor" }`, `ts`, `seq`, and `type` references;
- `{ "field": "payload:/pointer" }` and `{ "field": "state:/pointer" }` references;
- `{ "add": [left, right] }` and `{ "sub": [left, right] }` with exactly two signed 64-bit integer operands and checked arithmetic.

All JSON numbers in reactor definitions and input payloads must be integers (`u64` or `i64`); floating-point values are rejected. Output templates may not set the reserved `_molt_reactor` key.

For deterministic replay, object keys are sorted by the JSON representation, reactors are invoked by ascending name, rules follow array order, expression object keys are iterated in sorted order, and condition evaluation short-circuits left-to-right. Outputs from one trigger are processed depth-first in emission order before the next ledger event.

## 3. Determinism contract and analysis

The engine executes only this finite DSL interpreter. It has no user-code hooks, loops, recursion, clock, RNG, global mutable state, filesystem, environment, or network access. Evaluation uses ordered `BTreeMap`/`BTreeSet` collections and fixed-order vectors. Integer operations are checked; overflow returns an error. Input floats are rejected even when no rule reads them. Unsupported fields and operators fail closed.

`analyze_reactor` runs before registration and rejects source containing the forbidden nondeterminism markers `HashMap`, `HashSet`, `SystemTime`, `Instant::`, `thread_rng`, `rand::`, `f32`, `f64`, `std::fs`, `std::net`, or `std::env`; it also parses and validates the complete strict DSL and recursively rejects floating-point JSON numbers. This lexical check deliberately errs on the side of rejection. Because arbitrary Rust is not an accepted DSL feature, a forbidden string cannot become executable code; tests demonstrate rejection of the HashMap-order, float, and wall-clock trap fixtures. The CLI reports a clear error rather than executing any reactor source.

The core library is **not `no_std` compatible** in this release. The evaluator currently uses `std` collections, `std::error::Error`, and standard-feature `serde_json`/Ed25519 dependencies. This is an explicit portability tradeoff, not a determinism dependency; a future `no_std` build would need a separate allocation/crypto feature split.

## 4. Gas and trigger depth

For every emitted template payload, gas cost is:

```text
1 + byte_length(compact UTF-8 JSON serialization of the template payload)
```

The one unit charges the output event; each payload byte costs one unit. The count is before adding the reserved replay metadata, and is accumulated per reactor over the entire `run` call. It resets at the next call. `RunReport.gas_used` reports the committed per-reactor total. If the cumulative usage would exceed `gas_budget`, the whole run returns `GasExceeded` without changing reactor state, fired identities, ledger head, or committed outputs.

The DSL has no loops or user functions, so evaluation work is bounded by the validated condition/expression tree and input size; gas specifically meters emitted output and its payload, not input parsing or every interpreter operation. The 1 MiB definition limit and 64-level AST limit bound reactor-definition work. Very large upstream ranges still require upstream resource limits.

The initial range events have trigger depth zero. Every generated output is queued at parent depth plus one. If a reactor would process an event at a depth greater than its own `max_trigger_depth`, the run aborts with `TriggerDepth`. This bounds self-trigger and cross-reactor cycles. The default limit is 8.

## 5. Conflict detection

Each emission may declare `claims`, an array of state fields it intends to mutate. For every output, the engine pairs each claim with that invocation's canonical `state_key` value. After evaluating and validating the full run, but before commit, it checks claims in deterministic output order. If two different reactor names claim the same `(state_key, field)`, the complete run returns `ConflictError`; neither invocation's events nor state are committed. A reactor may claim the same field multiple times itself. Definitions that omit `claims` make no explicit state-field claims and therefore cannot conflict through this mechanism.

## 6. Atomicity, validation, and signing

`run` stages state, fired IDs, output events, and the prospective ledger head in working copies. Every input that matches a trigger passes `SchemaCheck`; every output passes `SchemaCheck` and `PolicyCheck`, then receives a hash and Ed25519 signature. A missing signer, schema/policy failure, arithmetic error, duplicate `(seq, hash)`, gas overrun, trigger-depth overflow, or conflict aborts before commit. All output batches from the run are atomic, which is stronger than per-trigger atomicity. The original engine state, head, and committed-output list are unchanged on error.

`SchemaCheck` and `PolicyCheck` are integration seams; the crate provides `PermissiveCheck` for examples. Production callers should supply checks backed by their MOLT schema/policy layers. Input checks are applied only to events whose type matches a registered trigger; upstream verification remains mandatory.

## 7. Idempotency and replay metadata

A rule firing identity is the tuple `(reactor name, version, trigger event hash, rule index)`. The engine records it in a deterministic ordered set after staging the output. Calling `run` again on the same input range with the same engine therefore emits zero additional events and leaves the derived state unchanged. The identity is also embedded in output payloads under the reserved `_molt_reactor` object, so a fresh engine can reconstruct the fired set when replaying the complete output-inclusive ledger. Replay markers are accepted only when the marker names a registered reactor/version/rule, the event type matches that rule's output type, its trigger hash identifies an earlier matching trigger event in the range, and the output event's actor/public key match the configured signer. During replay, the engine recomputes the rule's output payload at that point in state history and requires an exact type, payload, timestamp, actor, and public-key match; a duplicate, orphaned, or mismatched marker aborts the transaction.

This guarantee has a necessary boundary: an input-only range contains no evidence of outputs committed elsewhere. A fresh process given only the original input range must emit those outputs again. Restart-safe exactly-once replay requires replaying the ledger including the prior reactor output events and configuring the same output signer. `_molt_reactor` is reserved and cannot be supplied in a user output template.

## 8. CLI

- `molt-reactor register --reactor FILE`: validate and register in a short-lived in-memory engine; it does not persist a registry.
- `molt-reactor run --reactor FILE --range RANGE.json --identity IDENTITY.json`: execute and print the run report. Identity JSON is `{ "actor": "...", "seed_hex": "<64 hex chars>" }`; the seed must remain secret.
- `molt-reactor verify --reactor FILE --range OUTPUT_INCLUSIVE_RANGE.json --identity IDENTITY.json`: replay and report missing outputs. It needs the same signer identity to recognize trusted replay markers.
- `molt-reactor analyze --reactor FILE`: statically validate a definition and print `deterministic: yes`, or exit nonzero with a rejection reason.
- `molt-reactor demo`: run the escrow walkthrough, replay it, analyze the definition, and demonstrate schema rejection of a tampered amount.
