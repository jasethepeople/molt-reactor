use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use molt_reactor::{
    analyze_reactor, event_digest, Condition, Engine, EngineError, EventSigner, ReactorDef,
    SchemaCheck, VerifiedRange, GENESIS_HASH,
};
use serde_json::{json, Value};

fn definition(
    name: &str,
    trigger: &str,
    rules: Vec<Value>,
    gas: u64,
    depth: u8,
    key: &[&str],
) -> ReactorDef {
    let document = json!({
        "name": name,
        "version": 1,
        "gas_budget": gas,
        "max_trigger_depth": depth,
        "trigger": {"event_type": trigger},
        "state_key": key,
        "rules": rules,
    });
    molt_reactor::parse_reactor(&document.to_string()).unwrap()
}

fn rule(when: Value, event_type: &str, payload: Value) -> Value {
    json!({"when": when, "emit": {"type": event_type, "payload": payload}})
}

fn eq(path: &str, value: Value) -> Value {
    json!({"op":"payload_eq", "path":path, "value":value})
}

fn input_range(items: Vec<(&str, Value)>) -> VerifiedRange {
    let signer = EventSigner::from_seed("test-input", [17; 32]);
    let mut events = Vec::new();
    let mut prev = GENESIS_HASH.to_string();
    for (seq, (event_type, payload)) in items.into_iter().enumerate() {
        let event = signer
            .sign_event(
                seq as u64,
                seq as u64 + 10,
                event_type,
                payload,
                prev.clone(),
            )
            .unwrap();
        prev = event.hash.clone();
        events.push(event);
    }
    let head = events
        .last()
        .map(|event| (event.seq, event.hash.clone()))
        .unwrap_or((0, GENESIS_HASH.to_string()));
    VerifiedRange { events, head }
}

fn run_one(def: ReactorDef, payload: Value) -> (Engine, molt_reactor::RunReport, VerifiedRange) {
    let range = input_range(vec![("input", payload)]);
    let signer = EventSigner::from_seed("reactor-test", [23; 32]);
    let mut engine = Engine::new(Some(signer));
    engine.register_reactor(def).unwrap();
    let report = engine.run(&range).unwrap();
    (engine, report, range)
}

#[test]
fn analyze_rejects_nondeterministic_reactor() {
    for source in [
        include_str!("../demos/nondet-hashmap.json"),
        include_str!("../demos/nondet-float.json"),
        include_str!("../demos/nondet-clock.json"),
    ] {
        let error = analyze_reactor(source).unwrap_err().to_string();
        assert!(
            error.to_lowercase().contains("nondetermin")
                || error.to_lowercase().contains("float")
                || error.to_lowercase().contains("clock"),
            "{error}"
        );
    }
}

#[test]
fn analyze_rejects_unknown_executable_extension() {
    let source = r#"{"name":"x","version":1,"gas_budget":5,"trigger":{"event_type":"x"},"state_key":["/id"],"rules":[],"source":"HashMap::keys()"}"#;
    assert!(analyze_reactor(source).is_err());
}

#[test]
fn valid_reactor_analyzes_as_deterministic() {
    let (def, result) = analyze_reactor(include_str!("../demos/escrow.json")).unwrap();
    assert_eq!(def.name, "escrow");
    assert_eq!(result.version, 1);
    assert_eq!(result.gas_budget, 256);
    assert_eq!(result.rule_count, 3);
}

#[test]
fn unknown_dsl_fields_are_rejected() {
    let source = r#"{"name":"x","version":1,"gas_budget":5,"trigger":{"event_type":"x"},"state_key":["/id"],"rules":[],"seed":42}"#;
    assert!(analyze_reactor(source).is_err());
}

#[test]
fn float_condition_literal_is_rejected_at_registration() {
    let mut def = definition(
        "float",
        "input",
        vec![rule(eq("/x", json!(1)), "out", json!({}))],
        50,
        2,
        &["/id"],
    );
    if let Condition::PayloadEq { value, .. } = &mut def.rules[0].when {
        *value = json!(1.5);
    }
    let mut engine = Engine::new(Some(EventSigner::from_seed("r", [4; 32])));
    assert!(matches!(
        engine.register_reactor(def),
        Err(EngineError::Nondeterministic(_))
    ));
}

#[test]
fn output_order_follows_rule_array_order() {
    let rules = ["first", "second", "third"]
        .into_iter()
        .map(|name| rule(eq("/go", json!(true)), name, json!({"n":name})))
        .collect();
    let def = definition("ordered", "input", rules, 500, 4, &["/id"]);
    let (_, report, _) = run_one(def, json!({"id":"x","go":true}));
    let types: Vec<_> = report
        .new_events
        .iter()
        .map(|event| event.r#type.as_str())
        .collect();
    assert_eq!(types, ["first", "second", "third"]);
}

#[test]
fn payload_equality_matches_and_nonmatches() {
    let def = definition(
        "eq",
        "input",
        vec![rule(eq("/go", json!(true)), "yes", json!({}))],
        100,
        2,
        &["/id"],
    );
    let (_, yes, _) = run_one(def.clone(), json!({"id":"a","go":true}));
    assert_eq!(yes.new_events.len(), 1);
    let (_, no, _) = run_one(def, json!({"id":"b","go":false}));
    assert!(no.new_events.is_empty());
}

#[test]
fn payload_cmp_uses_integer_comparison() {
    let condition = json!({"op":"payload_cmp","path":"/amount","cmp":"gte","value":10});
    let def = definition(
        "cmp",
        "input",
        vec![rule(condition, "large", json!({}))],
        100,
        2,
        &["/id"],
    );
    let (_, report, _) = run_one(def, json!({"id":"a","amount":10}));
    assert_eq!(report.new_events.len(), 1);
}

#[test]
fn and_or_not_conditions_short_circuit_deterministically() {
    let and = json!({"op":"and","conditions":[eq("/go", json!(false)),{"op":"payload_cmp","path":"/missing","cmp":"gt","value":0}]});
    let or = json!({"op":"or","conditions":[eq("/go", json!(true)),{"op":"payload_cmp","path":"/missing","cmp":"gt","value":0}]});
    let not = json!({"op":"not","condition":eq("/blocked", json!(true))});
    let rules = vec![
        rule(and, "and", json!({})),
        rule(or, "or", json!({})),
        rule(not, "not", json!({})),
    ];
    let def = definition("logic", "input", rules, 100, 2, &["/id"]);
    let (_, report, _) = run_one(def, json!({"id":"a","go":true,"blocked":false}));
    let types: Vec<_> = report
        .new_events
        .iter()
        .map(|event| event.r#type.as_str())
        .collect();
    assert_eq!(types, ["or", "not"]);
}

#[test]
fn field_references_and_integer_arithmetic_work() {
    let payload = json!({
        "actor":{"field":"actor"},
        "ts":{"field":"ts"},
        "seq":{"field":"seq"},
        "copy":{"field":"payload:/amount"},
        "sum":{"add":[{"field":"payload:/amount"},2]},
        "difference":{"sub":[100,{"field":"payload:/amount"}]}
    });
    let def = definition(
        "fields",
        "input",
        vec![rule(eq("/go", json!(true)), "out", payload)],
        300,
        2,
        &["/id"],
    );
    let (_, report, _) = run_one(def, json!({"id":"a","go":true,"amount":8}));
    let out = &report.new_events[0];
    assert_eq!(out.payload["actor"], "test-input");
    assert_eq!(out.payload["ts"], 10);
    assert_eq!(out.payload["seq"], 0);
    assert_eq!(out.payload["copy"], 8);
    assert_eq!(out.payload["sum"], 10);
    assert_eq!(out.payload["difference"], 92);
}

#[test]
fn missing_field_reference_fails_without_partial_commit() {
    let def = definition(
        "missing",
        "input",
        vec![rule(
            eq("/go", json!(true)),
            "out",
            json!({"x":{"field":"payload:/absent"}}),
        )],
        100,
        2,
        &["/id"],
    );
    let range = input_range(vec![("input", json!({"id":"a","go":true}))]);
    let mut engine = Engine::new(Some(EventSigner::from_seed("r", [5; 32])));
    engine.register_reactor(def).unwrap();
    assert!(matches!(
        engine.run(&range),
        Err(EngineError::Evaluation(_))
    ));
    assert_eq!(engine.state_snapshot(), json!({}));
    assert!(engine.committed_events().is_empty());
    assert!(engine.ledger_head().is_none());
}

#[test]
fn state_eq_reads_prior_accumulated_payload_state() {
    let condition = json!({"op":"state_eq","path":"/ready","value":true});
    let def = definition(
        "state",
        "input",
        vec![rule(condition, "ready", json!({}))],
        100,
        2,
        &["/id"],
    );
    let (_, report, _) = run_one(def, json!({"id":"a","ready":true}));
    assert_eq!(report.new_events.len(), 1);
}

#[test]
fn state_is_partitioned_by_state_key() {
    let def = definition("partition", "input", vec![], 100, 2, &["/id"]);
    let range = input_range(vec![
        ("input", json!({"id":"a","v":1})),
        ("input", json!({"id":"b","v":2})),
    ]);
    let mut engine = Engine::new(None);
    engine.register_reactor(def).unwrap();
    let report = engine.run(&range).unwrap();
    assert_eq!(report.state["partition"]["[\"a\"]"]["v"], 1);
    assert_eq!(report.state["partition"]["[\"b\"]"]["v"], 2);
}

#[test]
fn state_merging_is_shallow_at_the_top_level() {
    let def = definition("shallow", "input", vec![], 100, 2, &["/id"]);
    let range = input_range(vec![
        ("input", json!({"id":"a","config":{"left":1,"right":2}})),
        ("input", json!({"id":"a","config":{"right":3}})),
    ]);
    let mut engine = Engine::new(None);
    engine.register_reactor(def).unwrap();
    let report = engine.run(&range).unwrap();
    assert_eq!(
        report.state["shallow"]["[\"a\"]"]["config"],
        json!({"right":3})
    );
}

#[test]
fn unmatched_event_emits_nothing() {
    let def = definition(
        "unmatched",
        "other",
        vec![rule(eq("/go", json!(true)), "out", json!({}))],
        100,
        2,
        &["/id"],
    );
    let (_, report, _) = run_one(def, json!({"id":"a","go":true}));
    assert!(report.new_events.is_empty());
}

#[test]
fn replay_same_range_twice_emits_zero_second_time() {
    let def = definition(
        "once",
        "input",
        vec![rule(eq("/go", json!(true)), "out", json!({"ok":true}))],
        100,
        2,
        &["/id"],
    );
    let range = input_range(vec![("input", json!({"id":"a","go":true}))]);
    let mut engine = Engine::new(Some(EventSigner::from_seed("r", [6; 32])));
    engine.register_reactor(def).unwrap();
    let first = engine.run(&range).unwrap();
    let state_after_first = first.state;
    assert_eq!(first.new_events.len(), 1);
    let second = engine.run(&range).unwrap();
    assert!(second.new_events.is_empty());
    assert_eq!(second.state, state_after_first);
    assert!(second.gas_used.is_empty());
}

#[test]
fn replay_complete_output_inclusive_range_reconstructs_state() {
    let def = definition(
        "replay",
        "input",
        vec![rule(eq("/go", json!(true)), "out", json!({"ok":true}))],
        100,
        2,
        &["/id"],
    );
    let range = input_range(vec![("input", json!({"id":"a","go":true,"v":7}))]);
    let mut first_engine = Engine::new(Some(EventSigner::from_seed("r", [7; 32])));
    first_engine.register_reactor(def.clone()).unwrap();
    let first = first_engine.run(&range).unwrap();
    let mut events = range.events.clone();
    events.extend(first.new_events.clone());
    let head = events
        .last()
        .map(|event| (event.seq, event.hash.clone()))
        .unwrap();
    let full = VerifiedRange { events, head };
    let mut replay = Engine::new(Some(EventSigner::from_seed("r", [7; 32])));
    replay.register_reactor(def).unwrap();
    let report = replay.run(&full).unwrap();
    assert!(report.new_events.is_empty());
    assert_eq!(report.state, first_engine.state_snapshot());
}

#[test]
fn replay_rejects_a_recorded_output_that_differs() {
    let def = definition(
        "replay-check",
        "input",
        vec![rule(eq("/go", json!(true)), "out", json!({"ok":true}))],
        100,
        2,
        &["/id"],
    );
    let input = input_range(vec![("input", json!({"id":"a","go":true}))]);
    let signer = EventSigner::from_seed("r", [27; 32]);
    let mut producer = Engine::new(Some(EventSigner::from_seed("r", [27; 32])));
    producer.register_reactor(def.clone()).unwrap();
    let output = producer.run(&input).unwrap().new_events.remove(0);
    let mut events = input.events.clone();
    let mut changed = output;
    changed.payload["ok"] = json!(false);
    events.push(changed);
    let head = events
        .last()
        .map(|event| (event.seq, event.hash.clone()))
        .unwrap();
    let full = VerifiedRange { events, head };
    let mut replay = Engine::new(Some(signer));
    replay.register_reactor(def).unwrap();
    assert!(matches!(
        replay.run(&full),
        Err(EngineError::ReplayMismatch(_))
    ));
    assert_eq!(replay.state_snapshot(), json!({}));
    assert!(replay.committed_events().is_empty());
}

#[test]
fn verify_rejects_orphaned_marker() {
    let def = definition(
        "orphan-check",
        "input",
        vec![rule(eq("/go", json!(true)), "out", json!({"ok":true}))],
        100,
        2,
        &["/id"],
    );
    let input = input_range(vec![("input", json!({"id":"a","go":true}))]);
    let signer = EventSigner::from_seed("r", [32; 32]);
    let mut producer = Engine::new(Some(EventSigner::from_seed("r", [32; 32])));
    producer.register_reactor(def.clone()).unwrap();
    let mut output = producer.run(&input).unwrap().new_events.remove(0);
    output.payload["_molt_reactor"]["trigger_hash"] = json!("f".repeat(64));
    let mut events = input.events.clone();
    events.push(output.clone());
    let full = VerifiedRange {
        events,
        head: (output.seq, output.hash),
    };
    let mut verifier = Engine::new(Some(signer));
    verifier.register_reactor(def).unwrap();
    let error = verifier.verify(&full).unwrap_err();
    assert_eq!(error.code(), "E_MARKER_INVALID");
    assert_eq!(verifier.snapshot_state(), json!({}));
    assert!(verifier.committed_events().is_empty());
}

#[test]
fn verify_missing_outputs_is_atomic() {
    let def = definition(
        "verify-missing",
        "input",
        vec![rule(eq("/go", json!(true)), "out", json!({"ok":true}))],
        100,
        2,
        &["/id"],
    );
    let input = input_range(vec![("input", json!({"id":"a","go":true}))]);
    let mut verifier = Engine::new(Some(EventSigner::from_seed("r", [33; 32])));
    verifier.register_reactor(def).unwrap();
    let error = verifier.verify(&input).unwrap_err();
    assert_eq!(error.code(), "E_REPLAY_MISMATCH");
    assert_eq!(verifier.snapshot_state(), json!({}));
    assert!(verifier.committed_events().is_empty());
    assert!(verifier.ledger_head().is_none());
}

#[test]
fn verify_does_not_trust_in_memory_fired_ids() {
    let def = definition(
        "verify-memory",
        "input",
        vec![rule(eq("/go", json!(true)), "out", json!({"ok":true}))],
        100,
        2,
        &["/id"],
    );
    let input = input_range(vec![("input", json!({"id":"a","go":true}))]);
    let mut engine = Engine::new(Some(EventSigner::from_seed("r", [35; 32])));
    engine.register_reactor(def).unwrap();
    engine.run(&input).unwrap();
    let old_state = engine.snapshot_state();
    let old_events = engine.committed_events().to_vec();
    let error = engine.verify(&input).unwrap_err();
    assert_eq!(error.code(), "E_REPLAY_MISMATCH");
    assert_eq!(engine.snapshot_state(), old_state);
    assert_eq!(engine.committed_events(), old_events.as_slice());
}

#[test]
fn verify_accepts_complete_output_inclusive_range() {
    let def = definition(
        "verify-complete",
        "input",
        vec![rule(eq("/go", json!(true)), "out", json!({"ok":true}))],
        100,
        2,
        &["/id"],
    );
    let input = input_range(vec![("input", json!({"id":"a","go":true}))]);
    let signer = EventSigner::from_seed("r", [34; 32]);
    let mut producer = Engine::new(Some(EventSigner::from_seed("r", [34; 32])));
    producer.register_reactor(def.clone()).unwrap();
    let output = producer.run(&input).unwrap().new_events;
    let mut events = input.events.clone();
    events.extend(output);
    let head = events
        .last()
        .map(|event| (event.seq, event.hash.clone()))
        .unwrap();
    let full = VerifiedRange { events, head };
    let mut verifier = Engine::new(Some(signer));
    verifier.register_reactor(def).unwrap();
    verifier.verify(&full).unwrap();
    assert_eq!(verifier.committed_events().len(), 0);
    assert_eq!(
        verifier.snapshot_state()["verify-complete"]["[\"a\"]"]["go"],
        true
    );
}

#[test]
fn engine_error_codes_are_stable_for_every_variant() {
    let errors = [
        (EngineError::Parse("x".into()), "E_PARSE"),
        (EngineError::InvalidDefinition("x".into()), "E_ANALYZE"),
        (EngineError::Nondeterministic("x".into()), "E_ANALYZE"),
        (EngineError::InvalidRange("x".into()), "E_RANGE_SHAPE"),
        (
            EngineError::Schema {
                event_index: 0,
                reason: "x".into(),
            },
            "E_SCHEMA",
        ),
        (
            EngineError::Policy {
                event_index: 0,
                reason: "x".into(),
            },
            "E_POLICY",
        ),
        (EngineError::MissingSigner, "E_SIGNER_MISSING"),
        (EngineError::Signature { event_index: 0 }, "E_SIG"),
        (
            EngineError::GasExceeded {
                reactor: "r".into(),
                used: 2,
                budget: 1,
            },
            "E_GAS",
        ),
        (
            EngineError::TriggerDepth {
                reactor: "r".into(),
                depth: 2,
                limit: 1,
            },
            "E_DEPTH",
        ),
        (
            EngineError::ConflictError {
                reactor_a: "a".into(),
                reactor_b: "b".into(),
                state_key: "[]".into(),
                field: "x".into(),
            },
            "E_CONFLICT",
        ),
        (
            EngineError::DuplicateEvent {
                seq: 1,
                hash: "a".repeat(64),
            },
            "E_DUP",
        ),
        (EngineError::ReplayMismatch("x".into()), "E_REPLAY_MISMATCH"),
        (
            EngineError::MarkerInvalid {
                event_index: 0,
                reason: "x".into(),
            },
            "E_MARKER_INVALID",
        ),
        (
            EngineError::StateKey {
                reactor: "r".into(),
                pointer: "/id".into(),
            },
            "E_STATE_KEY",
        ),
        (EngineError::Evaluation("x".into()), "E_ANALYZE"),
        (
            EngineError::ArithmeticOverflow {
                op: "+".into(),
                left: "1".into(),
                right: "2".into(),
            },
            "E_OVERFLOW",
        ),
    ];
    for (error, expected) in errors {
        assert_eq!(error.code(), expected);
    }
}

#[test]
fn unrelated_event_cannot_forge_replay_marker() {
    let def = definition(
        "marker-check",
        "input",
        vec![rule(eq("/go", json!(true)), "out", json!({"ok":true}))],
        100,
        2,
        &["/id"],
    );
    let mut range = input_range(vec![("input", json!({"id":"a","go":true}))]);
    let signer = EventSigner::from_seed("r", [28; 32]);
    let trigger_hash = range.events[0].hash.clone();
    let unrelated = signer
        .sign_event(
            1,
            20,
            "noise",
            json!({"_molt_reactor":{"name":"marker-check","version":1,"trigger_hash":trigger_hash,"rule_index":0}}),
            range.head.1.clone(),
        )
        .unwrap();
    range.events.push(unrelated.clone());
    range.head = (unrelated.seq, unrelated.hash);
    let mut engine = Engine::new(Some(signer));
    engine.register_reactor(def).unwrap();
    assert!(matches!(
        engine.run(&range),
        Err(EngineError::MarkerInvalid { .. })
    ));
    assert_eq!(engine.state_snapshot(), json!({}));
}

struct RejectThird;
impl SchemaCheck for RejectThird {
    fn check(&self, event_type: &str, _payload: &Value) -> Result<(), String> {
        if event_type == "out.third" {
            Err("third event schema rejected".into())
        } else {
            Ok(())
        }
    }
}

#[test]
fn atomic_batch_rolls_back_on_invalid_third_event() {
    let rules = ["out.first", "out.second", "out.third"]
        .into_iter()
        .map(|kind| rule(eq("/go", json!(true)), kind, json!({"ok":true})))
        .collect();
    let def = definition("atomic", "input", rules, 500, 3, &["/id"]);
    let range = input_range(vec![(
        "input",
        json!({"id":"a","go":true,"state":"before"}),
    )]);
    let mut engine = Engine::with_checks(
        Some(EventSigner::from_seed("r", [8; 32])),
        Box::new(RejectThird),
        Box::new(molt_reactor::PermissiveCheck),
    );
    engine.register_reactor(def).unwrap();
    let error = engine.run(&range).unwrap_err();
    assert!(error.to_string().contains("third event schema rejected"));
    assert!(matches!(error, EngineError::Schema { event_index: 3, .. }));
    assert_eq!(engine.state_snapshot(), json!({}));
    assert!(engine.committed_events().is_empty());
    assert!(engine.ledger_head().is_none());
}

#[test]
fn missing_signer_rolls_back_entire_batch() {
    let def = definition(
        "no-signer",
        "input",
        vec![rule(eq("/go", json!(true)), "out", json!({}))],
        100,
        2,
        &["/id"],
    );
    let range = input_range(vec![("input", json!({"id":"a","go":true}))]);
    let mut engine = Engine::new(None);
    engine.register_reactor(def).unwrap();
    assert!(matches!(
        engine.run(&range),
        Err(EngineError::MissingSigner)
    ));
    assert_eq!(engine.state_snapshot(), json!({}));
    assert!(engine.committed_events().is_empty());
}

#[test]
fn gas_budget_enforced_precommit() {
    let def = definition(
        "gas",
        "input",
        vec![rule(
            eq("/go", json!(true)),
            "out",
            json!({"long":"payload"}),
        )],
        4,
        2,
        &["/id"],
    );
    let range = input_range(vec![("input", json!({"id":"a","go":true}))]);
    let mut engine = Engine::new(Some(EventSigner::from_seed("r", [9; 32])));
    engine.register_reactor(def).unwrap();
    assert!(matches!(
        engine.run(&range),
        Err(EngineError::GasExceeded { .. })
    ));
    assert_eq!(engine.state_snapshot(), json!({}));
    assert!(engine.committed_events().is_empty());
    assert!(engine.ledger_head().is_none());
}

#[test]
fn self_trigger_cycle_aborted() {
    let output = json!({"id":{"field":"payload:/id"}});
    let def = definition(
        "cycle",
        "loop",
        vec![rule(eq("/id", json!("a")), "loop", output)],
        10_000,
        2,
        &["/id"],
    );
    let range = input_range(vec![("loop", json!({"id":"a"}))]);
    let mut engine = Engine::new(Some(EventSigner::from_seed("r", [10; 32])));
    engine.register_reactor(def).unwrap();
    assert!(matches!(
        engine.run(&range),
        Err(EngineError::TriggerDepth { .. })
    ));
    assert_eq!(engine.state_snapshot(), json!({}));
    assert!(engine.committed_events().is_empty());
}

#[test]
fn conflicting_reactors_aborted_together() {
    let shared_rule = || {
        let mut value = rule(eq("/spend", json!(true)), "debit", json!({"amount":10}));
        value["emit"]["claims"] = json!(["balance"]);
        value
    };
    let first = definition("alpha", "input", vec![shared_rule()], 100, 2, &["/id"]);
    let second = definition("beta", "input", vec![shared_rule()], 100, 2, &["/id"]);
    let range = input_range(vec![("input", json!({"id":"escrow-1","spend":true}))]);
    let mut engine = Engine::new(Some(EventSigner::from_seed("r", [11; 32])));
    engine.register_reactor(first).unwrap();
    engine.register_reactor(second).unwrap();
    let error = engine.run(&range).unwrap_err();
    match error {
        EngineError::ConflictError {
            reactor_a,
            reactor_b,
            ..
        } => {
            assert_eq!(reactor_a, "alpha");
            assert_eq!(reactor_b, "beta");
        }
        other => panic!("expected conflict, got {other}"),
    }
    assert_eq!(engine.state_snapshot(), json!({}));
    assert!(engine.committed_events().is_empty());
}

#[test]
fn same_reactor_can_claim_same_field_across_rules() {
    let rules = vec![
        {
            let mut r = rule(eq("/go", json!(true)), "one", json!({}));
            r["emit"]["claims"] = json!(["balance"]);
            r
        },
        {
            let mut r = rule(eq("/go", json!(true)), "two", json!({}));
            r["emit"]["claims"] = json!(["balance"]);
            r
        },
    ];
    let def = definition("single", "input", rules, 100, 2, &["/id"]);
    let (_, report, _) = run_one(def, json!({"id":"a","go":true}));
    assert_eq!(report.new_events.len(), 2);
}

#[test]
fn float_input_is_rejected_even_when_unused() {
    let def = definition("float-input", "input", vec![], 100, 2, &["/id"]);
    let event = molt_reactor::MoltEvent {
        seq: 0,
        ts: 1,
        r#type: "input".into(),
        payload: json!({"id":"a","unused":1.25}),
        actor: "upstream".into(),
        prev_hash: GENESIS_HASH.into(),
        pub_key: "00".repeat(32),
        sig: "00".repeat(64),
        hash: "ab".repeat(32),
    };
    let range = VerifiedRange {
        events: vec![event.clone()],
        head: (event.seq, event.hash),
    };
    let mut engine = Engine::new(None);
    engine.register_reactor(def).unwrap();
    assert!(matches!(
        engine.run(&range),
        Err(EngineError::Nondeterministic(_))
    ));
    assert_eq!(engine.state_snapshot(), json!({}));
}

#[test]
fn duplicate_sequence_range_is_rejected() {
    let signer = EventSigner::from_seed("a", [12; 32]);
    let first = signer
        .sign_event(0, 1, "x", json!({}), GENESIS_HASH)
        .unwrap();
    let second = signer
        .sign_event(0, 2, "x", json!({}), first.hash.clone())
        .unwrap();
    let range = VerifiedRange {
        head: (0, second.hash.clone()),
        events: vec![first, second],
    };
    let mut engine = Engine::new(None);
    assert!(matches!(
        engine.run(&range),
        Err(EngineError::InvalidRange(_))
    ));
}

#[test]
fn outputs_chain_and_increment_sequences_after_range_head() {
    let def = definition(
        "chain",
        "input",
        vec![rule(eq("/go", json!(true)), "out", json!({}))],
        100,
        2,
        &["/id"],
    );
    let range = input_range(vec![("input", json!({"id":"a","go":true}))]);
    let previous = range.head.1.clone();
    let (_, report, _) = run_one(def, json!({"id":"a","go":true}));
    let output = &report.new_events[0];
    assert_eq!(output.seq, 1);
    assert_eq!(output.prev_hash, previous);
    assert_eq!(output.ts, 10);
}

#[test]
fn chained_outputs_keep_trigger_timestamp_and_hash_ancestry() {
    let first = definition(
        "a-first",
        "input",
        vec![rule(
            eq("/go", json!(true)),
            "middle",
            json!({"id":{"field":"payload:/id"}}),
        )],
        100,
        4,
        &["/id"],
    );
    let second = definition(
        "b-second",
        "middle",
        vec![rule(eq("/id", json!("a")), "final", json!({"done":true}))],
        100,
        4,
        &["/id"],
    );
    let input = input_range(vec![("input", json!({"id":"a","go":true}))]);
    let mut engine = Engine::new(Some(EventSigner::from_seed("reactor-chain", [36; 32])));
    engine.register_reactor(first).unwrap();
    engine.register_reactor(second).unwrap();
    let report = engine.run(&input).unwrap();
    assert_eq!(report.new_events.len(), 2);
    let middle = &report.new_events[0];
    let final_event = &report.new_events[1];
    assert_eq!(middle.r#type, "middle");
    assert_eq!(final_event.r#type, "final");
    assert_eq!((middle.seq, final_event.seq), (1, 2));
    assert_eq!((middle.ts, final_event.ts), (10, 10));
    assert_eq!(middle.prev_hash, input.head.1);
    assert_eq!(final_event.prev_hash, middle.hash);
}

#[test]
fn signed_output_hash_and_ed25519_signature_are_valid() {
    let def = definition(
        "signed",
        "input",
        vec![rule(eq("/go", json!(true)), "out", json!({"ok":true}))],
        100,
        2,
        &["/id"],
    );
    let (_, report, _) = run_one(def, json!({"id":"a","go":true}));
    let event = &report.new_events[0];
    let pub_bytes: [u8; 32] = hex::decode(&event.pub_key).unwrap().try_into().unwrap();
    let key = VerifyingKey::from_bytes(&pub_bytes).unwrap();
    let signature = Signature::from_slice(&hex::decode(&event.sig).unwrap()).unwrap();
    let digest = event_digest(
        event.seq,
        event.ts,
        &event.r#type,
        &event.payload,
        &event.actor,
        &event.prev_hash,
        &event.pub_key,
    )
    .unwrap();
    assert_eq!(hex::encode(digest), event.hash);
    key.verify(&digest, &signature).unwrap();
}

#[test]
fn gas_meter_counts_one_plus_template_payload_bytes() {
    let payload = json!({"x":1});
    let expected = molt_reactor::canonical_json(&payload).unwrap().len() as u64 + 1;
    let def = definition(
        "meter",
        "input",
        vec![rule(eq("/go", json!(true)), "out", payload)],
        expected,
        2,
        &["/id"],
    );
    let (_, report, _) = run_one(def, json!({"id":"a","go":true}));
    assert_eq!(report.gas_used["meter"], expected);
}

#[test]
fn range_head_must_match_last_event() {
    let range = input_range(vec![("input", json!({"id":"a"}))]);
    let wrong = VerifiedRange {
        events: range.events,
        head: (0, "not-the-head".into()),
    };
    let mut engine = Engine::new(None);
    assert!(matches!(
        engine.run(&wrong),
        Err(EngineError::InvalidRange(_))
    ));
}

#[test]
fn state_key_must_exist_for_triggered_event() {
    let def = definition("missing-key", "input", vec![], 100, 2, &["/id"]);
    let range = input_range(vec![("input", json!({"not_id":"a"}))]);
    let mut engine = Engine::new(None);
    engine.register_reactor(def).unwrap();
    assert!(matches!(
        engine.run(&range),
        Err(EngineError::StateKey { .. })
    ));
    assert_eq!(engine.state_snapshot(), json!({}));
}

#[test]
fn deliver_only_fires_for_escrow_action() {
    let def = definition("generic", "other_action", vec![], 100, 2, &["/id"]);
    let range = input_range(vec![("other_action", json!({"id":"a","action":"deliver"}))]);
    let mut engine = Engine::new(Some(EventSigner::from_seed("r", [31; 32])));
    engine.register_reactor(def).unwrap();
    let report = engine.run(&range).unwrap();
    let partition = &report.state["generic"]["[\"a\"]"];
    assert_eq!(partition["action"], "deliver");
    assert!(partition.get("delivered").is_none());
}

#[test]
fn integer_arithmetic_overflow_aborts_atomically() {
    let payload = json!({"n":{"add":[i64::MAX,1]}});
    let def = definition(
        "overflow",
        "input",
        vec![rule(eq("/go", json!(true)), "out", payload)],
        500,
        2,
        &["/id"],
    );
    let range = input_range(vec![("input", json!({"id":"a","go":true}))]);
    let mut engine = Engine::new(Some(EventSigner::from_seed("r", [13; 32])));
    engine.register_reactor(def).unwrap();
    assert!(matches!(
        engine.run(&range),
        Err(EngineError::ArithmeticOverflow { .. })
    ));
    assert_eq!(engine.state_snapshot(), json!({}));
}

#[test]
fn user_payload_cannot_override_reserved_replay_metadata() {
    let source = json!({
        "name":"reserved",
        "version":1,
        "gas_budget":100,
        "trigger":{"event_type":"input"},
        "state_key":["/id"],
        "rules":[rule(eq("/go", json!(true)), "out", json!({"_molt_reactor":{}}))]
    })
    .to_string();
    let error = analyze_reactor(&source).unwrap_err();
    assert_eq!(error.code(), "E_ANALYZE");
    assert!(error.to_string().contains("reserved _molt_reactor"));
}

#[test]
fn event_payload_serialization_is_key_order_stable() {
    let left: Value = serde_json::from_str(r#"{"z":0,"a":1}"#).unwrap();
    let right: Value = serde_json::from_str(r#"{"a":1,"z":0}"#).unwrap();
    assert_eq!(
        serde_json::to_string(&left).unwrap(),
        serde_json::to_string(&right).unwrap()
    );
    assert_eq!(
        event_digest(1, 2, "x", &left, "actor", GENESIS_HASH, "pub").unwrap(),
        event_digest(1, 2, "x", &right, "actor", GENESIS_HASH, "pub").unwrap()
    );
}

#[test]
fn canonical_json_rejects_float_and_out_of_i64_values_with_stable_codes() {
    let float = molt_reactor::canonical_json(&json!(1.5)).unwrap_err();
    assert_eq!(float.code(), "E_ANALYZE");
    let large = json!(i64::MAX as u64 + 1);
    let outside = molt_reactor::canonical_json(&large).unwrap_err();
    assert_eq!(outside.code(), "E_PARSE");
}

#[test]
fn range_parser_requires_array_head_and_rejects_extra_keys() {
    let range = input_range(vec![("input", json!({"id":"a"}))]);
    let json = serde_json::to_string(&range).unwrap();
    assert!(serde_json::from_str::<Value>(&json).unwrap()["head"].is_array());
    let with_extra = json.replacen("{\"events\":", "{\"extra\":true,\"events\":", 1);
    assert_eq!(
        molt_reactor::parse_verified_range(&with_extra)
            .unwrap_err()
            .code(),
        "E_PARSE"
    );
}

#[test]
fn range_payload_decimal_is_analyze_error_but_envelope_decimal_is_parse_error() {
    let range = input_range(vec![("input", json!({"id":"a"}))]);
    let source = serde_json::to_string(&range).unwrap();
    let decimal_payload = source.replace("\"id\":\"a\"", "\"id\":\"a\",\"unused\":1.25");
    assert_eq!(
        molt_reactor::parse_verified_range(&decimal_payload)
            .unwrap_err()
            .code(),
        "E_ANALYZE"
    );
    let decimal_sequence = source.replace("\"seq\":0", "\"seq\":0.0");
    assert_eq!(
        molt_reactor::parse_verified_range(&decimal_sequence)
            .unwrap_err()
            .code(),
        "E_PARSE"
    );
}

#[test]
fn empty_range_requires_genesis_sequence_and_hash() {
    let invalid = r#"{"events":[],"head":[1,"0000000000000000000000000000000000000000000000000000000000000000"]}"#;
    assert_eq!(
        molt_reactor::parse_verified_range(invalid)
            .unwrap_err()
            .code(),
        "E_RANGE_SHAPE"
    );
}

#[test]
fn envelope_u64_is_allowed_but_payload_integers_are_bounded_to_i64() {
    let valid = molt_reactor::MoltEvent {
        seq: u64::MAX,
        ts: u64::MAX,
        r#type: "input".into(),
        payload: json!({"n":i64::MAX}),
        actor: "upstream".into(),
        prev_hash: GENESIS_HASH.into(),
        pub_key: "00".repeat(32),
        sig: "00".repeat(64),
        hash: "ab".repeat(32),
    };
    let valid_range = VerifiedRange {
        events: vec![valid.clone()],
        head: (u64::MAX, valid.hash.clone()),
    };
    assert_eq!(
        molt_reactor::parse_verified_range(&serde_json::to_string(&valid_range).unwrap())
            .unwrap()
            .events[0]
            .seq,
        u64::MAX
    );
    let invalid = molt_reactor::MoltEvent {
        payload: json!({"n":i64::MAX as u64 + 1}),
        ..valid.clone()
    };
    let invalid_range = VerifiedRange {
        events: vec![invalid.clone()],
        head: (u64::MAX, invalid.hash.clone()),
    };
    assert_eq!(
        molt_reactor::parse_verified_range(&serde_json::to_string(&invalid_range).unwrap())
            .unwrap_err()
            .code(),
        "E_PARSE"
    );
}

#[test]
fn reactor_definition_rejects_out_of_i64_integer_with_parse_code() {
    let source = r#"{"name":"too-large","version":1,"gas_budget":9223372036854775808,"trigger":{"event_type":"x"},"state_key":["/id"],"rules":[]}"#;
    assert_eq!(analyze_reactor(source).unwrap_err().code(), "E_PARSE");
}

#[test]
fn integers_beyond_u64_in_payloads_are_parse_errors() {
    let hash = "ab".repeat(32);
    let source = format!(
        r#"{{"events":[{{"seq":0,"ts":1,"type":"x","payload":{{"n":18446744073709551616}},"actor":"a","prev_hash":"{}","pub_key":"","sig":"","hash":"{}"}}],"head":[0,"{}"]}}"#,
        GENESIS_HASH, hash, hash
    );
    assert_eq!(
        molt_reactor::parse_verified_range(&source)
            .unwrap_err()
            .code(),
        "E_PARSE"
    );
}

#[test]
fn canonical_json_pins_utf8_order_escaping_and_negative_zero() {
    let value: Value = serde_json::from_str(r#"{"é":3,"z":2,"a":1}"#).unwrap();
    assert_eq!(
        molt_reactor::canonical_json(&value).unwrap(),
        r#"{"a":1,"z":2,"é":3}"#
    );
    let text = Value::String("\"\\\n\t\0é".into());
    assert_eq!(
        molt_reactor::canonical_json(&text).unwrap(),
        r#""\"\\\u000a\u0009\u0000é""#
    );
    assert_eq!(
        molt_reactor::canonical_json(&serde_json::from_str("-0").unwrap()).unwrap(),
        "0"
    );
    assert_eq!(
        molt_reactor::canonical_json(&json!(1.0))
            .unwrap_err()
            .code(),
        "E_ANALYZE"
    );
}

#[test]
fn decimal_and_exponent_syntax_is_rejected_at_parse_boundaries() {
    for source in [
        r#"{"name":"fraction","version":1,"gas_budget":10,"trigger":{"event_type":"x"},"state_key":["/id"],"rules":[{"when":{"op":"payload_eq","path":"/x","value":-0.0},"emit":{"type":"out","payload":{}}}]}"#,
        r#"{"name":"exponent","version":1,"gas_budget":10,"trigger":{"event_type":"x"},"state_key":["/id"],"rules":[{"when":{"op":"payload_eq","path":"/x","value":1e0},"emit":{"type":"out","payload":{}}}]}"#,
    ] {
        assert_eq!(analyze_reactor(source).unwrap_err().code(), "E_ANALYZE");
    }
}

#[test]
fn out_of_i64_numbers_are_rejected_at_parse_boundaries_but_envelopes_stay_u64() {
    let large = i64::MAX as u64 + 1;
    let event = molt_reactor::MoltEvent {
        seq: u64::MAX,
        ts: u64::MAX,
        r#type: "input".into(),
        payload: json!({"n":large}),
        actor: "upstream".into(),
        prev_hash: GENESIS_HASH.into(),
        pub_key: "00".repeat(32),
        sig: "00".repeat(64),
        hash: "ab".repeat(32),
    };
    let range = VerifiedRange {
        events: vec![event],
        head: (u64::MAX, "ab".repeat(32)),
    };
    let source = serde_json::to_string(&range).unwrap();
    assert_eq!(
        molt_reactor::parse_verified_range(&source)
            .unwrap_err()
            .code(),
        "E_PARSE"
    );
    let reactor = r#"{"name":"wide","version":1,"gas_budget":9223372036854775808,"trigger":{"event_type":"x"},"state_key":["/id"],"rules":[]}"#;
    assert_eq!(analyze_reactor(reactor).unwrap_err().code(), "E_PARSE");
}

#[test]
fn verified_range_requires_array_head_and_exact_keys() {
    let range = input_range(vec![("input", json!({"id":"a"}))]);
    let source = serde_json::to_string(&range).unwrap();
    assert!(source.contains("\"head\":["));
    let extra_key = source.replace("\"head\":", "\"extra\":0,\"head\":");
    assert_eq!(
        molt_reactor::parse_verified_range(&extra_key)
            .unwrap_err()
            .code(),
        "E_PARSE"
    );
    let empty = r#"{"events":[],"head":[1,"0000000000000000000000000000000000000000000000000000000000000000"]}"#;
    assert_eq!(
        molt_reactor::parse_verified_range(empty)
            .unwrap_err()
            .code(),
        "E_RANGE_SHAPE"
    );
}

#[test]
fn default_trigger_depth_is_eight() {
    let source = r#"{"name":"default-depth","version":1,"gas_budget":10,"trigger":{"event_type":"x"},"state_key":["/id"],"rules":[]}"#;
    let (def, analysis) = analyze_reactor(source).unwrap();
    assert_eq!(def.max_trigger_depth, 8);
    assert_eq!(analysis.max_trigger_depth, 8);
}

#[test]
fn multiple_reactors_are_evaluated_by_name_deterministically() {
    let make = |name: &str| {
        definition(
            name,
            "input",
            vec![rule(eq("/go", json!(true)), name, json!({}))],
            100,
            2,
            &["/id"],
        )
    };
    let range = input_range(vec![("input", json!({"id":"a","go":true}))]);
    let mut engine = Engine::new(Some(EventSigner::from_seed("r", [15; 32])));
    engine.register_reactor(make("zeta")).unwrap();
    engine.register_reactor(make("alpha")).unwrap();
    let report = engine.run(&range).unwrap();
    let types: Vec<_> = report
        .new_events
        .iter()
        .map(|event| event.r#type.as_str())
        .collect();
    assert_eq!(types, ["alpha", "zeta"]);
}

#[test]
fn output_metadata_reconstructs_the_deterministic_fired_set() {
    let def = definition(
        "marker",
        "input",
        vec![rule(eq("/go", json!(true)), "out", json!({"ok":true}))],
        100,
        2,
        &["/id"],
    );
    let range = input_range(vec![("input", json!({"id":"a","go":true}))]);
    let mut engine = Engine::new(Some(EventSigner::from_seed("r", [16; 32])));
    engine.register_reactor(def.clone()).unwrap();
    let first = engine.run(&range).unwrap();
    let mut full_events = range.events.clone();
    full_events.extend(first.new_events);
    let head = full_events
        .last()
        .map(|event| (event.seq, event.hash.clone()))
        .unwrap();
    let full_range = VerifiedRange {
        events: full_events,
        head,
    };
    let mut replay = Engine::new(Some(EventSigner::from_seed("r", [16; 32])));
    replay.register_reactor(def).unwrap();
    assert!(replay.run(&full_range).unwrap().new_events.is_empty());
}

#[test]
fn policy_rejection_is_atomic() {
    struct RejectPolicy;
    impl molt_reactor::PolicyCheck for RejectPolicy {
        fn check(&self, event_type: &str, _payload: &Value) -> Result<(), String> {
            if event_type == "forbidden" {
                Err("policy denied".into())
            } else {
                Ok(())
            }
        }
    }
    let def = definition(
        "policy",
        "input",
        vec![rule(eq("/go", json!(true)), "forbidden", json!({}))],
        100,
        2,
        &["/id"],
    );
    let range = input_range(vec![("input", json!({"id":"a","go":true}))]);
    let mut engine = Engine::with_checks(
        Some(EventSigner::from_seed("r", [18; 32])),
        Box::new(molt_reactor::PermissiveCheck),
        Box::new(RejectPolicy),
    );
    engine.register_reactor(def).unwrap();
    assert!(matches!(
        engine.run(&range),
        Err(EngineError::Policy { .. })
    ));
    assert_eq!(engine.state_snapshot(), json!({}));
}

#[test]
fn escrow_contract_emits_three_outputs_and_expected_state() {
    let (def, _) = analyze_reactor(include_str!("../demos/escrow.json")).unwrap();
    let inputs = input_range(vec![
        ("reactor.registered", json!({"name":"escrow","version":1})),
        (
            "escrow_action",
            json!({"escrow_id":"e1","action":"fund","amount":100,"seller":"bob"}),
        ),
        (
            "escrow_action",
            json!({"escrow_id":"e1","action":"deliver"}),
        ),
        (
            "escrow_action",
            json!({"escrow_id":"e1","action":"release"}),
        ),
    ]);
    let mut engine = Engine::new(Some(EventSigner::from_seed("reactor", [19; 32])));
    engine.register_reactor(def).unwrap();
    let report = engine.run(&inputs).unwrap();
    assert_eq!(report.new_events.len(), 3);
    assert_eq!(report.new_events[0].payload["account"], "test-input");
    assert_eq!(report.new_events[0].payload["delta"], -100);
    assert_eq!(report.new_events[1].r#type, "escrow.delivered");
    assert_eq!(report.new_events[2].payload["account"], "bob");
    assert_eq!(report.new_events[2].payload["delta"], 100);
    assert_eq!(report.state["escrow"]["[\"e1\"]"]["delivered"], true);
}
