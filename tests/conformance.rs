use molt_reactor::{parse_reactor, parse_verified_range, Engine, EventSigner};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
const VECTOR_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/v1.1");
const VECTOR_IDS: [&str; 8] = [
    "emit-basic",
    "gas-budget",
    "conflict",
    "trigger-depth",
    "replay",
    "deliver-scope",
    "orphan-marker",
    "out-of-i64",
];

fn run_vector(vector: &Value) -> Value {
    let operation = vector["operation"].as_str().expect("operation string");
    let range_source = serde_json::to_string(&vector["range"]).expect("range serialization");
    if operation == "parse_range" {
        return match parse_verified_range(&range_source) {
            Ok(_) => json!({"error_code": null}),
            Err(error) => json!({"error_code": error.code()}),
        };
    }

    let range = parse_verified_range(&range_source).expect("valid vector range");
    let definitions = vector["reactors"]
        .as_array()
        .expect("reactor list")
        .iter()
        .map(|definition| {
            parse_reactor(&serde_json::to_string(definition).expect("reactor serialization"))
                .expect("valid vector reactor")
        })
        .collect::<Vec<_>>();
    let signer = &vector["signer"];
    let seed_hex = signer["seed_hex"].as_str().expect("signer seed");
    let seed: [u8; 32] = hex::decode(seed_hex)
        .expect("hex signer seed")
        .try_into()
        .expect("32-byte signer seed");
    let actor = signer["actor"].as_str().expect("signer actor");
    let mut engine = Engine::new(Some(EventSigner::from_seed(actor, seed)));
    for definition in definitions {
        engine
            .register_reactor(definition)
            .expect("register vector reactor");
    }

    match operation {
        "run" => match engine.run(&range) {
            Ok(report) => json!({
                "error_code": null,
                "new_events": report.new_events,
                "gas_used": report.gas_used,
                "state": report.state
            }),
            Err(error) => json!({
                "error_code": error.code(),
                "new_events": [],
                "gas_used": {},
                "state": engine.snapshot_state()
            }),
        },
        "verify" => match engine.verify(&range) {
            Ok(()) => json!({
                "error_code": null,
                "new_events": [],
                "gas_used": {},
                "state": engine.snapshot_state()
            }),
            Err(error) => json!({
                "error_code": error.code(),
                "new_events": [],
                "gas_used": {},
                "state": engine.snapshot_state()
            }),
        },
        other => panic!("unsupported vector operation: {other}"),
    }
}

#[test]
fn all_v1_1_vectors_match_exact_expected_outputs() {
    let directory = fs::read_dir(VECTOR_DIR).expect("conformance vector directory");
    let mut found = BTreeSet::new();
    for entry in directory {
        let path = entry.expect("vector directory entry").path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let source = fs::read_to_string(&path).expect("vector file");
        let vector: Value = serde_json::from_str(&source).expect("valid vector JSON");
        let id = vector["id"].as_str().expect("vector id");
        assert!(found.insert(id.to_owned()), "duplicate vector id: {id}");
        assert_eq!(vector["vector_version"], 1, "{id}");
        assert_eq!(vector["spec_version"], "1.1", "{id}");
        assert_eq!(
            run_vector(&vector),
            vector["expected"],
            "conformance mismatch in {id}"
        );
    }
    let expected = VECTOR_IDS
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert_eq!(found, expected, "the v1.1 vector set must be exact");
}
