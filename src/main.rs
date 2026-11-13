use molt_reactor::{
    analyze_reactor, Engine, EventSigner, MoltEvent, PermissiveCheck, ReactorDef, SchemaCheck,
    VerifiedRange, GENESIS_HASH,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::process::ExitCode;

#[derive(Deserialize)]
struct IdentityFile {
    actor: String,
    seed_hex: String,
}

struct EscrowSchema;

impl SchemaCheck for EscrowSchema {
    fn check(&self, event_type: &str, payload: &Value) -> Result<(), String> {
        match event_type {
            "escrow_action" => {
                if payload.get("escrow_id").and_then(Value::as_str).is_none() {
                    return Err("escrow_action.escrow_id must be a string".into());
                }
                let action = payload
                    .get("action")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "escrow_action.action must be a string".to_owned())?;
                match action {
                    "fund" => {
                        if payload.get("amount").and_then(as_integer).is_none() {
                            return Err("fund amount must be an integer".into());
                        }
                        if payload.get("seller").and_then(Value::as_str).is_none() {
                            return Err("fund seller must be a string".into());
                        }
                    }
                    "deliver" | "release" => (),
                    _ => return Err(format!("unsupported escrow action {action}")),
                }
                Ok(())
            }
            "balance.delta" => {
                if payload.get("account").and_then(Value::as_str).is_none()
                    || payload.get("delta").and_then(as_integer).is_none()
                {
                    return Err("balance.delta requires string account and integer delta".into());
                }
                Ok(())
            }
            "escrow.delivered" => {
                if payload.get("escrow_id").and_then(Value::as_str).is_none() {
                    return Err("escrow.delivered.escrow_id must be a string".into());
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

fn as_integer(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|n| i64::try_from(n).ok()))
}

fn main() -> ExitCode {
    match run_cli(env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("molt-reactor: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run_cli(args: Vec<String>) -> Result<(), String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Err(usage().into());
    };
    match command {
        "analyze" => {
            let path = option(&args[1..], "--reactor")
                .or_else(|| args.get(1).map(String::as_str))
                .ok_or_else(|| "analyze requires --reactor <path>".to_owned())?;
            let source =
                fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
            let (_, analysis) = analyze_reactor(&source).map_err(|e| e.to_string())?;
            println!("deterministic: yes");
            println!("reactor: {}@{}", analysis.name, analysis.version);
            println!(
                "rules: {}, gas budget: {}, max trigger depth: {}",
                analysis.rule_count, analysis.gas_budget, analysis.max_trigger_depth
            );
            Ok(())
        }
        "register" => {
            let path = option(&args[1..], "--reactor")
                .ok_or_else(|| "register requires --reactor <path>".to_owned())?;
            let (def, analysis) = load_reactor(path)?;
            let mut engine = Engine::new(None);
            engine.register_reactor(def).map_err(|e| e.to_string())?;
            println!(
                "registered {}@{}; deterministic: yes; gas budget: {}",
                analysis.name, analysis.version, analysis.gas_budget
            );
            Ok(())
        }
        "run" => {
            let reactor_path = option(&args[1..], "--reactor")
                .ok_or_else(|| "run requires --reactor <path>".to_owned())?;
            let range_path = option(&args[1..], "--range")
                .ok_or_else(|| "run requires --range <path>".to_owned())?;
            let identity_path = option(&args[1..], "--identity")
                .ok_or_else(|| "run requires --identity <path>".to_owned())?;
            let (def, _) = load_reactor(reactor_path)?;
            let range = load_range(range_path)?;
            let signer = load_signer(identity_path)?;
            let mut engine = Engine::new(Some(signer));
            engine.register_reactor(def).map_err(|e| e.to_string())?;
            let report = engine.run(&range).map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        "verify" => {
            let reactor_path = option(&args[1..], "--reactor")
                .ok_or_else(|| "verify requires --reactor <path>".to_owned())?;
            let range_path = option(&args[1..], "--range")
                .ok_or_else(|| "verify requires --range <path>".to_owned())?;
            let identity_path = option(&args[1..], "--identity").ok_or_else(|| {
                "verify requires --identity <identity.json> for replay markers".to_owned()
            })?;
            let (def, _) = load_reactor(reactor_path)?;
            let range = load_range(range_path)?;
            let signer = load_signer(identity_path)?;
            let mut engine = Engine::new(Some(signer));
            engine.register_reactor(def).map_err(|e| e.to_string())?;
            let report = engine.run(&range).map_err(|e| e.to_string())?;
            if !report.new_events.is_empty() {
                return Err(format!(
                    "range is missing {} recorded reactor output(s)",
                    report.new_events.len()
                ));
            }
            println!(
                "verified: deterministic replay; {} input events; no missing outputs",
                range.events.len()
            );
            Ok(())
        }
        "demo" => demo(),
        "help" | "--help" | "-h" => {
            println!("{}", usage());
            Ok(())
        }
        _ => Err(usage().into()),
    }
}

fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
}

fn load_reactor(path: &str) -> Result<(ReactorDef, molt_reactor::Analysis), String> {
    let source = fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    analyze_reactor(&source).map_err(|e| e.to_string())
}

fn load_range(path: &str) -> Result<VerifiedRange, String> {
    let source = fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    serde_json::from_str(&source).map_err(|e| format!("invalid range JSON: {e}"))
}

fn load_signer(path: &str) -> Result<EventSigner, String> {
    let source =
        fs::read_to_string(path).map_err(|e| format!("cannot read identity {path}: {e}"))?;
    let identity: IdentityFile =
        serde_json::from_str(&source).map_err(|e| format!("invalid identity JSON: {e}"))?;
    let bytes =
        hex::decode(&identity.seed_hex).map_err(|e| format!("seed_hex is not valid hex: {e}"))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "seed_hex must encode exactly 32 bytes".to_owned())?;
    Ok(EventSigner::from_seed(identity.actor, seed))
}

fn demo() -> Result<(), String> {
    let reactor_source = include_str!("../demos/escrow.json");
    let (reactor, analysis) = analyze_reactor(reactor_source).map_err(|e| e.to_string())?;
    println!(
        "1. Register escrow reactor {}@{}",
        reactor.name, reactor.version
    );

    let admin = EventSigner::from_seed("reactor-registry", [9; 32]);
    let alice = EventSigner::from_seed("alice", [1; 32]);
    let bob = EventSigner::from_seed("bob", [2; 32]);
    let output_signer = EventSigner::from_seed("molt-reactor:escrow", [3; 32]);
    let mut inputs = Vec::<MoltEvent>::new();
    inputs.push(
        admin
            .sign_event(
                0,
                1,
                "reactor.registered",
                json!({"name":"escrow","version":1}),
                GENESIS_HASH,
            )
            .map_err(|e| e.to_string())?,
    );
    let fund = alice
        .sign_event(
            1,
            2,
            "escrow_action",
            json!({"escrow_id":"e1","action":"fund","amount":100,"seller":"bob"}),
            inputs.last().unwrap().hash.clone(),
        )
        .map_err(|e| e.to_string())?;
    inputs.push(fund);
    let delivered = bob
        .sign_event(
            2,
            3,
            "escrow_action",
            json!({"escrow_id":"e1","action":"deliver"}),
            inputs.last().unwrap().hash.clone(),
        )
        .map_err(|e| e.to_string())?;
    inputs.push(delivered);
    let released = alice
        .sign_event(
            3,
            4,
            "escrow_action",
            json!({"escrow_id":"e1","action":"release"}),
            inputs.last().unwrap().hash.clone(),
        )
        .map_err(|e| e.to_string())?;
    inputs.push(released);
    println!("2. Alice funds escrow e1 with 100 for Bob");
    println!("3. Bob marks escrow e1 delivered");
    println!("4. Alice releases escrow e1");

    let head = inputs
        .last()
        .map(|event| (event.seq, event.hash.clone()))
        .ok_or("demo input range unexpectedly empty")?;
    let range = VerifiedRange {
        events: inputs.clone(),
        head,
    };
    let mut engine = Engine::with_checks(
        Some(output_signer),
        Box::new(EscrowSchema),
        Box::new(PermissiveCheck),
    );
    engine
        .register_reactor(reactor.clone())
        .map_err(|e| e.to_string())?;
    let report = engine.run(&range).map_err(|e| e.to_string())?;
    if report.new_events.len() != 3 {
        return Err(format!(
            "expected 3 outputs, got {}",
            report.new_events.len()
        ));
    }

    let mut balances = BTreeMap::<String, i64>::new();
    for event in &report.new_events {
        if event.r#type == "balance.delta" {
            let account = event
                .payload
                .get("account")
                .and_then(Value::as_str)
                .ok_or("balance output is missing account")?;
            let delta = event
                .payload
                .get("delta")
                .and_then(as_integer)
                .ok_or("balance output is missing integer delta")?;
            let balance = balances.entry(account.to_owned()).or_insert(0);
            *balance = balance.checked_add(delta).ok_or("demo balance overflow")?;
        }
        println!(
            "   → {} {}",
            event.r#type,
            serde_json::to_string(&event.payload).map_err(|e| e.to_string())?
        );
    }
    println!(
        "5. Derived balances: alice {:+}, bob {:+}",
        balances.get("alice").copied().unwrap_or(0),
        balances.get("bob").copied().unwrap_or(0)
    );
    if balances.get("alice") != Some(&-100) || balances.get("bob") != Some(&100) {
        return Err("escrow balance deltas do not match the expected final state".into());
    }
    let escrow_state = engine
        .state_for("escrow", &[json!("e1")])
        .ok_or("escrow state was not derived")?;
    if escrow_state.get("delivered") != Some(&Value::Bool(true))
        || escrow_state.get("seller").and_then(Value::as_str) != Some("bob")
    {
        return Err("escrow final state did not preserve seller and delivery".into());
    }
    println!(
        "   State: delivered={}, seller={}, amount={}",
        escrow_state["delivered"], escrow_state["seller"], escrow_state["amount"]
    );

    let mut replay_events = inputs.clone();
    replay_events.extend(report.new_events.clone());
    let replay_head = replay_events
        .last()
        .map(|event| (event.seq, event.hash.clone()))
        .ok_or("replay range unexpectedly empty")?;
    let replay_range = VerifiedRange {
        events: replay_events,
        head: replay_head,
    };
    let replay_signer = EventSigner::from_seed("molt-reactor:escrow", [3; 32]);
    let mut replay_engine = Engine::with_checks(
        Some(replay_signer),
        Box::new(EscrowSchema),
        Box::new(PermissiveCheck),
    );
    replay_engine
        .register_reactor(reactor.clone())
        .map_err(|e| e.to_string())?;
    let replay_report = replay_engine
        .run(&replay_range)
        .map_err(|e| e.to_string())?;
    if !replay_report.new_events.is_empty() || replay_report.state != engine.state_snapshot() {
        return Err("replay did not reproduce the same state with zero new output events".into());
    }
    println!(
        "6–7. Replay from genesis: identical state, {} new events",
        replay_report.new_events.len()
    );

    let (_, checked_analysis) = analyze_reactor(reactor_source).map_err(|e| e.to_string())?;
    if checked_analysis != analysis {
        return Err("analyzer returned inconsistent results".into());
    }
    println!("8. Reactor analysis: deterministic: yes");

    let mut tampered_events = inputs.clone();
    tampered_events[1].payload["amount"] = json!("one hundred");
    let tampered_head = tampered_events
        .last()
        .map(|event| (event.seq, event.hash.clone()))
        .ok_or("tampered range unexpectedly empty")?;
    let tampered_range = VerifiedRange {
        events: tampered_events,
        head: tampered_head,
    };
    let mut tamper_engine = Engine::with_checks(
        Some(EventSigner::from_seed("molt-reactor:escrow", [3; 32])),
        Box::new(EscrowSchema),
        Box::new(PermissiveCheck),
    );
    tamper_engine
        .register_reactor(reactor)
        .map_err(|e| e.to_string())?;
    match tamper_engine.run(&tampered_range) {
        Err(error) if error.to_string().contains("fund amount must be an integer") => {
            println!("9. Tampered input rejected by schema validation: {error}")
        }
        Err(error) => {
            return Err(format!(
                "tampered input failed for an unexpected reason: {error}"
            ))
        }
        Ok(_) => return Err("tampered fund amount was not rejected".into()),
    }

    let gas_used: u64 = report.gas_used.values().copied().sum();
    println!("✅ escrow contract: {} inputs → {} outputs, replay-identical, deterministic, gas={gas_used}/{}", inputs.len(), report.new_events.len(), analysis.gas_budget);
    Ok(())
}

fn usage() -> &'static str {
    "Usage:\n  molt-reactor register --reactor <file.json>\n  molt-reactor run --reactor <file.json> --range <verified-range.json> --identity <identity.json>\n  molt-reactor verify --reactor <file.json> --range <output-inclusive-range.json> --identity <identity.json>\n  molt-reactor analyze --reactor <file.json>\n  molt-reactor demo"
}
