use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_REACTOR_BYTES: usize = 1_048_576;
const MAX_AST_DEPTH: usize = 64;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MoltEvent {
    pub seq: u64,
    pub ts: u64,
    #[serde(rename = "type")]
    pub r#type: String,
    pub payload: Value,
    pub actor: String,
    pub prev_hash: String,
    pub pub_key: String,
    pub sig: String,
    pub hash: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerifiedRange {
    pub events: Vec<MoltEvent>,
    pub head: (u64, String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactorError(pub String);

impl fmt::Display for ReactorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ReactorError {}

pub type ReactorResult<T> = Result<T, ReactorError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineError {
    InvalidDefinition(String),
    Nondeterministic(String),
    InvalidRange(String),
    Schema(String),
    Policy(String),
    MissingSigner,
    GasExceeded {
        reactor: String,
        used: u64,
        budget: u64,
    },
    TriggerDepth {
        reactor: String,
        limit: u8,
    },
    ConflictError {
        state_key: String,
        field: String,
    },
    DuplicateEvent {
        seq: u64,
        hash: String,
    },
    ReplayMismatch(String),
    Evaluation(String),
    ArithmeticOverflow,
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDefinition(message) => write!(f, "invalid reactor: {message}"),
            Self::Nondeterministic(message) => write!(f, "nondeterministic reactor: {message}"),
            Self::InvalidRange(message) => write!(f, "invalid verified range: {message}"),
            Self::Schema(message) => write!(f, "schema validation failed: {message}"),
            Self::Policy(message) => write!(f, "policy validation failed: {message}"),
            Self::MissingSigner => {
                f.write_str("reactor emitted events but no signer is configured")
            }
            Self::GasExceeded {
                reactor,
                used,
                budget,
            } => write!(f, "gas budget exceeded for {reactor}: {used}/{budget}"),
            Self::TriggerDepth { reactor, limit } => {
                write!(f, "trigger depth exceeded for {reactor} (max {limit})")
            }
            Self::ConflictError { state_key, field } => write!(
                f,
                "conflicting reactor claims for state key {state_key}, field {field}"
            ),
            Self::DuplicateEvent { seq, hash } => {
                write!(f, "duplicate output event ({seq}, {hash})")
            }
            Self::ReplayMismatch(message) => write!(f, "reactor replay mismatch: {message}"),
            Self::Evaluation(message) => write!(f, "reactor evaluation failed: {message}"),
            Self::ArithmeticOverflow => f.write_str("checked integer arithmetic overflow"),
        }
    }
}

impl std::error::Error for EngineError {}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReactorDef {
    pub name: String,
    pub version: u32,
    pub gas_budget: u64,
    #[serde(default = "default_trigger_depth")]
    pub max_trigger_depth: u8,
    pub trigger: TriggerDef,
    pub state_key: Vec<String>,
    pub rules: Vec<RuleDef>,
}

fn default_trigger_depth() -> u8 {
    8
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerDef {
    pub event_type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleDef {
    pub when: Condition,
    pub emit: EmitTemplate,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmitTemplate {
    #[serde(rename = "type")]
    pub event_type: String,
    pub payload: ValueExpr,
    #[serde(default)]
    pub claims: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    PayloadEq {
        path: String,
        value: Value,
    },
    PayloadCmp {
        path: String,
        cmp: CompareOp,
        value: i64,
    },
    StateEq {
        path: String,
        value: Value,
    },
    And {
        conditions: Vec<Condition>,
    },
    Or {
        conditions: Vec<Condition>,
    },
    Not {
        condition: Box<Condition>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompareOp {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ValueExpr {
    Field(FieldExpr),
    Add(AddExpr),
    Sub(SubExpr),
    Object(BTreeMap<String, ValueExpr>),
    Array(Vec<ValueExpr>),
    Literal(Value),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FieldExpr {
    pub field: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AddExpr {
    pub add: Vec<ValueExpr>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubExpr {
    pub sub: Vec<ValueExpr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Analysis {
    pub name: String,
    pub version: u32,
    pub rule_count: usize,
    pub gas_budget: u64,
    pub max_trigger_depth: u8,
}

pub fn analyze_reactor(source: &str) -> ReactorResult<(ReactorDef, Analysis)> {
    if source.len() > MAX_REACTOR_BYTES {
        return Err(ReactorError(
            "reactor JSON exceeds the 1 MiB analysis limit".into(),
        ));
    }
    reject_forbidden_source(source)?;
    let raw: Value =
        serde_json::from_str(source).map_err(|e| ReactorError(format!("invalid JSON: {e}")))?;
    reject_float_values(&raw)?;
    let def: ReactorDef = serde_json::from_value(raw)
        .map_err(|e| ReactorError(format!("invalid reactor DSL: {e}")))?;
    validate_definition(&def).map_err(|e| ReactorError(e.to_string()))?;
    let analysis = Analysis {
        name: def.name.clone(),
        version: def.version,
        rule_count: def.rules.len(),
        gas_budget: def.gas_budget,
        max_trigger_depth: def.max_trigger_depth,
    };
    Ok((def, analysis))
}

pub fn parse_reactor(source: &str) -> ReactorResult<ReactorDef> {
    analyze_reactor(source).map(|(def, _)| def)
}

fn reject_forbidden_source(source: &str) -> ReactorResult<()> {
    let lower = source.to_ascii_lowercase();
    let forbidden = [
        ("hashmap", "HashMap iteration/order is nondeterministic"),
        ("hashset", "HashSet iteration/order is nondeterministic"),
        ("systemtime", "wall-clock access is forbidden"),
        ("instant::", "monotonic-clock access is forbidden"),
        ("thread_rng", "random-number generation is forbidden"),
        ("rand::", "random-number generation is forbidden"),
        ("f32", "floating-point values are forbidden"),
        ("f64", "floating-point values are forbidden"),
        ("std::fs", "filesystem access is forbidden"),
        ("std::net", "network access is forbidden"),
        ("std::env", "environment access is forbidden"),
    ];
    for (needle, reason) in forbidden {
        if lower.contains(needle) {
            return Err(ReactorError(format!("{reason} (found {needle})")));
        }
    }
    Ok(())
}

fn reject_float_values(value: &Value) -> ReactorResult<()> {
    match value {
        Value::Number(number) if number.as_i64().is_none() && number.as_u64().is_none() => Err(
            ReactorError("floating-point JSON numbers are forbidden".into()),
        ),
        Value::Array(items) => items.iter().try_for_each(reject_float_values),
        Value::Object(items) => items.values().try_for_each(reject_float_values),
        _ => Ok(()),
    }
}

fn validate_definition(def: &ReactorDef) -> Result<(), EngineError> {
    if def.name.trim().is_empty() || def.name.len() > 128 {
        return Err(EngineError::InvalidDefinition(
            "name must contain 1..=128 non-whitespace bytes".into(),
        ));
    }
    if def.version == 0 {
        return Err(EngineError::InvalidDefinition(
            "version must be at least 1".into(),
        ));
    }
    if def.gas_budget == 0 {
        return Err(EngineError::InvalidDefinition(
            "gas_budget must be greater than zero".into(),
        ));
    }
    if def.max_trigger_depth == 0 {
        return Err(EngineError::InvalidDefinition(
            "max_trigger_depth must be at least 1".into(),
        ));
    }
    if def.trigger.event_type.is_empty() {
        return Err(EngineError::InvalidDefinition(
            "trigger.event_type cannot be empty".into(),
        ));
    }
    if def.state_key.is_empty() {
        return Err(EngineError::InvalidDefinition(
            "state_key must have at least one JSON Pointer".into(),
        ));
    }
    for path in &def.state_key {
        if !valid_pointer(path) {
            return Err(EngineError::InvalidDefinition(format!(
                "invalid state_key JSON Pointer: {path}"
            )));
        }
    }
    for rule in &def.rules {
        if rule.emit.event_type.is_empty() {
            return Err(EngineError::InvalidDefinition(
                "emitted event type cannot be empty".into(),
            ));
        }
        let mut seen = BTreeSet::new();
        for claim in &rule.emit.claims {
            if claim.is_empty() || !seen.insert(claim) {
                return Err(EngineError::InvalidDefinition(
                    "claims must be nonempty and unique within a rule".into(),
                ));
            }
        }
        validate_condition(&rule.when, 0)?;
        validate_expr(&rule.emit.payload, 0)?;
    }
    Ok(())
}

fn valid_pointer(path: &str) -> bool {
    if path.is_empty() {
        return true;
    }
    if !path.starts_with('/') {
        return false;
    }
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'~' {
            i += 1;
            if i >= bytes.len() || (bytes[i] != b'0' && bytes[i] != b'1') {
                return false;
            }
        }
        i += 1;
    }
    true
}

fn validate_condition(condition: &Condition, depth: usize) -> Result<(), EngineError> {
    if depth > MAX_AST_DEPTH {
        return Err(EngineError::InvalidDefinition(
            "condition nesting exceeds 64".into(),
        ));
    }
    match condition {
        Condition::PayloadEq { path, value } | Condition::StateEq { path, value } => {
            if !valid_pointer(path) {
                return Err(EngineError::InvalidDefinition(format!(
                    "invalid condition JSON Pointer: {path}"
                )));
            }
            reject_float_values(value)
                .map_err(|error| EngineError::Nondeterministic(error.to_string()))?;
        }
        Condition::PayloadCmp { path, .. } => {
            if !valid_pointer(path) {
                return Err(EngineError::InvalidDefinition(format!(
                    "invalid condition JSON Pointer: {path}"
                )));
            }
        }
        Condition::And { conditions } | Condition::Or { conditions } => {
            if conditions.is_empty() {
                return Err(EngineError::InvalidDefinition(
                    "and/or requires at least one condition".into(),
                ));
            }
            for child in conditions {
                validate_condition(child, depth + 1)?;
            }
        }
        Condition::Not { condition } => validate_condition(condition, depth + 1)?,
    }
    Ok(())
}

fn validate_expr(expr: &ValueExpr, depth: usize) -> Result<(), EngineError> {
    if depth > MAX_AST_DEPTH {
        return Err(EngineError::InvalidDefinition(
            "expression nesting exceeds 64".into(),
        ));
    }
    match expr {
        ValueExpr::Field(field) => {
            let supported = ["actor", "ts", "seq", "type"];
            if !supported.contains(&field.field.as_str())
                && !(field.field.starts_with("payload:") && valid_pointer(&field.field[8..]))
                && !(field.field.starts_with("state:") && valid_pointer(&field.field[6..]))
            {
                return Err(EngineError::InvalidDefinition(format!(
                    "unsupported field reference: {}",
                    field.field
                )));
            }
        }
        ValueExpr::Add(AddExpr { add }) | ValueExpr::Sub(SubExpr { sub: add }) => {
            if add.len() != 2 {
                return Err(EngineError::InvalidDefinition(
                    "add/sub requires exactly two operands".into(),
                ));
            }
            for child in add {
                validate_expr(child, depth + 1)?;
            }
        }
        ValueExpr::Object(items) => {
            for child in items.values() {
                validate_expr(child, depth + 1)?;
            }
        }
        ValueExpr::Array(items) => {
            for child in items {
                validate_expr(child, depth + 1)?;
            }
        }
        ValueExpr::Literal(value) => {
            reject_float_values(value).map_err(|e| EngineError::Nondeterministic(e.to_string()))?
        }
    }
    Ok(())
}

pub trait SchemaCheck {
    fn check(&self, event_type: &str, payload: &Value) -> Result<(), String>;
}

pub trait PolicyCheck {
    fn check(&self, event_type: &str, payload: &Value) -> Result<(), String>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PermissiveCheck;

impl SchemaCheck for PermissiveCheck {
    fn check(&self, _event_type: &str, _payload: &Value) -> Result<(), String> {
        Ok(())
    }
}

impl PolicyCheck for PermissiveCheck {
    fn check(&self, _event_type: &str, _payload: &Value) -> Result<(), String> {
        Ok(())
    }
}

pub struct EventSigner {
    actor: String,
    key: SigningKey,
    pub_key: String,
}

impl EventSigner {
    pub fn from_seed(actor: impl Into<String>, seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        let pub_key = hex::encode(key.verifying_key().to_bytes());
        Self {
            actor: actor.into(),
            key,
            pub_key,
        }
    }

    pub fn actor(&self) -> &str {
        &self.actor
    }

    pub fn public_key(&self) -> &str {
        &self.pub_key
    }

    pub fn sign_event(
        &self,
        seq: u64,
        ts: u64,
        event_type: impl Into<String>,
        payload: Value,
        prev_hash: impl Into<String>,
    ) -> ReactorResult<MoltEvent> {
        let event_type = event_type.into();
        let prev_hash = prev_hash.into();
        let digest = event_digest(
            seq,
            ts,
            &event_type,
            &payload,
            &self.actor,
            &prev_hash,
            &self.pub_key,
        )?;
        let sig = self.key.sign(&digest).to_bytes();
        Ok(MoltEvent {
            seq,
            ts,
            r#type: event_type,
            payload,
            actor: self.actor.clone(),
            prev_hash,
            pub_key: self.pub_key.clone(),
            sig: hex::encode(sig),
            hash: hex::encode(digest),
        })
    }
}

pub fn event_digest(
    seq: u64,
    ts: u64,
    event_type: &str,
    payload: &Value,
    actor: &str,
    prev_hash: &str,
    pub_key: &str,
) -> ReactorResult<[u8; 32]> {
    let payload_bytes = serde_json::to_string(payload)
        .map_err(|e| ReactorError(format!("cannot serialize payload: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(seq.to_be_bytes());
    hasher.update(ts.to_be_bytes());
    hasher.update(event_type.as_bytes());
    hasher.update(payload_bytes.as_bytes());
    hasher.update(actor.as_bytes());
    hasher.update(prev_hash.as_bytes());
    hasher.update(pub_key.as_bytes());
    let digest = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&digest);
    Ok(result)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RunReport {
    pub new_events: Vec<MoltEvent>,
    pub gas_used: BTreeMap<String, u64>,
    pub state: Value,
}

struct WorkItem {
    event: MoltEvent,
    depth: u8,
}
struct StagedOutput {
    event: MoltEvent,
    reactor: String,
    claims: Vec<(String, String)>,
}

pub struct Engine {
    reactors: BTreeMap<String, ReactorDef>,
    signer: Option<EventSigner>,
    schema: Box<dyn SchemaCheck>,
    policy: Box<dyn PolicyCheck>,
    state: BTreeMap<(String, String), Value>,
    fired: BTreeSet<String>,
    head: Option<(u64, String)>,
    committed_events: Vec<MoltEvent>,
}

impl Engine {
    pub fn new(signer: Option<EventSigner>) -> Self {
        Self::with_checks(signer, Box::new(PermissiveCheck), Box::new(PermissiveCheck))
    }

    pub fn with_checks(
        signer: Option<EventSigner>,
        schema: Box<dyn SchemaCheck>,
        policy: Box<dyn PolicyCheck>,
    ) -> Self {
        Self {
            reactors: BTreeMap::new(),
            signer,
            schema,
            policy,
            state: BTreeMap::new(),
            fired: BTreeSet::new(),
            head: None,
            committed_events: Vec::new(),
        }
    }

    pub fn register_reactor(&mut self, def: ReactorDef) -> Result<(), EngineError> {
        validate_definition(&def)?;
        if self.reactors.contains_key(&def.name) {
            return Err(EngineError::InvalidDefinition(format!(
                "reactor {} is already registered",
                def.name
            )));
        }
        self.reactors.insert(def.name.clone(), def);
        Ok(())
    }

    pub fn state_snapshot(&self) -> Value {
        snapshot_state(&self.state)
    }

    pub fn state_for(&self, reactor: &str, key_values: &[Value]) -> Option<&Value> {
        let id = serde_json::to_string(key_values).ok()?;
        self.state.get(&(reactor.to_owned(), id))
    }

    pub fn committed_events(&self) -> &[MoltEvent] {
        &self.committed_events
    }

    pub fn ledger_head(&self) -> Option<&(u64, String)> {
        self.head.as_ref()
    }

    pub fn run(&mut self, range: &VerifiedRange) -> Result<RunReport, EngineError> {
        validate_range_shape(range)?;
        let mut working_state = self.state.clone();
        let mut working_fired = self.fired.clone();
        let mut working_head = match &self.head {
            Some(current) if current.0 >= range.head.0 => Some(current.clone()),
            _ => Some(range.head.clone()),
        };
        let source_types: BTreeMap<String, String> = range
            .events
            .iter()
            .map(|event| (event.hash.clone(), event.r#type.clone()))
            .collect();
        let source_sequences: BTreeMap<String, u64> = range
            .events
            .iter()
            .map(|event| (event.hash.clone(), event.seq))
            .collect();
        let mut recorded_outputs = BTreeMap::<String, MoltEvent>::new();
        for event in &range.events {
            if let Some(id) = recorded_firing_id(
                event,
                &self.reactors,
                self.signer.as_ref(),
                &source_types,
                &source_sequences,
            ) {
                if recorded_outputs.insert(id, event.clone()).is_some() {
                    return Err(EngineError::ReplayMismatch(
                        "more than one recorded output claims the same rule firing".into(),
                    ));
                }
            }
        }
        let mut consumed_recorded = BTreeSet::new();
        let mut queue: VecDeque<WorkItem> = range
            .events
            .iter()
            .cloned()
            .map(|event| WorkItem { event, depth: 0 })
            .collect();
        let mut staged = Vec::new();
        let mut gas_used = BTreeMap::<String, u64>::new();
        let mut seen = BTreeSet::<(u64, String)>::new();
        for event in &range.events {
            seen.insert((event.seq, event.hash.clone()));
        }
        for event in &self.committed_events {
            seen.insert((event.seq, event.hash.clone()));
        }

        while let Some(item) = queue.pop_front() {
            reject_float_values(&item.event.payload)
                .map_err(|e| EngineError::Nondeterministic(e.to_string()))?;
            let matching: Vec<ReactorDef> = self
                .reactors
                .values()
                .filter(|r| r.trigger.event_type == item.event.r#type)
                .cloned()
                .collect();
            let mut children = Vec::new();
            for reactor in matching {
                if item.depth > reactor.max_trigger_depth {
                    return Err(EngineError::TriggerDepth {
                        reactor: reactor.name,
                        limit: reactor.max_trigger_depth,
                    });
                }
                self.schema
                    .check(&item.event.r#type, &item.event.payload)
                    .map_err(EngineError::Schema)?;
                let key_id = state_key_id(&reactor, &item.event)?;
                let state_slot = (reactor.name.clone(), key_id.clone());
                let current = working_state
                    .entry(state_slot.clone())
                    .or_insert_with(|| Value::Object(Map::new()));
                merge_input_state(current, &item.event.payload);
                if item.event.payload.get("action").and_then(Value::as_str) == Some("deliver") {
                    if let Value::Object(map) = current {
                        map.insert("delivered".into(), Value::Bool(true));
                    }
                }
                for (rule_index, rule) in reactor.rules.iter().enumerate() {
                    if !eval_condition(&rule.when, &item.event, current)? {
                        continue;
                    }
                    let fire_id = fire_id(&reactor, &item.event.hash, rule_index);
                    if let Some(recorded) = recorded_outputs.get(&fire_id) {
                        let expected = eval_expr(&rule.emit.payload, &item.event, current)?;
                        reject_float_values(&expected)
                            .map_err(|e| EngineError::Nondeterministic(e.to_string()))?;
                        let expected =
                            attach_metadata(expected, &reactor, &item.event.hash, rule_index)?;
                        let signer = self.signer.as_ref().ok_or(EngineError::MissingSigner)?;
                        if recorded.r#type != rule.emit.event_type
                            || recorded.payload != expected
                            || recorded.ts != item.event.ts
                            || recorded.actor != signer.actor()
                            || recorded.pub_key != signer.public_key()
                        {
                            return Err(EngineError::ReplayMismatch(format!(
                                "recorded output for reactor {} rule {rule_index} differs from deterministic evaluation",
                                reactor.name
                            )));
                        }
                        self.schema
                            .check(&recorded.r#type, &recorded.payload)
                            .map_err(EngineError::Schema)?;
                        self.policy
                            .check(&recorded.r#type, &recorded.payload)
                            .map_err(EngineError::Policy)?;
                        consumed_recorded.insert(fire_id.clone());
                        working_fired.insert(fire_id);
                        continue;
                    }
                    if working_fired.contains(&fire_id) {
                        continue;
                    }
                    let payload = eval_expr(&rule.emit.payload, &item.event, current)?;
                    reject_float_values(&payload)
                        .map_err(|e| EngineError::Nondeterministic(e.to_string()))?;
                    let payload_bytes = serde_json::to_string(&payload)
                        .map_err(|e| EngineError::Evaluation(e.to_string()))?
                        .len() as u64;
                    let cost = payload_bytes
                        .checked_add(1)
                        .ok_or(EngineError::ArithmeticOverflow)?;
                    let used = gas_used.entry(reactor.name.clone()).or_insert(0);
                    *used = used
                        .checked_add(cost)
                        .ok_or(EngineError::ArithmeticOverflow)?;
                    if *used > reactor.gas_budget {
                        return Err(EngineError::GasExceeded {
                            reactor: reactor.name.clone(),
                            used: *used,
                            budget: reactor.gas_budget,
                        });
                    }
                    let output_payload =
                        attach_metadata(payload, &reactor, &item.event.hash, rule_index)?;
                    self.schema
                        .check(&rule.emit.event_type, &output_payload)
                        .map_err(EngineError::Schema)?;
                    self.policy
                        .check(&rule.emit.event_type, &output_payload)
                        .map_err(EngineError::Policy)?;
                    let signer = self.signer.as_ref().ok_or(EngineError::MissingSigner)?;
                    let head = working_head
                        .as_ref()
                        .ok_or_else(|| EngineError::InvalidRange("missing ledger head".into()))?;
                    let seq = next_sequence(head)?;
                    let event = signer
                        .sign_event(
                            seq,
                            item.event.ts,
                            rule.emit.event_type.clone(),
                            output_payload,
                            head.1.clone(),
                        )
                        .map_err(|e| EngineError::Evaluation(e.to_string()))?;
                    if !seen.insert((event.seq, event.hash.clone())) {
                        return Err(EngineError::DuplicateEvent {
                            seq: event.seq,
                            hash: event.hash,
                        });
                    }
                    working_head = Some((event.seq, event.hash.clone()));
                    let claims = rule
                        .emit
                        .claims
                        .iter()
                        .map(|field| (key_id.clone(), field.clone()))
                        .collect();
                    staged.push(StagedOutput {
                        event: event.clone(),
                        reactor: reactor.name.clone(),
                        claims,
                    });
                    children.push(event);
                    working_fired.insert(fire_id);
                }
            }
            for event in children.into_iter().rev() {
                queue.push_front(WorkItem {
                    event,
                    depth: item.depth.saturating_add(1),
                });
            }
        }

        if recorded_outputs
            .keys()
            .any(|fire_id| !consumed_recorded.contains(fire_id))
        {
            return Err(EngineError::ReplayMismatch(
                "a recorded output has no matching rule firing in this range".into(),
            ));
        }

        let mut claimed = BTreeMap::<(String, String), String>::new();
        for output in &staged {
            for (key, field) in &output.claims {
                let claim_key = (key.clone(), field.clone());
                if let Some(previous) = claimed.get(&claim_key) {
                    if previous != &output.reactor {
                        return Err(EngineError::ConflictError {
                            state_key: key.clone(),
                            field: field.clone(),
                        });
                    }
                } else {
                    claimed.insert(claim_key, output.reactor.clone());
                }
            }
        }

        self.state = working_state;
        self.fired = working_fired;
        self.head = working_head;
        let new_events: Vec<MoltEvent> = staged.into_iter().map(|output| output.event).collect();
        self.committed_events.extend(new_events.clone());
        Ok(RunReport {
            new_events,
            gas_used,
            state: snapshot_state(&self.state),
        })
    }
}

fn validate_range_shape(range: &VerifiedRange) -> Result<(), EngineError> {
    if range.events.is_empty() {
        if range.head.1 != GENESIS_HASH {
            return Err(EngineError::InvalidRange(
                "an empty range must use GENESIS_HASH as its head".into(),
            ));
        }
        return Ok(());
    }
    for pair in range.events.windows(2) {
        if pair[1].seq
            != pair[0]
                .seq
                .checked_add(1)
                .ok_or(EngineError::ArithmeticOverflow)?
        {
            return Err(EngineError::InvalidRange(
                "event sequence numbers are not contiguous".into(),
            ));
        }
    }
    let last = range
        .events
        .last()
        .ok_or_else(|| EngineError::InvalidRange("missing last event".into()))?;
    if range.head != (last.seq, last.hash.clone()) {
        return Err(EngineError::InvalidRange(
            "head does not match the last event".into(),
        ));
    }
    Ok(())
}

fn next_sequence(head: &(u64, String)) -> Result<u64, EngineError> {
    if head.1 == GENESIS_HASH {
        Ok(0)
    } else {
        head.0.checked_add(1).ok_or(EngineError::ArithmeticOverflow)
    }
}

fn state_key_id(reactor: &ReactorDef, event: &MoltEvent) -> Result<String, EngineError> {
    let mut parts = Vec::with_capacity(reactor.state_key.len());
    for path in &reactor.state_key {
        let value = event
            .payload
            .pointer(path)
            .ok_or_else(|| EngineError::Evaluation(format!("missing state_key value at {path}")))?;
        parts.push(value.clone());
    }
    serde_json::to_string(&parts).map_err(|e| EngineError::Evaluation(e.to_string()))
}

fn merge_input_state(state: &mut Value, payload: &Value) {
    if let (Value::Object(target), Value::Object(source)) = (&mut *state, payload) {
        for (key, value) in source {
            target.insert(key.clone(), value.clone());
        }
    } else if let Value::Object(target) = &mut *state {
        target.insert("_value".into(), payload.clone());
    }
}

fn eval_condition(
    condition: &Condition,
    event: &MoltEvent,
    state: &Value,
) -> Result<bool, EngineError> {
    match condition {
        Condition::PayloadEq { path, value } => Ok(event.payload.pointer(path) == Some(value)),
        Condition::PayloadCmp { path, cmp, value } => {
            let Some(found) = event.payload.pointer(path) else {
                return Ok(false);
            };
            let Some(number) = integer_i64(found) else {
                return Ok(false);
            };
            Ok(match cmp {
                CompareOp::Eq => number == *value,
                CompareOp::Ne => number != *value,
                CompareOp::Gt => number > *value,
                CompareOp::Gte => number >= *value,
                CompareOp::Lt => number < *value,
                CompareOp::Lte => number <= *value,
            })
        }
        Condition::StateEq { path, value } => Ok(state.pointer(path) == Some(value)),
        Condition::And { conditions } => {
            for condition in conditions {
                if !eval_condition(condition, event, state)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Condition::Or { conditions } => {
            for condition in conditions {
                if eval_condition(condition, event, state)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Condition::Not { condition } => Ok(!eval_condition(condition, event, state)?),
    }
}

fn integer_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|n| i64::try_from(n).ok()))
}

fn eval_expr(expr: &ValueExpr, event: &MoltEvent, state: &Value) -> Result<Value, EngineError> {
    match expr {
        ValueExpr::Literal(value) => Ok(value.clone()),
        ValueExpr::Field(FieldExpr { field }) => {
            let found = match field.as_str() {
                "actor" => Some(Value::String(event.actor.clone())),
                "ts" => Some(Value::Number(Number::from(event.ts))),
                "seq" => Some(Value::Number(Number::from(event.seq))),
                "type" => Some(Value::String(event.r#type.clone())),
                reference if reference.starts_with("payload:") => {
                    event.payload.pointer(&reference[8..]).cloned()
                }
                reference if reference.starts_with("state:") => {
                    state.pointer(&reference[6..]).cloned()
                }
                _ => None,
            };
            found.ok_or_else(|| {
                EngineError::Evaluation(format!("missing field reference {}", field))
            })
        }
        ValueExpr::Add(AddExpr { add }) => binary_integer(add, event, state, true),
        ValueExpr::Sub(SubExpr { sub }) => binary_integer(sub, event, state, false),
        ValueExpr::Object(items) => {
            let mut output = Map::new();
            for (key, value) in items {
                output.insert(key.clone(), eval_expr(value, event, state)?);
            }
            Ok(Value::Object(output))
        }
        ValueExpr::Array(items) => items
            .iter()
            .map(|item| eval_expr(item, event, state))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
    }
}

fn binary_integer(
    items: &[ValueExpr],
    event: &MoltEvent,
    state: &Value,
    add: bool,
) -> Result<Value, EngineError> {
    if items.len() != 2 {
        return Err(EngineError::InvalidDefinition(
            "add/sub requires exactly two operands".into(),
        ));
    }
    let left = eval_expr(&items[0], event, state)?
        .as_i64()
        .ok_or_else(|| {
            EngineError::Evaluation("integer arithmetic requires signed 64-bit operands".into())
        })?;
    let right = eval_expr(&items[1], event, state)?
        .as_i64()
        .ok_or_else(|| {
            EngineError::Evaluation("integer arithmetic requires signed 64-bit operands".into())
        })?;
    let result = if add {
        left.checked_add(right)
    } else {
        left.checked_sub(right)
    }
    .ok_or(EngineError::ArithmeticOverflow)?;
    Ok(Value::Number(Number::from(result)))
}

fn attach_metadata(
    payload: Value,
    reactor: &ReactorDef,
    trigger_hash: &str,
    rule_index: usize,
) -> Result<Value, EngineError> {
    let metadata = serde_json::json!({
        "name": reactor.name,
        "version": reactor.version,
        "trigger_hash": trigger_hash,
        "rule_index": rule_index
    });
    match payload {
        Value::Object(mut object) => {
            if object.contains_key("_molt_reactor") {
                return Err(EngineError::Evaluation(
                    "payload cannot define reserved _molt_reactor metadata".into(),
                ));
            }
            object.insert("_molt_reactor".into(), metadata);
            Ok(Value::Object(object))
        }
        other => Ok(serde_json::json!({"_molt_reactor": metadata, "value": other})),
    }
}

fn recorded_firing_id(
    event: &MoltEvent,
    reactors: &BTreeMap<String, ReactorDef>,
    signer: Option<&EventSigner>,
    source_types: &BTreeMap<String, String>,
    source_sequences: &BTreeMap<String, u64>,
) -> Option<String> {
    let metadata = event.payload.get("_molt_reactor")?;
    let (Some(name), Some(version), Some(trigger_hash), Some(rule_index)) = (
        metadata.get("name").and_then(Value::as_str),
        metadata.get("version").and_then(Value::as_u64),
        metadata.get("trigger_hash").and_then(Value::as_str),
        metadata.get("rule_index").and_then(Value::as_u64),
    ) else {
        return None;
    };
    let reactor = reactors.get(name)?;
    let rule_index = usize::try_from(rule_index).ok()?;
    let rule = reactor.rules.get(rule_index)?;
    let expected_signer = signer?;
    if reactor.version as u64 == version
        && event.r#type == rule.emit.event_type
        && event.actor == expected_signer.actor()
        && event.pub_key == expected_signer.public_key()
        && source_types.get(trigger_hash) == Some(&reactor.trigger.event_type)
        && source_sequences
            .get(trigger_hash)
            .is_some_and(|sequence| *sequence < event.seq)
    {
        Some(fire_id(reactor, trigger_hash, rule_index))
    } else {
        None
    }
}

fn fire_id(reactor: &ReactorDef, trigger_hash: &str, rule_index: usize) -> String {
    format!(
        "{}\0{}\0{}\0{}",
        reactor.name, reactor.version, trigger_hash, rule_index
    )
}

fn snapshot_state(state: &BTreeMap<(String, String), Value>) -> Value {
    let mut reactors = Map::new();
    for ((reactor, key), value) in state {
        let entry = reactors
            .entry(reactor.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(states) = entry {
            states.insert(key.clone(), value.clone());
        }
    }
    Value::Object(reactors)
}
