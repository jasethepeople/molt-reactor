use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{value::RawValue, Map, Number, Value};
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
    #[serde(deserialize_with = "deserialize_payload")]
    pub payload: Value,
    pub actor: String,
    pub prev_hash: String,
    pub pub_key: String,
    pub sig: String,
    pub hash: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedRange {
    pub events: Vec<MoltEvent>,
    pub head: (u64, String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVerifiedRange {
    events: Vec<RawMoltEvent>,
    head: (u64, String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMoltEvent {
    seq: u64,
    ts: u64,
    #[serde(rename = "type")]
    r#type: String,
    payload: Box<RawValue>,
    actor: String,
    prev_hash: String,
    pub_key: String,
    sig: String,
    hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactorError {
    code: &'static str,
    message: String,
}

impl ReactorError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }
}

impl fmt::Display for ReactorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ReactorError {}

pub type ReactorResult<T> = Result<T, ReactorError>;

fn deserialize_payload<'de, D>(deserializer: D) -> Result<Value, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let mut value = Value::deserialize(deserializer)?;
    reject_float_values(&value).map_err(serde::de::Error::custom)?;
    reject_out_of_i64(&value).map_err(serde::de::Error::custom)?;
    normalize_negative_zero(&mut value);
    Ok(value)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineError {
    Parse(String),
    InvalidDefinition(String),
    Nondeterministic(String),
    InvalidRange(String),
    Schema {
        event_index: usize,
        reason: String,
    },
    Policy {
        event_index: usize,
        reason: String,
    },
    MissingSigner,
    Signature {
        event_index: usize,
    },
    GasExceeded {
        reactor: String,
        used: u64,
        budget: u64,
    },
    TriggerDepth {
        reactor: String,
        depth: u8,
        limit: u8,
    },
    ConflictError {
        reactor_a: String,
        reactor_b: String,
        state_key: String,
        field: String,
    },
    DuplicateEvent {
        seq: u64,
        hash: String,
    },
    ReplayMismatch(String),
    MarkerInvalid {
        event_index: usize,
        reason: String,
    },
    StateKey {
        reactor: String,
        pointer: String,
    },
    Evaluation(String),
    ArithmeticOverflow {
        op: String,
        left: String,
        right: String,
    },
}

impl EngineError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Parse(_) => "E_PARSE",
            Self::InvalidDefinition(_) | Self::Nondeterministic(_) | Self::Evaluation(_) => {
                "E_ANALYZE"
            }
            Self::InvalidRange(_) => "E_RANGE_SHAPE",
            Self::Schema { .. } => "E_SCHEMA",
            Self::Policy { .. } => "E_POLICY",
            Self::MissingSigner => "E_SIGNER_MISSING",
            Self::Signature { .. } => "E_SIG",
            Self::GasExceeded { .. } => "E_GAS",
            Self::TriggerDepth { .. } => "E_DEPTH",
            Self::ConflictError { .. } => "E_CONFLICT",
            Self::DuplicateEvent { .. } => "E_DUP",
            Self::ReplayMismatch(_) => "E_REPLAY_MISMATCH",
            Self::MarkerInvalid { .. } => "E_MARKER_INVALID",
            Self::StateKey { .. } => "E_STATE_KEY",
            Self::ArithmeticOverflow { .. } => "E_OVERFLOW",
        }
    }
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(message) => write!(f, "parse error: {message}"),
            Self::InvalidDefinition(message) => write!(f, "invalid reactor: {message}"),
            Self::Nondeterministic(message) => write!(f, "nondeterministic reactor: {message}"),
            Self::InvalidRange(message) => write!(f, "invalid verified range: {message}"),
            Self::Schema { event_index, reason } => write!(f, "schema validation failed at event {event_index}: {reason}"),
            Self::Policy { event_index, reason } => write!(f, "policy validation failed at event {event_index}: {reason}"),
            Self::MissingSigner => f.write_str("reactor emitted events but no signer is configured"),
            Self::Signature { event_index } => write!(f, "Ed25519 signing failed at event {event_index}"),
            Self::GasExceeded { reactor, used, budget } => write!(f, "gas budget exceeded for {reactor}: {used}/{budget}"),
            Self::TriggerDepth { reactor, depth, limit } => write!(f, "trigger depth exceeded for {reactor}: depth {depth} exceeds limit {limit}"),
            Self::ConflictError { reactor_a, reactor_b, state_key, field } => write!(f, "reactors {reactor_a} and {reactor_b} conflict on state key {state_key}, field {field}"),
            Self::DuplicateEvent { seq, hash } => write!(f, "duplicate output event ({seq}, {hash})"),
            Self::ReplayMismatch(message) => write!(f, "reactor replay mismatch: {message}"),
            Self::MarkerInvalid { event_index, reason } => write!(f, "invalid replay marker at event {event_index}: {reason}"),
            Self::StateKey { reactor, pointer } => write!(f, "reactor {reactor} is missing state_key value at {pointer}"),
            Self::Evaluation(message) => write!(f, "reactor evaluation failed: {message}"),
            Self::ArithmeticOverflow { op, left, right } => write!(f, "checked arithmetic overflow: {left} {op} {right}"),
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
        return Err(ReactorError::new(
            "E_ANALYZE",
            "reactor JSON exceeds the 1 MiB analysis limit",
        ));
    }
    reject_forbidden_source(source)?;
    let mut raw: Value = serde_json::from_str(source)
        .map_err(|e| ReactorError::new("E_PARSE", format!("invalid JSON: {e}")))?;
    reject_non_integer_number_syntax(source)?;
    reject_float_values(&raw)?;
    reject_out_of_i64(&raw)?;
    normalize_negative_zero(&mut raw);
    let def: ReactorDef = serde_json::from_value(raw)
        .map_err(|e| ReactorError::new("E_PARSE", format!("invalid reactor DSL: {e}")))?;
    validate_definition(&def).map_err(|e| ReactorError::new("E_ANALYZE", e.to_string()))?;
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

pub fn parse_verified_range(source: &str) -> Result<VerifiedRange, EngineError> {
    let raw: RawVerifiedRange = serde_json::from_str(source)
        .map_err(|error| EngineError::Parse(format!("invalid verified range JSON: {error}")))?;
    let mut events = Vec::with_capacity(raw.events.len());
    for event in raw.events {
        let payload_source = event.payload.get();
        reject_non_integer_number_syntax(payload_source).map_err(map_reactor_error)?;
        let mut payload: Value = serde_json::from_str(payload_source)
            .map_err(|error| EngineError::Parse(format!("invalid event payload JSON: {error}")))?;
        validate_payload_numbers(&payload)?;
        normalize_negative_zero(&mut payload);
        events.push(MoltEvent {
            seq: event.seq,
            ts: event.ts,
            r#type: event.r#type,
            payload,
            actor: event.actor,
            prev_hash: event.prev_hash,
            pub_key: event.pub_key,
            sig: event.sig,
            hash: event.hash,
        });
    }
    let range = VerifiedRange {
        events,
        head: raw.head,
    };
    validate_range_shape(&range)?;
    Ok(range)
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
            return Err(ReactorError::new(
                "E_ANALYZE",
                format!("{reason} (found {needle})"),
            ));
        }
    }
    Ok(())
}

fn reject_non_integer_number_syntax(source: &str) -> ReactorResult<()> {
    let bytes = source.as_bytes();
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_digit()
                    || matches!(bytes[index], b'.' | b'e' | b'E' | b'+' | b'-'))
            {
                index += 1;
            }
            let token = &source[start..index];
            if token.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
                return Err(ReactorError::new(
                    "E_ANALYZE",
                    "floating-point JSON number syntax is forbidden",
                ));
            }
            if token.parse::<i64>().is_err() {
                return Err(ReactorError::new(
                    "E_PARSE",
                    "integer outside i64 range is forbidden",
                ));
            }
            continue;
        }
        index += 1;
    }
    Ok(())
}

fn is_negative_zero(number: &Number) -> bool {
    number
        .as_f64()
        .is_some_and(|value| value == 0.0 && value.is_sign_negative())
}

fn normalize_negative_zero(value: &mut Value) {
    match value {
        Value::Number(number) if is_negative_zero(number) => {
            *value = Value::Number(Number::from(0));
        }
        Value::Array(items) => items.iter_mut().for_each(normalize_negative_zero),
        Value::Object(items) => items.values_mut().for_each(normalize_negative_zero),
        _ => {}
    }
}

fn reject_float_values(value: &Value) -> ReactorResult<()> {
    match value {
        Value::Number(number) if number.is_f64() && !is_negative_zero(number) => Err(
            ReactorError::new("E_ANALYZE", "floating-point JSON numbers are forbidden"),
        ),
        Value::Array(items) => items.iter().try_for_each(reject_float_values),
        Value::Object(items) => items.values().try_for_each(reject_float_values),
        _ => Ok(()),
    }
}

fn reject_out_of_i64(value: &Value) -> ReactorResult<()> {
    match value {
        Value::Number(number) if number.as_i64().is_none() && !is_negative_zero(number) => Err(
            ReactorError::new("E_PARSE", "integer outside i64 range is forbidden"),
        ),
        Value::Array(items) => items.iter().try_for_each(reject_out_of_i64),
        Value::Object(items) => items.values().try_for_each(reject_out_of_i64),
        _ => Ok(()),
    }
}

fn validate_payload_numbers(value: &Value) -> Result<(), EngineError> {
    reject_float_values(value).map_err(|error| EngineError::Nondeterministic(error.to_string()))?;
    reject_out_of_i64(value).map_err(|error| EngineError::Parse(error.to_string()))?;
    Ok(())
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
    if def.gas_budget > i64::MAX as u64 {
        return Err(EngineError::Parse(
            "gas_budget exceeds the supported i64 range".into(),
        ));
    }
    if def.max_trigger_depth == 0 || def.max_trigger_depth == u8::MAX {
        return Err(EngineError::InvalidDefinition(
            "max_trigger_depth must be in 1..=254".into(),
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
            validate_payload_numbers(value)?;
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
            if items.contains_key("_molt_reactor") {
                return Err(EngineError::InvalidDefinition(
                    "payload cannot define reserved _molt_reactor metadata".into(),
                ));
            }
            for child in items.values() {
                validate_expr(child, depth + 1)?;
            }
        }
        ValueExpr::Array(items) => {
            for child in items {
                validate_expr(child, depth + 1)?;
            }
        }
        ValueExpr::Literal(value) => validate_payload_numbers(value)?,
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
        mut payload: Value,
        prev_hash: impl Into<String>,
    ) -> ReactorResult<MoltEvent> {
        let event_type = event_type.into();
        let prev_hash = prev_hash.into();
        normalize_negative_zero(&mut payload);
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
    let payload_bytes = canonical_json(payload)?;
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

pub fn canonical_json(value: &Value) -> ReactorResult<String> {
    let mut output = String::new();
    write_canonical(value, &mut output)?;
    Ok(output)
}

fn write_canonical(value: &Value, output: &mut String) -> ReactorResult<()> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(number) => {
            if is_negative_zero(number) {
                output.push('0');
            } else {
                let integer = number.as_i64().ok_or_else(|| {
                    if number.is_f64() {
                        ReactorError::new("E_ANALYZE", "floating-point JSON numbers are forbidden")
                    } else {
                        ReactorError::new("E_PARSE", "integer outside i64 range is forbidden")
                    }
                })?;
                output.push_str(&integer.to_string());
            }
        }
        Value::String(value) => write_canonical_string(value, output),
        Value::Array(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical(item, output)?;
            }
            output.push(']');
        }
        Value::Object(items) => {
            output.push('{');
            let mut entries: Vec<_> = items.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical_string(key, output);
                output.push(':');
                write_canonical(item, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn write_canonical_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            character if (character as u32) <= 0x1f => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
    output.push('"');
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
    event_index: usize,
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

    pub fn snapshot_state(&self) -> Value {
        self.state_snapshot()
    }

    pub fn state_for(&self, reactor: &str, key_values: &[Value]) -> Option<&Value> {
        let key = Value::Array(key_values.to_vec());
        let id = canonical_json(&key).ok()?;
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
        let mut recorded_outputs = BTreeMap::<String, (MoltEvent, usize)>::new();
        for (event_index, event) in range.events.iter().enumerate() {
            let Some(id) = recorded_firing_id(
                event,
                &self.reactors,
                self.signer.as_ref(),
                &source_types,
                &source_sequences,
            )
            .map_err(|reason| EngineError::MarkerInvalid {
                event_index,
                reason,
            })?
            else {
                continue;
            };
            if recorded_outputs
                .insert(id, (event.clone(), event_index))
                .is_some()
            {
                return Err(EngineError::MarkerInvalid {
                    event_index,
                    reason: "more than one recorded output claims the same rule firing".into(),
                });
            }
        }
        let mut consumed_recorded = BTreeSet::new();
        let mut queue: VecDeque<WorkItem> = range
            .events
            .iter()
            .cloned()
            .enumerate()
            .map(|(event_index, event)| WorkItem {
                event,
                depth: 0,
                event_index,
            })
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

        while let Some(mut item) = queue.pop_front() {
            normalize_negative_zero(&mut item.event.payload);
            validate_payload_numbers(&item.event.payload)?;
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
                        depth: item.depth,
                        limit: reactor.max_trigger_depth,
                    });
                }
                self.schema
                    .check(&item.event.r#type, &item.event.payload)
                    .map_err(|reason| EngineError::Schema {
                        event_index: item.event_index,
                        reason,
                    })?;
                let key_id = state_key_id(&reactor, &item.event)?;
                let state_slot = (reactor.name.clone(), key_id.clone());
                let current = working_state
                    .entry(state_slot.clone())
                    .or_insert_with(|| Value::Object(Map::new()));
                merge_input_state(current, &item.event.payload);
                if reactor.trigger.event_type == "escrow_action"
                    && item.event.payload.get("action").and_then(Value::as_str) == Some("deliver")
                {
                    if let Value::Object(map) = current {
                        map.insert("delivered".into(), Value::Bool(true));
                    }
                }
                for (rule_index, rule) in reactor.rules.iter().enumerate() {
                    if !eval_condition(&rule.when, &item.event, current)? {
                        continue;
                    }
                    let fire_id = fire_id(&reactor, &item.event.hash, rule_index);
                    if let Some((recorded, recorded_index)) = recorded_outputs.get(&fire_id) {
                        let expected = eval_expr(&rule.emit.payload, &item.event, current)?;
                        validate_payload_numbers(&expected)?;
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
                            .map_err(|reason| EngineError::Schema {
                                event_index: *recorded_index,
                                reason,
                            })?;
                        self.policy
                            .check(&recorded.r#type, &recorded.payload)
                            .map_err(|reason| EngineError::Policy {
                                event_index: *recorded_index,
                                reason,
                            })?;
                        consumed_recorded.insert(fire_id.clone());
                        working_fired.insert(fire_id);
                        continue;
                    }
                    if working_fired.contains(&fire_id) {
                        continue;
                    }
                    let payload = eval_expr(&rule.emit.payload, &item.event, current)?;
                    validate_payload_numbers(&payload)?;
                    let payload_bytes =
                        canonical_json(&payload).map_err(map_reactor_error)?.len() as u64;
                    let cost = payload_bytes
                        .checked_add(1)
                        .ok_or_else(|| arithmetic_overflow("+", payload_bytes, 1))?;
                    let used = gas_used.entry(reactor.name.clone()).or_insert(0);
                    *used = used
                        .checked_add(cost)
                        .ok_or_else(|| arithmetic_overflow("+", *used, cost))?;
                    if *used > reactor.gas_budget {
                        return Err(EngineError::GasExceeded {
                            reactor: reactor.name.clone(),
                            used: *used,
                            budget: reactor.gas_budget,
                        });
                    }
                    let output_payload =
                        attach_metadata(payload, &reactor, &item.event.hash, rule_index)?;
                    validate_payload_numbers(&output_payload)?;
                    let output_index = range.events.len() + staged.len();
                    self.schema
                        .check(&rule.emit.event_type, &output_payload)
                        .map_err(|reason| EngineError::Schema {
                            event_index: output_index,
                            reason,
                        })?;
                    self.policy
                        .check(&rule.emit.event_type, &output_payload)
                        .map_err(|reason| EngineError::Policy {
                            event_index: output_index,
                            reason,
                        })?;
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
                        .map_err(map_reactor_error)?;
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
                    children.push((event, output_index));
                    working_fired.insert(fire_id);
                }
            }
            for (event, event_index) in children.into_iter().rev() {
                queue.push_front(WorkItem {
                    event,
                    depth: item.depth.saturating_add(1),
                    event_index,
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
                            reactor_a: previous.clone(),
                            reactor_b: output.reactor.clone(),
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

    pub fn verify(&mut self, range: &VerifiedRange) -> Result<(), EngineError> {
        let previous_state = std::mem::take(&mut self.state);
        let previous_fired = std::mem::take(&mut self.fired);
        let previous_head = self.head.take();
        let previous_events = std::mem::take(&mut self.committed_events);
        let result = self.run(range);
        match result {
            Ok(report) if report.new_events.is_empty() => {
                self.committed_events = previous_events;
                Ok(())
            }
            Ok(report) => {
                self.state = previous_state;
                self.fired = previous_fired;
                self.head = previous_head;
                self.committed_events = previous_events;
                Err(EngineError::ReplayMismatch(format!(
                    "range is missing {} recorded reactor output(s)",
                    report.new_events.len()
                )))
            }
            Err(error) => {
                self.state = previous_state;
                self.fired = previous_fired;
                self.head = previous_head;
                self.committed_events = previous_events;
                Err(error)
            }
        }
    }
}

fn map_reactor_error(error: ReactorError) -> EngineError {
    match error.code() {
        "E_PARSE" => EngineError::Parse(error.to_string()),
        "E_ANALYZE" => EngineError::Nondeterministic(error.to_string()),
        _ => EngineError::Evaluation(error.to_string()),
    }
}

fn arithmetic_overflow(op: &str, left: impl ToString, right: impl ToString) -> EngineError {
    EngineError::ArithmeticOverflow {
        op: op.to_owned(),
        left: left.to_string(),
        right: right.to_string(),
    }
}

fn is_lower_hex_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_range_shape(range: &VerifiedRange) -> Result<(), EngineError> {
    if range.events.is_empty() {
        if range.head != (0, GENESIS_HASH.to_owned()) {
            return Err(EngineError::InvalidRange(
                "an empty range must use sequence 0 and GENESIS_HASH".into(),
            ));
        }
        return Ok(());
    }
    for event in &range.events {
        if !is_lower_hex_hash(&event.hash) {
            return Err(EngineError::InvalidRange(
                "event hash must be 64 lowercase hexadecimal characters".into(),
            ));
        }
    }
    for pair in range.events.windows(2) {
        let expected =
            pair[0]
                .seq
                .checked_add(1)
                .ok_or_else(|| EngineError::ArithmeticOverflow {
                    op: "+".into(),
                    left: pair[0].seq.to_string(),
                    right: "1".into(),
                })?;
        if pair[1].seq != expected {
            return Err(EngineError::InvalidRange(
                "event sequence numbers are not contiguous".into(),
            ));
        }
    }
    let last = range
        .events
        .last()
        .ok_or_else(|| EngineError::InvalidRange("missing last event".into()))?;
    if range.head != (last.seq, last.hash.clone()) || !is_lower_hex_hash(&range.head.1) {
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
        head.0
            .checked_add(1)
            .ok_or_else(|| arithmetic_overflow("+", head.0, 1))
    }
}

fn state_key_id(reactor: &ReactorDef, event: &MoltEvent) -> Result<String, EngineError> {
    let mut parts = Vec::with_capacity(reactor.state_key.len());
    for path in &reactor.state_key {
        let value = event
            .payload
            .pointer(path)
            .ok_or_else(|| EngineError::StateKey {
                reactor: reactor.name.clone(),
                pointer: path.clone(),
            })?;
        parts.push(value.clone());
    }
    canonical_json(&Value::Array(parts)).map_err(|error| {
        if error.code() == "E_PARSE" {
            EngineError::Parse(error.to_string())
        } else {
            EngineError::Nondeterministic(error.to_string())
        }
    })
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
    let op = if add { "+" } else { "-" };
    let result = if add {
        left.checked_add(right)
    } else {
        left.checked_sub(right)
    }
    .ok_or_else(|| arithmetic_overflow(op, left, right))?;
    Ok(Value::Number(Number::from(result)))
}

fn attach_metadata(
    mut payload: Value,
    reactor: &ReactorDef,
    trigger_hash: &str,
    rule_index: usize,
) -> Result<Value, EngineError> {
    normalize_negative_zero(&mut payload);
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
) -> Result<Option<String>, String> {
    let Some(metadata) = event.payload.get("_molt_reactor") else {
        return Ok(None);
    };
    let Value::Object(fields) = metadata else {
        return Err("_molt_reactor must be an object".into());
    };
    let expected_fields = ["name", "rule_index", "trigger_hash", "version"];
    if fields.len() != expected_fields.len()
        || fields
            .keys()
            .map(String::as_str)
            .any(|key| !expected_fields.contains(&key))
    {
        return Err(
            "_molt_reactor must contain exactly name, version, trigger_hash, and rule_index".into(),
        );
    }
    let name = fields
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "marker name must be a string".to_owned())?;
    let version = fields
        .get("version")
        .and_then(Value::as_i64)
        .filter(|version| *version >= 1)
        .ok_or_else(|| "marker version must be an integer >= 1".to_owned())?;
    let trigger_hash = fields
        .get("trigger_hash")
        .and_then(Value::as_str)
        .filter(|hash| is_lower_hex_hash(hash))
        .ok_or_else(|| "marker trigger_hash must be 64 lowercase hex characters".to_owned())?;
    let rule_index = fields
        .get("rule_index")
        .and_then(Value::as_i64)
        .filter(|index| *index >= 0)
        .and_then(|index| usize::try_from(index).ok())
        .ok_or_else(|| "marker rule_index must be an integer >= 0".to_owned())?;
    let reactor = reactors
        .get(name)
        .ok_or_else(|| format!("marker names unregistered reactor {name}"))?;
    let rule = reactor
        .rules
        .get(rule_index)
        .ok_or_else(|| format!("marker rule_index {rule_index} is out of range"))?;
    let expected_signer =
        signer.ok_or_else(|| "replay marker requires a configured signer".to_owned())?;
    if reactor.version as i64 != version {
        return Err("marker version does not match registered reactor".into());
    }
    if event.r#type != rule.emit.event_type {
        return Err("marker output type does not match its rule".into());
    }
    if event.actor != expected_signer.actor() || event.pub_key != expected_signer.public_key() {
        return Err("marker output signer does not match configured signer".into());
    }
    if source_types.get(trigger_hash) != Some(&reactor.trigger.event_type)
        || !source_sequences
            .get(trigger_hash)
            .is_some_and(|sequence| *sequence < event.seq)
    {
        return Err("marker trigger_hash does not identify an earlier matching input event".into());
    }
    Ok(Some(fire_id(reactor, trigger_hash, rule_index)))
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
