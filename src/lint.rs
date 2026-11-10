//! Schema checks the SDK's validator doesn't make, against the CAWG specifications:
//!
//! - `cawg.metadata` (Metadata Assertion 1.1 §3),
//! - `cawg.training-mining` (Training and Data Mining Assertion 1.1 §3),
//! - `cawg.identity` structure (Identity Assertion 1.3 §5.2 CDDL), read from a store whose
//!   identity assertions were not decoded.
//!
//! Each message names the assertion label it is about.

use serde_json::{Map, Value};

const TDM_STANDARD: [&str; 4] = ["cawg.data_mining", "cawg.ai_inference", "cawg.ai_training", "cawg.ai_generative_training"];
const TDM_USES: [&str; 3] = ["allowed", "notAllowed", "constrained"];

/// Lints every CAWG assertion in the active manifest of `detailed` and `json`
/// (`Reader::detailed_json()` and `Reader::json()`, with `core.decode_identity_assertions` off).
pub fn lint(detailed: &Value, json: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(active) = detailed["active_manifest"].as_str() else { return out };
    let manifest = &detailed["manifests"][active];
    let Some(store) = manifest["assertion_store"].as_object() else { return out };
    for (label, value) in store {
        let base = label.split("__").next().unwrap_or(label);
        match base {
            "cawg.metadata" => metadata(label, value, &mut out),
            "cawg.training-mining" => training_mining(label, value, &mut out),
            "cawg.identity" => identity(label, value, &mut out),
            _ => {}
        }
    }
    // The assertion store doesn't say how each assertion was serialized, so the content box
    // type comes from `Reader::json()`, which marks JSON assertions with `kind: Json`.
    let assertions = json["manifests"][active]["assertions"].as_array().into_iter().flatten();
    for a in assertions.filter(|a| a["label"] == "cawg.metadata") {
        if a["kind"] != "Json" {
            out.push("cawg.metadata: not in a JSON content type box".to_owned());
        }
    }
    out
}

/// §3: a JSON content type box with a JSON-LD object that has `@context`. Every compact IRI
/// (`prefix:term`) must use a prefix that `@context` defines, or JSON-LD expansion drops it.
fn metadata(label: &str, v: &Value, out: &mut Vec<String>) {
    let Some(obj) = v.as_object() else {
        out.push(format!("{label}: not a JSON object"));
        return;
    };
    let Some(context) = obj.get("@context") else {
        out.push(format!("{label}: @context is missing"));
        return;
    };
    let mut prefixes = Map::new();
    let mut collect = |c: &Value| match c {
        Value::Object(m) => prefixes.extend(m.clone()),
        Value::String(_) => {}
        other => out.push(format!("{label}: @context entry {other} is neither an IRI nor an object")),
    };
    match context {
        Value::Array(a) => a.iter().for_each(&mut collect),
        c => collect(c),
    }
    for (prefix, iri) in &prefixes {
        if !iri.is_string() && !iri.is_object() {
            out.push(format!("{label}: @context term {prefix} is not an IRI"));
        }
    }
    fn walk(label: &str, v: &Value, prefixes: &Map<String, Value>, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                for (k, v) in m {
                    if let Some((prefix, _)) = k.split_once(':') {
                        if !k.starts_with('@') && !prefixes.contains_key(prefix) && !k.contains("://") {
                            out.push(format!("{label}: {k} uses prefix {prefix}, which @context doesn't define"));
                        }
                    }
                    if k != "@context" {
                        walk(label, v, prefixes, out);
                    }
                }
            }
            Value::Array(a) => a.iter().for_each(|v| walk(label, v, prefixes, out)),
            _ => {}
        }
    }
    walk(label, v, &prefixes, out);
}

/// §3.2 CDDL: `entries` is required; each entry has `use` from the choice set and an optional
/// non-empty `constraint_info`. `cawg.`-prefixed keys are reserved for the four standard
/// entries; other keys use the C2PA custom label syntax.
fn training_mining(label: &str, v: &Value, out: &mut Vec<String>) {
    let Some(obj) = v.as_object() else {
        out.push(format!("{label}: not a map"));
        return;
    };
    for k in obj.keys() {
        if k != "entries" && k != "metadata" {
            out.push(format!("{label}: unknown field {k}"));
        }
    }
    if obj.get("metadata").is_some_and(|m| !m.is_object()) {
        out.push(format!("{label}: metadata is not a map"));
    }
    let Some(entries) = obj.get("entries") else {
        out.push(format!("{label}: entries is missing"));
        return;
    };
    let Some(entries) = entries.as_object() else {
        out.push(format!("{label}: entries is not a map"));
        return;
    };
    for (key, entry) in entries {
        if key.starts_with("cawg.") && !TDM_STANDARD.contains(&key.as_str()) {
            out.push(format!("{label}: entry {key} uses the reserved cawg. prefix but isn't a standard entry"));
        } else if !key.starts_with("cawg.") && !custom_label(key) {
            out.push(format!("{label}: entry {key} isn't a valid custom label"));
        }
        let Some(entry) = entry.as_object() else {
            out.push(format!("{label}: entry {key} is not a map"));
            continue;
        };
        match entry.get("use") {
            None => out.push(format!("{label}: entry {key} has no use")),
            Some(Value::String(u)) if TDM_USES.contains(&u.as_str()) => {}
            Some(u) => out.push(format!("{label}: entry {key} use {u} is not allowed, notAllowed or constrained")),
        }
        match entry.get("constraint_info") {
            None => {}
            Some(Value::String(s)) if !s.is_empty() => {}
            Some(c) => out.push(format!("{label}: entry {key} constraint_info {c} is not a non-empty text string")),
        }
    }
}

/// C2PA §6.2 entity-specific label: a reverse domain name, then the label, in dot-separated
/// components of lowercase letters, digits, `_` and `-`.
fn custom_label(key: &str) -> bool {
    let parts: Vec<&str> = key.split('.').collect();
    parts.len() >= 3
        && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-'))
}

/// Identity 1.3 §5.2 CDDL. `expected_*` fields were removed in 1.2; validators must ignore them.
fn identity(label: &str, v: &Value, out: &mut Vec<String>) {
    let Some(obj) = v.as_object() else {
        out.push(format!("{label}: not a map"));
        return;
    };
    for k in obj.keys() {
        if !["signer_payload", "signature", "pad1", "pad2"].contains(&k.as_str()) {
            out.push(format!("{label}: unknown field {k}"));
        }
    }
    for k in ["signature", "pad1"] {
        if !obj.get(k).is_some_and(is_bytes) {
            out.push(format!("{label}: {k} is missing or not a byte string"));
        }
    }
    if obj.get("pad2").is_some_and(|p| !is_bytes(p)) {
        out.push(format!("{label}: pad2 is not a byte string"));
    }
    let Some(sp) = obj.get("signer_payload") else {
        out.push(format!("{label}: signer_payload is missing"));
        return;
    };
    let Some(sp) = sp.as_object() else {
        out.push(format!("{label}: signer_payload is not a map"));
        return;
    };
    match sp.get("referenced_assertions") {
        Some(Value::Array(a)) if !a.is_empty() => {
            for r in a {
                if !r["url"].is_string() || !r.get("hash").is_some_and(is_bytes) {
                    out.push(format!("{label}: referenced assertion {r} is not a hashed-uri-map"));
                }
            }
        }
        _ => out.push(format!("{label}: referenced_assertions is missing or empty")),
    }
    if !sp.get("sig_type").and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
        out.push(format!("{label}: sig_type is missing or empty"));
    }
    match sp.get("role") {
        None => {}
        Some(Value::Array(a)) if !a.is_empty() && a.iter().all(|r| r.as_str().is_some_and(|s| !s.is_empty())) => {}
        Some(r) => out.push(format!("{label}: role {r} is not a non-empty array of non-empty text strings")),
    }
    for k in sp.keys() {
        if !["referenced_assertions", "sig_type", "role"].contains(&k.as_str()) && !k.starts_with("expected_") {
            out.push(format!("{label}: signer_payload has unknown field {k}"));
        }
    }
}

/// How a CBOR byte string appears in the Reader's JSON: an array of bytes, or base64 text.
fn is_bytes(v: &Value) -> bool {
    match v {
        Value::String(_) => true,
        Value::Array(a) => a.iter().all(|b| b.as_u64().is_some_and(|b| b < 256)),
        _ => false,
    }
}
