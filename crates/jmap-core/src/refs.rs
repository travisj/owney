//! Result references (RFC 8620 §3.7): method chaining without round-trips.
//!
//! A request argument named `#foo` containing `{resultOf, name, path}` is
//! replaced by the dispatcher with the value extracted from a previous
//! method response. This allows clients to chain method calls and pass
//! results from one call as arguments to the next within a single round-trip.
//!
//! # Overview
//!
//! The dispatcher calls [`resolve_references`] before handing arguments to
//! a handler. For each `#key` in the arguments object:
//!
//! 1. Look up the prior response matching `resultOf` (call ID) and `name`
//!    (method name).
//! 2. Extract the value at the JSON path specified in `path` (e.g. `/ids`,
//!    `/results/0/emails`).
//! 3. Replace `#key` in the arguments with the extracted value. The handler
//!    sees the plain key name.
//!
//! # Path Syntax
//!
//! Paths are JSON-Pointer-like (RFC 6901) with one extension: `*` acts as
//! a wildcard.
//!
//! - `/ids` → the root `ids` field
//! - `/list/0/name` → first item in `list`, then `name` field
//! - `/list/*/ids` → for each item in `list`, get its `ids` field, flatten
//!   result arrays one level
//! - `/by_tag/*` → for each value in the object, flattens result arrays
//!
//! Wildcard flattening rules (RFC 8620 §3.7):
//! - `*` against an array: apply the rest of the path to each element,
//!   flatten one level of resulting arrays.
//! - `*` against an object: apply the rest of the path to each value,
//!   flatten one level of resulting arrays.
//!
//! # Example: Query then Get
//!
//! Client wants to query for emails, then fetch them. Without result
//! references, this takes two requests. With them, one request:
//!
//! Request:
//! ```json
//! {
//!   "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
//!   "methodCalls": [
//!     ["Email/query", {"accountId": "a1", "filter": {"inMailbox": "INBOX"}}, "q1"],
//!     ["Email/get", {
//!       "accountId": "a1",
//!       "#ids": {
//!         "resultOf": "q1",
//!         "name": "Email/query",
//!         "path": "/ids"
//!       },
//!       "properties": ["subject", "from"]
//!     }, "g1"]
//!   ]
//! }
//! ```
//!
//! First response (`Email/query`):
//! ```json
//! ["Email/query", {"ids": ["e1", "e2", "e3"]}, "q1"]
//! ```
//!
//! The dispatcher resolves `#ids` to the value at `/ids` from the prior
//! response, so the `Email/get` handler receives:
//! ```json
//! {
//!   "accountId": "a1",
//!   "ids": ["e1", "e2", "e3"],
//!   "properties": ["subject", "from"]
//! }
//! ```
//!
//! # Example: Wildcard Flattening
//!
//! Query returns emails grouped by tag. Client wants all email IDs:
//!
//! Query response:
//! ```json
//! ["Foo/query", {
//!   "byTag": {
//!     "important": ["e1", "e2"],
//!     "follow-up": ["e3"]
//!   }
//! }, "q1"]
//! ```
//!
//! Reference with wildcard:
//! ```json
//! "#ids": {
//!   "resultOf": "q1",
//!   "name": "Foo/query",
//!   "path": "/byTag/*"
//! }
//! ```
//!
//! Handler receives: `["e1", "e2", "e3"]` (one level of arrays flattened).
//!
//! # Errors
//!
//! Result reference resolution fails with [`MethodError::InvalidResultReference`] if:
//! - The referenced call is missing from prior responses
//! - The path does not exist in the response
//! - The reference object is malformed (missing fields, unknown fields)
//! - A plain key also exists in arguments (e.g., both `ids` and `#ids`)

use serde::Deserialize;
use serde_json::Value;

use crate::envelope::{Invocation, MethodError};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResultReference {
    result_of: String,
    name: String,
    path: String,
}

/// Replace every `#key` argument with its resolved value. Errors if a plain
/// `key` also exists, if the referenced call is missing, or if the path
/// doesn't resolve (all per spec).
pub fn resolve_references(
    arguments: Value,
    prior_responses: &[Invocation],
) -> Result<Value, MethodError> {
    let Value::Object(map) = arguments else {
        return Err(MethodError::InvalidArguments(
            "arguments must be an object".into(),
        ));
    };

    let mut resolved = serde_json::Map::with_capacity(map.len());
    for (key, value) in &map {
        let Some(plain_key) = key.strip_prefix('#') else {
            continue;
        };
        if map.contains_key(plain_key) {
            return Err(MethodError::InvalidArguments(format!(
                "both {key} and {plain_key} present"
            )));
        }
        let reference: ResultReference = serde_json::from_value(value.clone())
            .map_err(|err| MethodError::InvalidResultReference(err.to_string()))?;

        let source = prior_responses
            .iter()
            .find(|inv| inv.call_id() == reference.result_of && inv.name() == reference.name)
            .ok_or_else(|| {
                MethodError::InvalidResultReference(format!(
                    "no prior response {} with callId {}",
                    reference.name, reference.result_of
                ))
            })?;

        let extracted = eval_path(source.arguments(), &reference.path).ok_or_else(|| {
            MethodError::InvalidResultReference(format!("path {} not found", reference.path))
        })?;
        resolved.insert(plain_key.to_owned(), extracted);
    }

    let mut out = serde_json::Map::with_capacity(map.len());
    for (key, value) in map {
        if let Some(plain_key) = key.strip_prefix('#') {
            let value = resolved
                .remove(plain_key)
                .expect("resolved above for every # key");
            out.insert(plain_key.to_owned(), value);
        } else {
            out.insert(key, value);
        }
    }
    Ok(Value::Object(out))
}

/// RFC 8620 §3.7 path evaluation: `/`-separated tokens; a token of `*`
/// against an array applies the rest of the path to every element and
/// flattens one level of resulting arrays.
fn eval_path(value: &Value, path: &str) -> Option<Value> {
    let path = path.strip_prefix('/').unwrap_or(path);
    eval_tokens(value, &path.split('/').collect::<Vec<_>>())
}

fn eval_tokens(value: &Value, tokens: &[&str]) -> Option<Value> {
    let Some((token, rest)) = tokens.split_first() else {
        return Some(value.clone());
    };
    // JSON pointer escapes (~0 → ~, ~1 → /).
    let token = token.replace("~1", "/").replace("~0", "~");

    match value {
        Value::Array(items) if token == "*" => {
            let mut flattened = Vec::new();
            for item in items {
                match eval_tokens(item, rest)? {
                    Value::Array(inner) => flattened.extend(inner),
                    other => flattened.push(other),
                }
            }
            Some(Value::Array(flattened))
        }
        Value::Array(items) => {
            let index: usize = token.parse().ok()?;
            eval_tokens(items.get(index)?, rest)
        }
        Value::Object(map) if token == "*" => {
            let mut flattened = Vec::new();
            for (_k, item) in map {
                match eval_tokens(item, rest)? {
                    Value::Array(inner) => flattened.extend(inner),
                    other => flattened.push(other),
                }
            }
            Some(Value::Array(flattened))
        }
        Value::Object(map) => eval_tokens(map.get(token.as_str())?, rest),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn prior() -> Vec<Invocation> {
        vec![Invocation(
            "Foo/query".to_owned(),
            json!({
                "accountId": "a1",
                "ids": ["id1", "id2", "id3"],
                "list": [
                    {"id": "t1", "emailIds": ["e1", "e2"]},
                    {"id": "t2", "emailIds": ["e3"]},
                ],
            }),
            "c0".to_owned(),
        )]
    }

    fn prior_with_object() -> Vec<Invocation> {
        vec![Invocation(
            "Foo/list".to_owned(),
            json!({
                "by_tag": {
                    "important": ["id1", "id2"],
                    "spam": ["id3"],
                }
            }),
            "c0".to_owned(),
        )]
    }

    #[test]
    fn plain_pointer() {
        let args = json!({
            "accountId": "a1",
            "#ids": {"resultOf": "c0", "name": "Foo/query", "path": "/ids"},
        });
        let resolved = resolve_references(args, &prior()).expect("resolve");
        assert_eq!(resolved["ids"], json!(["id1", "id2", "id3"]));
        assert_eq!(resolved["accountId"], json!("a1"));
        assert!(resolved.get("#ids").is_none());
    }

    #[test]
    fn wildcard_flattens() {
        let args = json!({
            "#ids": {"resultOf": "c0", "name": "Foo/query", "path": "/list/*/emailIds"},
        });
        let resolved = resolve_references(args, &prior()).expect("resolve");
        assert_eq!(resolved["ids"], json!(["e1", "e2", "e3"]));
    }

    #[test]
    fn wildcard_against_object_flattens_values() {
        let args = json!({
            "#ids": {"resultOf": "c0", "name": "Foo/list", "path": "/by_tag/*"},
        });
        let resolved = resolve_references(args, &prior_with_object()).expect("resolve");
        // Per RFC 8620 §3.7: wildcard on an object applies to all values
        // and flattens one level of arrays.
        assert_eq!(resolved["ids"], json!(["id1", "id2", "id3"]));
    }

    #[test]
    fn missing_source_is_an_error() {
        let args = json!({
            "#ids": {"resultOf": "nope", "name": "Foo/query", "path": "/ids"},
        });
        assert!(matches!(
            resolve_references(args, &prior()),
            Err(MethodError::InvalidResultReference(_))
        ));
    }

    #[test]
    fn duplicate_plain_and_reference_key_is_an_error() {
        let args = json!({
            "ids": ["x"],
            "#ids": {"resultOf": "c0", "name": "Foo/query", "path": "/ids"},
        });
        assert!(matches!(
            resolve_references(args, &prior()),
            Err(MethodError::InvalidArguments(_))
        ));
    }

    #[test]
    fn bad_path_is_an_error() {
        let args = json!({
            "#ids": {"resultOf": "c0", "name": "Foo/query", "path": "/nope/deeper"},
        });
        assert!(matches!(
            resolve_references(args, &prior()),
            Err(MethodError::InvalidResultReference(_))
        ));
    }

    #[test]
    fn reference_with_unknown_field_is_an_error() {
        let args = json!({
            "#ids": {"resultOf": "c0", "name": "Foo/query", "path": "/ids", "extra": 1},
        });
        assert!(matches!(
            resolve_references(args, &prior()),
            Err(MethodError::InvalidResultReference(_))
        ));
    }

    #[test]
    fn json_pointer_escapes() {
        let prior = vec![Invocation(
            "Foo/get".to_owned(),
            json!({"data": {"a/b": 1, "c~d": 2}}),
            "c0".to_owned(),
        )];
        let args = json!({
            "#v": {"resultOf": "c0", "name": "Foo/get", "path": "/data/a~1b"},
        });
        let resolved = resolve_references(args, &prior).expect("resolve");
        assert_eq!(resolved["v"], json!(1));

        let args = json!({
            "#v": {"resultOf": "c0", "name": "Foo/get", "path": "/data/c~0d"},
        });
        let resolved = resolve_references(args, &prior).expect("resolve");
        assert_eq!(resolved["v"], json!(2));
    }
}
