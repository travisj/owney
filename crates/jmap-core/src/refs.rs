//! Result references (RFC 8620 §3.7): a request argument named `#foo`
//! containing `{resultOf, name, path}` is replaced by the value extracted
//! from a previous method response via a JSON-pointer-like path where `*`
//! flattens arrays.

use serde::Deserialize;
use serde_json::Value;

use crate::envelope::{Invocation, MethodError};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
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
}
