// Bidirectional helpers for JSON Schema generation and sampling.
use serde_json::{Map, Value, json};

use crate::convert::json_utils::ordered_keys;

pub fn json_to_schema(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut props = Map::new();
            for key in ordered_keys(map) {
                if let Some(child) = map.get(&key) {
                    props.insert(key.clone(), json_to_schema(child));
                }
            }
            let mut schema = Map::new();
            schema.insert("type".into(), Value::String("object".into()));
            schema.insert("properties".into(), Value::Object(props));
            schema.insert(
                "required".into(),
                Value::Array(ordered_keys(map).into_iter().map(Value::String).collect()),
            );
            Value::Object(schema)
        }
        Value::Array(items) => {
            let sample = items.iter().find(|v| !v.is_null()).or(items.first());
            let schema = sample
                .map(json_to_schema)
                .unwrap_or_else(|| json!({"type": "string"}));
            json!({
                "type": "array",
                "items": schema
            })
        }
        Value::String(_) => json!({"type": "string"}),
        Value::Bool(_) => json!({"type": "boolean"}),
        Value::Number(_) => json!({"type": "number"}),
        Value::Null => json!({"type": "null"}),
    }
}

pub fn schema_to_sample(schema: &Value) -> Value {
    match schema {
        Value::Object(map) => match map.get("type").and_then(|v| v.as_str()) {
            Some("object") => {
                let mut props = Map::new();
                if let Some(Value::Object(children)) = map.get("properties") {
                    for (key, child) in children {
                        props.insert(key.clone(), schema_to_sample(child));
                    }
                }
                Value::Object(props)
            }
            Some("array") => {
                if let Some(items) = map.get("items") {
                    Value::Array(vec![schema_to_sample(items)])
                } else {
                    Value::Array(vec![])
                }
            }
            Some("string") => Value::String(String::new()),
            Some("boolean") => Value::Bool(false),
            Some("integer") => Value::Number(serde_json::Number::from(0)),
            Some("number") => Value::Number(serde_json::Number::from(0)),
            Some("null") => Value::Null,
            _ => Value::Null,
        },
        Value::Array(arr) => {
            if let Some(first) = arr.first() {
                schema_to_sample(first)
            } else {
                Value::Null
            }
        }
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_object_schema_and_sample() {
        let src = json!({"name": "Ada", "age": 30});
        let schema = json_to_schema(&src);
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"].get("name").is_some());
        let sample = schema_to_sample(&schema);
        let text = sample.to_string();
        assert!(text.contains("\"name\""));
    }

    #[test]
    fn builds_array_schema() {
        let src = json!([1, 2, 3]);
        let schema = json_to_schema(&src);
        assert_eq!(schema["type"], "array");
    }
}
