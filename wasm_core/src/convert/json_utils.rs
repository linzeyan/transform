use serde_json::{Map, Number, Value};

pub fn parse_json(input: &str) -> Result<Value, String> {
    serde_json::from_str(input).map_err(|err| err.to_string())
}

pub fn encode_json(value: &Value, minify: bool) -> Result<String, String> {
    let serialized = if minify {
        serde_json::to_string(value)
    } else {
        serde_json::to_string_pretty(value)
    }
    .map_err(|err| err.to_string())?;
    Ok(serialized.trim_end().to_string())
}

pub fn looks_integer(num: &Number) -> bool {
    if num.is_i64() || num.is_u64() {
        return true;
    }
    let text = num.to_string();
    !(text.contains('.') || text.contains('e') || text.contains('E'))
}

pub fn ordered_keys(map: &Map<String, Value>) -> Vec<String> {
    let mut keys: Vec<String> = map.keys().cloned().collect();
    keys.sort();
    keys
}

pub fn yaml_to_json(value: serde_yaml::Value) -> Value {
    match value {
        serde_yaml::Value::Null => Value::Null,
        serde_yaml::Value::Bool(b) => Value::Bool(b),
        serde_yaml::Value::Number(num) => {
            if let Some(i) = num.as_i64() {
                Value::Number(Number::from(i))
            } else if let Some(u) = num.as_u64() {
                Value::Number(Number::from(u))
            } else if let Some(f) = num.as_f64() {
                Number::from_f64(f)
                    .map(Value::Number)
                    .unwrap_or(Value::Null)
            } else {
                Value::Null
            }
        }
        serde_yaml::Value::String(s) => Value::String(s),
        serde_yaml::Value::Sequence(seq) => {
            let items = seq.into_iter().map(yaml_to_json).collect();
            Value::Array(items)
        }
        serde_yaml::Value::Mapping(map) => {
            let mut obj = Map::new();
            for (k, v) in map.into_iter() {
                let key = match k {
                    serde_yaml::Value::String(s) => s,
                    other => serde_yaml::to_string(&other)
                        .unwrap_or_default()
                        .trim()
                        .to_string(),
                };
                obj.insert(key, yaml_to_json(v));
            }
            Value::Object(obj)
        }
        serde_yaml::Value::Tagged(tagged) => {
            let tagged_value = *tagged;
            yaml_to_json(tagged_value.value)
        }
    }
}

pub fn toml_to_json(value: toml::Value) -> Value {
    match value {
        toml::Value::String(s) => Value::String(s),
        toml::Value::Integer(i) => Value::Number(Number::from(i)),
        toml::Value::Float(f) => Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        toml::Value::Boolean(b) => Value::Bool(b),
        toml::Value::Datetime(dt) => Value::String(dt.to_string()),
        toml::Value::Array(arr) => {
            let items = arr.into_iter().map(toml_to_json).collect();
            Value::Array(items)
        }
        toml::Value::Table(table) => {
            let mut obj = Map::new();
            for (k, v) in table.into_iter() {
                obj.insert(k, toml_to_json(v));
            }
            Value::Object(obj)
        }
    }
}

pub fn json_to_toml(value: &Value) -> Result<toml::Value, String> {
    match value {
        Value::Null => Ok(toml::Value::String(String::new())),
        Value::Bool(b) => Ok(toml::Value::Boolean(*b)),
        Value::Number(num) => {
            if let Some(i) = num.as_i64() {
                Ok(toml::Value::Integer(i))
            } else if let Some(u) = num.as_u64() {
                Ok(toml::Value::Integer(u as i64))
            } else if let Some(f) = num.as_f64() {
                Ok(toml::Value::Float(f))
            } else {
                Err("unsupported number".into())
            }
        }
        Value::String(s) => Ok(toml::Value::String(s.clone())),
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(json_to_toml(item)?);
            }
            Ok(toml::Value::Array(out))
        }
        Value::Object(map) => {
            let mut table = toml::value::Table::new();
            for (k, v) in map.iter() {
                table.insert(k.clone(), json_to_toml(v)?);
            }
            Ok(toml::Value::Table(table))
        }
    }
}
