use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use crate::convert::json_utils::{encode_json, parse_json};

pub fn json_to_msgpack(input: &str) -> Result<String, String> {
    let value = parse_json(input)?;
    let bytes = rmp_serde::to_vec(&value).map_err(|err| err.to_string())?;
    Ok(STANDARD.encode(bytes))
}

pub fn msgpack_to_json(input: &str) -> Result<String, String> {
    let raw = STANDARD
        .decode(input.trim())
        .map_err(|err| err.to_string())?;
    let value: Value = rmp_serde::from_slice(&raw).map_err(|err| err.to_string())?;
    encode_json(&value, false)
}
