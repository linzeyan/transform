// Base64-wrapped MsgPack encoder/decoder to align with the UI transport format.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_msgpack() {
        let json = r#"{"hello":"world"}"#;
        let encoded = json_to_msgpack(json).unwrap();
        let back = msgpack_to_json(&encoded).unwrap();
        let v: Value = serde_json::from_str(&back).unwrap();
        assert_eq!(v["hello"], "world");
    }
}
