// Base64-wrapped MsgPack encoder/decoder to align with the UI transport format.
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use crate::convert::json_utils::{encode_json, parse_json};

/// Encodes JSON into MsgPack and returns a Base64 string the UI can transport.
///
/// # Example
/// ```
/// use wasm_core::convert::msgpack::json_to_msgpack;
/// let encoded = json_to_msgpack("{\"hello\":\"world\"}")?;
/// assert!(!encoded.is_empty());
/// # Ok::<(), String>(())
/// ```
pub fn json_to_msgpack(input: &str) -> Result<String, String> {
    let value = parse_json(input)?;
    let bytes = rmp_serde::to_vec(&value).map_err(|err| err.to_string())?;
    Ok(STANDARD.encode(bytes))
}

/// Decodes Base64-wrapped MsgPack back into pretty-printed JSON.
pub fn msgpack_to_json(input: &str) -> Result<String, String> {
    let raw = STANDARD
        .decode(input.trim())
        .map_err(|err| err.to_string())?;
    let value: Value = rmp_serde::from_slice(&raw).map_err(|err| err.to_string())?;
    encode_json(&value, false)
}
