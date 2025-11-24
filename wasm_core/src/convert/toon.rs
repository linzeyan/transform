// TOON (table oriented object notation) bridge so the converter can round-trip spreadsheet-shaped data.
use json2toon_rs::{DecoderOptions, EncoderOptions, decode as toon_decode, encode as toon_encode};
use serde_json::Value;

use crate::convert::json_utils::{encode_json, parse_json};

/// Converts JSON into TOON (table oriented object notation) so spreadsheet-like structures
/// can be previewed and round-tripped in the UI.
pub fn json_to_toon(input: &str) -> Result<String, String> {
    let value = parse_json(input)?;
    Ok(toon_encode(&value, &EncoderOptions::default()))
}

/// Decodes TOON back into pretty-printed JSON.
pub fn toon_to_json(input: &str) -> Result<String, String> {
    let decoded: Value =
        toon_decode(input, &DecoderOptions::default()).map_err(|err| err.to_string())?;
    encode_json(&decoded, false)
}
