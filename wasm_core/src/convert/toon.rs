use json2toon_rs::{decode as toon_decode, encode as toon_encode, DecoderOptions, EncoderOptions};
use serde_json::Value;

use crate::convert::json_utils::{encode_json, parse_json};

pub fn json_to_toon(input: &str) -> Result<String, String> {
    let value = parse_json(input)?;
    Ok(toon_encode(&value, &EncoderOptions::default()))
}

pub fn toon_to_json(input: &str) -> Result<String, String> {
    let decoded: Value =
        toon_decode(input, &DecoderOptions::default()).map_err(|err| err.to_string())?;
    encode_json(&decoded, false)
}
