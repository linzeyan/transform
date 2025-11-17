use json2toon_rs::{DecoderOptions, EncoderOptions, decode as toon_decode, encode as toon_encode};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_between_json_and_toon() {
        let payload = json!({
            "users": [
                {"id": 1, "name": "Ada"},
                {"id": 2, "name": "Bob"}
            ]
        });
        let json_text = serde_json::to_string(&payload).unwrap();
        let toon = json_to_toon(&json_text).expect("able to encode TOON");
        assert!(toon.contains("users"));
        let json_back = toon_to_json(&toon).expect("able to decode back to JSON");
        let parsed: Value = serde_json::from_str(&json_back).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn decode_known_toon_snippet() {
        let toon = "users[2]{id,name}:\n  1,Ada\n  2,Bob";
        let json_back = toon_to_json(toon).expect("decode static TOON");
        let parsed: Value = serde_json::from_str(&json_back).unwrap();
        assert_eq!(
            parsed,
            json!({
                "users": [
                    {"id": 1, "name": "Ada"},
                    {"id": 2, "name": "Bob"}
                ]
            })
        );
    }

    #[test]
    fn invalid_json_payload_is_rejected() {
        assert!(json_to_toon("not valid json").is_err());
    }
}
