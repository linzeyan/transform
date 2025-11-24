//! Format conversion helpers.
//!
//! This module mirrors the "Format Converter" workspace from the Go version.
//! Every format exposed in the UI (JSON, YAML, TOON, MsgPack, GraphQL schema,
//! etc.) is normalized through JSON so we can deterministically round-trip
//! between representations. The implementation intentionally sticks to the
//! concrete syntax described in the spec excerpt shared earlier in the session.
//!
//! # Examples
//!
//! ```rust
//! use wasm_core::convert::formats::convert_formats;
//!
//! let toon = convert_formats("JSON", "TOON", r#"{"name":"Ada"}"#)?;
//! assert_eq!(toon.trim(), "name: Ada");
//! ```
//!
//! ```rust
//! use wasm_core::convert::formats::format_content;
//!
//! let pretty = format_content("JSON", "{\"a\":1}", false)?;
//! assert_eq!(pretty, "{\n  \"a\": 1\n}\n");
//! ```
use crate::convert::json_utils::{
    encode_json, json_to_toml, parse_json, toml_to_json, yaml_to_json,
};
use crate::convert::schema::{json_to_schema, schema_to_sample};
use crate::convert::{go_struct, graphql, msgpack, proto, toon, xml};

const FORMAT_JSON: &str = "JSON";
const FORMAT_YAML: &str = "YAML";
const FORMAT_TOML: &str = "TOML";
const FORMAT_XML: &str = "XML";
const FORMAT_SCHEMA: &str = "JSON Schema";
const FORMAT_GO_STRUCT: &str = "Go Struct";
const FORMAT_TOON: &str = "TOON";
const FORMAT_MSGPACK: &str = "MsgPack";
const FORMAT_GRAPHQL: &str = "GraphQL Schema";
const FORMAT_PROTO: &str = "Protobuf";

/// Converts between supported structured-text formats (JSON, YAML, TOML, XML, JSON Schema,
/// Go structs, TOON, MsgPack, GraphQL schema, and Protobuf).
///
/// All conversions pass through JSON internally so failures surface early with a single
/// error type. Handy for the web UI where users paste arbitrary snippets.
///
/// # Examples
/// ```
/// use wasm_core::convert::formats::convert_formats;
///
/// let yaml = convert_formats("JSON", "YAML", "{\"id\":1}")?;
/// let back = convert_formats("YAML", "JSON", &yaml)?;
/// assert!(back.contains("\"id\": 1"));
/// # Ok::<(), String>(())
/// ```
pub fn convert_formats(from: &str, to: &str, input: &str) -> Result<String, String> {
    if from == to {
        return Ok(input.to_string());
    }
    let value = match from {
        FORMAT_JSON => parse_json(input)?,
        FORMAT_YAML => yaml_to_json(serde_yaml::from_str(input).map_err(|err| err.to_string())?),
        FORMAT_TOML => toml_to_json(
            input
                .parse::<toml::Value>()
                .map_err(|err| err.to_string())?,
        ),
        FORMAT_XML => {
            let json_text = xml::xml_to_json(input)?;
            parse_json(&json_text)?
        }
        FORMAT_SCHEMA => {
            let schema_value = parse_json(input)?;
            schema_to_sample(&schema_value)
        }
        FORMAT_GO_STRUCT => go_struct::go_struct_to_value(input)?,
        FORMAT_MSGPACK => {
            let json = msgpack::msgpack_to_json(input)?;
            parse_json(&json)?
        }
        FORMAT_TOON => {
            let json = toon::toon_to_json(input)?;
            parse_json(&json)?
        }
        FORMAT_GRAPHQL => {
            let json = graphql::graphql_to_json(input)?;
            parse_json(&json)?
        }
        FORMAT_PROTO => {
            let json = proto::proto_to_json(input)?;
            parse_json(&json)?
        }
        _ => return Err(format!("Unsupported source format: {from}")),
    };
    match to {
        FORMAT_JSON => encode_json(&value, false),
        FORMAT_YAML => serde_yaml::to_string(&value).map_err(|err| err.to_string()),
        FORMAT_TOML => {
            let toml_value = json_to_toml(&value)?;
            toml::to_string(&toml_value).map_err(|err| err.to_string())
        }
        FORMAT_XML => {
            let json_text = encode_json(&value, false)?;
            xml::json_to_xml(&json_text)
        }
        FORMAT_SCHEMA => {
            let schema = json_to_schema(&value);
            serde_json::to_string_pretty(&schema).map_err(|err| err.to_string())
        }
        FORMAT_GO_STRUCT => Ok(go_struct::json_value_to_go(&value)),
        FORMAT_MSGPACK => {
            let json = encode_json(&value, false)?;
            msgpack::json_to_msgpack(&json)
        }
        FORMAT_TOON => {
            let json = encode_json(&value, false)?;
            toon::json_to_toon(&json)
        }
        FORMAT_GRAPHQL => {
            let json = encode_json(&value, false)?;
            graphql::json_to_graphql(&json)
        }
        FORMAT_PROTO => {
            let json = encode_json(&value, false)?;
            proto::json_to_proto(&json)
        }
        _ => Err(format!("Unsupported target format: {to}")),
    }
}

/// Pretty-prints or minifies textual formats exposed in the converter UI.
///
/// JSON/YAML/TOML are normalized via JSON to keep spacing deterministic. XML and
/// Go structs are returned trimmed. Unsupported formats yield an `Err`.
///
/// # Examples
/// ```
/// use wasm_core::convert::formats::format_content;
/// let minified = format_content("JSON", "{ \"a\": 1 }", true)?;
/// assert_eq!(minified, "{\"a\":1}");
/// # Ok::<(), String>(())
/// ```
pub fn format_content(format_name: &str, input: &str, minify: bool) -> Result<String, String> {
    match format_name {
        FORMAT_JSON => {
            let value = parse_json(input)?;
            encode_json(&value, minify)
        }
        FORMAT_YAML => {
            let value = yaml_to_json(serde_yaml::from_str(input).map_err(|err| err.to_string())?);
            let formatted = encode_json(&value, minify)?;
            let repro = parse_json(&formatted)?;
            serde_yaml::to_string(&repro).map_err(|err| err.to_string())
        }
        FORMAT_TOML => {
            let value = toml_to_json(
                input
                    .parse::<toml::Value>()
                    .map_err(|err| err.to_string())?,
            );
            let formatted = encode_json(&value, minify)?;
            let repro = parse_json(&formatted)?;
            let toml_value = json_to_toml(&repro)?;
            toml::to_string(&toml_value).map_err(|err| err.to_string())
        }
        FORMAT_XML => {
            let json_text = xml::xml_to_json(input)?;
            xml::json_to_xml(&json_text)
        }
        FORMAT_GO_STRUCT => Ok(input.trim().to_string()),
        _ => Err("Formatting is not available for this format".into()),
    }
}
