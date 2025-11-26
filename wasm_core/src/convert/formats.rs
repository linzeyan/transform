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
        FORMAT_GRAPHQL => format_braced_content(input, minify, false),
        FORMAT_PROTO => format_braced_content(input, minify, true),
        FORMAT_TOON => format_toon_content(input, minify),
        FORMAT_MSGPACK | FORMAT_SCHEMA => {
            // Normalize by JSON round-trip; these are data formats.
            let json_text = convert_formats(format_name, FORMAT_JSON, input)?;
            let normalized_json = {
                let parsed = parse_json(&json_text)?;
                encode_json(&parsed, minify)?
            };
            convert_formats(FORMAT_JSON, format_name, &normalized_json)
        }
        _ => Err("Formatting is not available for this format".into()),
    }
}

// Lightweight formatter for brace-based languages (GraphQL, Protobuf).
fn format_braced_content(
    input: &str,
    minify: bool,
    break_on_semicolon: bool,
) -> Result<String, String> {
    if minify {
        // Collapse whitespace but keep braces, semicolons, and commas meaningful.
        let mut out = String::new();
        let mut last_space = false;
        for ch in input.chars() {
            if ch.is_whitespace() {
                last_space = true;
                continue;
            }
            if matches!(ch, '{' | '}' | ';' | ',' | ':') {
                out.push(ch);
                last_space = false;
                continue;
            }
            if last_space {
                out.push(' ');
                last_space = false;
            }
            out.push(ch);
        }
        return Ok(out);
    }

    let mut lines: Vec<String> = Vec::new();
    let mut indent: i32 = 0;
    for token in tokenize_braced(input, break_on_semicolon) {
        let normalized = normalize_braced_token(&token, break_on_semicolon);
        match normalized.as_str() {
            "}" => {
                indent = (indent - 1).max(0);
                push_line(&mut lines, indent, "}");
            }
            "{" => {
                push_line(&mut lines, indent, "{");
                indent += 1;
            }
            ";" => {
                if let Some(last) = lines.last_mut() {
                    last.push(';');
                } else {
                    push_line(&mut lines, indent, ";");
                }
            }
            t => {
                push_line(&mut lines, indent, t);
            }
        }
    }
    Ok(lines.join("\n"))
}

fn tokenize_braced(input: &str, break_on_semicolon: bool) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut buf = String::new();
    let push_buf = |tokens: &mut Vec<String>, buf: &mut String| {
        let trimmed = buf.trim();
        if !trimmed.is_empty() {
            tokens.push(trimmed.to_string());
        }
        buf.clear();
    };

    for ch in input.chars() {
        match ch {
            '{' | '}' => {
                push_buf(&mut tokens, &mut buf);
                tokens.push(ch.to_string());
            }
            ';' if break_on_semicolon => {
                push_buf(&mut tokens, &mut buf);
                tokens.push(String::from(";"));
            }
            '\n' | '\r' => {
                push_buf(&mut tokens, &mut buf);
            }
            _ => buf.push(ch),
        }
    }
    push_buf(&mut tokens, &mut buf);
    tokens
}

fn push_line(lines: &mut Vec<String>, indent: i32, line: &str) {
    let mut buf = String::new();
    for _ in 0..indent {
        buf.push_str("  ");
    }
    buf.push_str(line.trim());
    lines.push(buf);
}

fn normalize_braced_token(token: &str, break_on_semicolon: bool) -> String {
    let mut out = String::new();
    let mut prev_space = false;
    let mut chars = token.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch.is_whitespace() {
            prev_space = true;
            continue;
        }
        match ch {
            ':' => {
                while out.ends_with(' ') {
                    out.pop();
                }
                out.push(':');
                while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
                    chars.next();
                }
                out.push(' ');
                prev_space = false;
            }
            '=' => {
                if !out.is_empty() && !out.ends_with(' ') {
                    out.push(' ');
                }
                out.push('=');
                while matches!(chars.peek(), Some(c) if c.is_whitespace()) {
                    chars.next();
                }
                out.push(' ');
                prev_space = false;
            }
            ';' if break_on_semicolon => {
                out = out.trim_end().to_string();
                out.push(';');
                prev_space = false;
            }
            _ => {
                if prev_space && !out.ends_with(' ') {
                    out.push(' ');
                }
                out.push(ch);
                prev_space = false;
            }
        }
    }
    out.trim().to_string()
}

fn format_toon_content(input: &str, minify: bool) -> Result<String, String> {
    // Reuse existing TOON converters to normalize structure.
    let json = convert_formats(FORMAT_TOON, FORMAT_JSON, input)?;
    let pretty_json = {
        let value = parse_json(&json)?;
        encode_json(&value, minify)?
    };
    convert_formats(FORMAT_JSON, FORMAT_TOON, &pretty_json)
}
