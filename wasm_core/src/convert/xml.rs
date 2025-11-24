// Lightweight JSON ↔ XML converter to keep the formatter predictable and dependency-light.
use quick_xml::Reader;
use quick_xml::events::Event;
use serde_json::{Map, Value};

use crate::convert::json_utils::{ordered_keys, parse_json};

/// Converts JSON into a minimal, predictable XML document with a `<root>` wrapper.
pub fn json_to_xml(input: &str) -> Result<String, String> {
    let value = parse_json(input)?;
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    build_xml(&mut out, "root", &value, 0);
    Ok(out)
}

fn build_xml(buf: &mut String, name: &str, value: &Value, depth: usize) {
    let indent = "  ".repeat(depth);
    match value {
        Value::Object(map) => {
            buf.push_str(&format!("{indent}<{name}>\n"));
            for key in ordered_keys(map) {
                if let Some(child) = map.get(&key) {
                    build_xml(buf, &key, child, depth + 1);
                }
            }
            buf.push_str(&format!("{indent}</{name}>\n"));
        }
        Value::Array(items) => {
            for item in items {
                build_xml(buf, name, item, depth);
            }
        }
        _ => {
            let text = match value {
                Value::Null => "null".to_string(),
                Value::Bool(b) => b.to_string(),
                Value::Number(n) => n.to_string(),
                Value::String(s) => s.clone(),
                Value::Array(_) | Value::Object(_) => String::new(),
            };
            buf.push_str(&format!("{indent}<{name}>{}</{name}>\n", xml_escape(&text)));
        }
    }
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Parses a small XML fragment into pretty-printed JSON, grouping repeated tags into arrays.
pub fn xml_to_json(input: &str) -> Result<String, String> {
    let mut reader = Reader::from_str(input);
    reader.trim_text(true);
    let mut buf = Vec::new();
    let mut stack: Vec<XmlElement> = Vec::new();
    let mut root: Option<XmlElement> = None;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(tag)) => {
                let name = tag.name().as_ref().to_vec();
                let node = XmlElement::new(String::from_utf8_lossy(&name).trim().to_string());
                stack.push(node);
            }
            Ok(Event::End(_)) => {
                if let Some(node) = stack.pop() {
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(node);
                    } else {
                        root = Some(node);
                    }
                }
            }
            Ok(Event::Text(text)) => {
                if let Some(current) = stack.last_mut() {
                    current
                        .value
                        .push_str(text.unescape().unwrap_or_default().as_ref());
                }
            }
            Ok(Event::Eof) => break,
            Err(err) => return Err(err.to_string()),
            _ => {}
        }
        buf.clear();
    }
    let root = root.ok_or_else(|| "invalid XML".to_string())?;
    let value = element_to_value(&root);
    serde_json::to_string_pretty(&value).map_err(|err| err.to_string())
}

fn element_to_value(el: &XmlElement) -> Value {
    if el.children.is_empty() {
        return Value::String(el.value.trim().to_string());
    }
    let mut obj = Map::new();
    for child in &el.children {
        let entry = obj.entry(child.name.clone()).or_insert(Value::Null);
        let value = element_to_value(child);
        if entry.is_null() {
            *entry = value;
        } else if let Value::Array(arr) = entry {
            arr.push(value);
        } else {
            let existing = entry.clone();
            *entry = Value::Array(vec![existing, value]);
        }
    }
    Value::Object(obj)
}

#[derive(Debug, Clone)]
struct XmlElement {
    name: String,
    value: String,
    children: Vec<XmlElement>,
}

impl XmlElement {
    fn new(name: String) -> Self {
        Self {
            name,
            value: String::new(),
            children: Vec::new(),
        }
    }
}
