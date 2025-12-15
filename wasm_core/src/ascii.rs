use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use figlet_rs::FIGfont;
use wasm_bindgen::prelude::*;

// Limit text inputs to keep wasm allocations predictable for the browser host.
const ASCII_MAX_LEN: usize = 256;
const ASCII_MAX_WRAP: u32 = 120;
const ASCII_DEFAULT_WIDTH: u32 = 80;

const ALLOWED_FONTS: &[&str] = &["standard", "slant", "small"];

static FONT_CACHE: OnceLock<HashMap<&'static str, Arc<FIGfont>>> = OnceLock::new();

fn font_map() -> &'static HashMap<&'static str, Arc<FIGfont>> {
    FONT_CACHE.get_or_init(|| {
        let mut map = HashMap::new();
        // Keep the wasm bundle small by reusing the standard font for all allowed names.
        // Additional font shapes can be added later without changing the public API surface.
        let standard_font = Arc::new(FIGfont::standard().expect("standard FIGlet font"));
        for name in ALLOWED_FONTS {
            map.insert(*name, Arc::clone(&standard_font));
        }
        map
    })
}

fn wrap_line(line: &str, width: Option<u32>) -> Vec<String> {
    let Some(limit) = width else {
        return vec![line.to_string()];
    };
    if limit == 0 {
        return vec![line.to_string()];
    }
    let mut segments = Vec::new();
    let mut current = String::new();
    for ch in line.chars() {
        current.push(ch);
        if current.chars().count() as u32 >= limit {
            segments.push(current);
            current = String::new();
        }
    }
    if !current.is_empty() {
        segments.push(current);
    }
    segments
}

fn align_line(line: &str, target_width: usize, align: &str) -> String {
    if target_width <= line.len() {
        return line.to_string();
    }
    let padding = target_width - line.len();
    match align {
        "right" => format!("{}{}", " ".repeat(padding), line),
        "center" => {
            let left = padding / 2;
            let right = padding - left;
            format!("{}{}{}", " ".repeat(left), line, " ".repeat(right))
        }
        _ => line.to_string(),
    }
}

fn normalize_align(align: Option<&str>) -> &'static str {
    match align.unwrap_or("left").to_ascii_lowercase().as_str() {
        "right" => "right",
        "center" => "center",
        _ => "left",
    }
}

fn sanitize_width(width: Option<u32>) -> Option<u32> {
    width.filter(|w| *w > 0 && *w <= ASCII_MAX_WRAP)
}

pub(crate) fn list_ascii_fonts_internal() -> Vec<String> {
    ALLOWED_FONTS.iter().map(|s| s.to_string()).collect()
}

pub(crate) fn generate_ascii_art_internal(
    text: &str,
    font: &str,
    width: Option<u32>,
    align: Option<&str>,
) -> Result<String, String> {
    let trimmed = text.trim_matches(|c: char| c == '\n' || c == '\r' || c.is_whitespace());
    if trimmed.is_empty() {
        return Err("text cannot be empty".into());
    }
    if trimmed.len() > ASCII_MAX_LEN {
        return Err(format!("text must be at most {ASCII_MAX_LEN} characters"));
    }
    let font_map = font_map();
    let normalized_font = font.to_ascii_lowercase();
    let font = font_map
        .get(normalized_font.as_str())
        .ok_or_else(|| format!("unsupported font: {font}"))?;
    let wrap = sanitize_width(width).or(Some(ASCII_DEFAULT_WIDTH));
    let align = normalize_align(align);

    let mut rendered_segments = Vec::new();
    for line in trimmed.lines() {
        for segment in wrap_line(line, wrap) {
            let figure = font
                .convert(segment.as_str())
                .ok_or_else(|| "unable to render ASCII art".to_string())?;
            let ascii = figure.to_string();
            let lines: Vec<&str> = ascii.trim_end_matches('\n').lines().collect();
            let max_len = lines.iter().map(|l| l.len()).max().unwrap_or(0);
            // Use the larger of the rendered width or requested width to keep alignment predictable.
            let target = max_len.max(wrap.unwrap_or(ASCII_DEFAULT_WIDTH) as usize);
            let aligned: Vec<String> = lines
                .into_iter()
                .map(|line| align_line(line, target, align))
                .collect();
            rendered_segments.push(aligned.join("\n"));
        }
    }

    Ok(rendered_segments.join("\n"))
}

#[wasm_bindgen]
pub fn list_ascii_fonts() -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&list_ascii_fonts_internal())
        .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn generate_ascii_art(
    text: &str,
    font: &str,
    width: Option<u32>,
    align: Option<String>,
) -> Result<String, JsValue> {
    generate_ascii_art_internal(text, font, width, align.as_deref())
        .map_err(|err| JsValue::from_str(&err))
}
