use std::collections::HashMap;
use std::sync::OnceLock;

use wasm_bindgen::prelude::*;

// Limit text inputs to keep wasm allocations predictable for the browser host.
const ASCII_MAX_LEN: usize = 256;
const ASCII_MIN_WRAP: u32 = 10;
const ASCII_MAX_WRAP: u32 = 120;
const ASCII_DEFAULT_WIDTH: u32 = 80;

// figlet 2.1's own fonts; their headers allow redistribution.
const FONTS: &[(&str, &str)] = &[
    ("standard", include_str!("../data/figlet/standard.flf")),
    ("slant", include_str!("../data/figlet/slant.flf")),
    ("small", include_str!("../data/figlet/small.flf")),
];

static FONT_CACHE: OnceLock<HashMap<&'static str, Font>> = OnceLock::new();

fn font_map() -> &'static HashMap<&'static str, Font> {
    FONT_CACHE.get_or_init(|| {
        FONTS
            .iter()
            .map(|(name, source)| (*name, Font::parse(source).expect("bundled FIGlet font")))
            .collect()
    })
}

/// A FIGlet font with its hardblanks intact: they are what keeps a word's
/// space from being smushed away, so a parser that turns them into spaces at
/// load time (figlet-rs does) cannot lay text out the way figlet does.
struct Font {
    hardblank: char,
    height: usize,
    layout: Layout,
    glyphs: HashMap<char, Vec<Vec<char>>>,
}

impl Font {
    fn parse(source: &str) -> Result<Self, String> {
        let mut lines = source.lines();
        let header = lines.next().ok_or("empty font")?;
        let fields: Vec<&str> = header.split_whitespace().collect();
        let signature = fields.first().ok_or("missing header")?;
        let hardblank = signature.chars().last().ok_or("missing hardblank")?;
        let number = |i: usize| fields.get(i).and_then(|f| f.parse::<i64>().ok());
        let height = number(1).ok_or("missing height")? as usize;
        let old_layout = number(4).unwrap_or(0);
        let comment_lines = number(5).unwrap_or(0) as usize;
        let full_layout = number(7);
        let layout = layout_of(old_layout, full_layout);
        let mut lines = lines.skip(comment_lines);
        let mut glyphs = HashMap::new();
        let read_glyph = |lines: &mut dyn Iterator<Item = &str>| -> Option<Vec<Vec<char>>> {
            let mut rows = Vec::with_capacity(height);
            for _ in 0..height {
                let line = lines.next()?.trim_end();
                let endmark = line.chars().last()?;
                rows.push(line.trim_end_matches(endmark).chars().collect());
            }
            Some(rows)
        };
        // The required set: ASCII 32..=126, then the seven Deutsch letters.
        let required = (32u32..=126).chain([196, 214, 220, 228, 246, 252, 223]);
        for code in required {
            let rows = read_glyph(&mut lines).ok_or("font ends early")?;
            glyphs.insert(char::from_u32(code).unwrap(), rows);
        }
        // Code-tagged glyphs: a line starting with the code, then the rows.
        while let Some(tag) = lines.next() {
            let code = tag.split_whitespace().next().unwrap_or("");
            let parsed = if let Some(hex) = code.strip_prefix("0x").or(code.strip_prefix("0X")) {
                u32::from_str_radix(hex, 16).ok()
            } else if code.len() > 1 && code.starts_with('0') {
                u32::from_str_radix(&code[1..], 8).ok()
            } else {
                code.parse().ok()
            };
            let Some(rows) = read_glyph(&mut lines) else {
                break;
            };
            if let Some(ch) = parsed.and_then(char::from_u32) {
                glyphs.insert(ch, rows);
            }
        }
        Ok(Self {
            hardblank,
            height: height.max(1),
            layout,
            glyphs,
        })
    }
}

/// How characters meet, from the font header -- what figlet calls the layout.
#[derive(Clone, Copy)]
enum Layout {
    FullWidth,
    Kerning,
    Smushing(u32),
}

fn layout_of(old_layout: i64, full_layout: Option<i64>) -> Layout {
    match full_layout {
        Some(full) if full & 128 != 0 => Layout::Smushing((full & 63) as u32),
        Some(full) if full & 64 != 0 => Layout::Kerning,
        Some(_) => Layout::FullWidth,
        None => match old_layout {
            -1 => Layout::FullWidth,
            0 => Layout::Kerning,
            rules => Layout::Smushing((rules & 63) as u32),
        },
    }
}

struct Renderer<'a> {
    font: &'a Font,
    layout: Layout,
    hardblank: char,
    height: usize,
}

impl<'a> Renderer<'a> {
    fn new(font: &'a Font) -> Self {
        Self {
            font,
            layout: font.layout,
            hardblank: font.hardblank,
            height: font.height,
        }
    }

    fn glyph(&self, ch: char) -> Result<&'a Vec<Vec<char>>, String> {
        self.font.glyphs.get(&ch).ok_or_else(|| {
            format!("this font has no letter for '{ch}': it covers Latin letters, digits and punctuation")
        })
    }

    /// figlet's smushem(): the one character two overlapping ones become, if any.
    fn smush(&self, left: char, right: char, widths: (usize, usize)) -> Option<char> {
        if left == ' ' {
            return Some(right);
        }
        if right == ' ' {
            return Some(left);
        }
        if widths.0 < 2 || widths.1 < 2 {
            return None;
        }
        let Layout::Smushing(rules) = self.layout else {
            return None;
        };
        let hb = self.hardblank;
        if rules == 0 {
            // Universal smushing: the later character wins, hardblanks give way.
            return Some(if left == hb {
                right
            } else if right == hb {
                left
            } else {
                right
            });
        }
        if rules & 32 != 0 && left == hb && right == hb {
            return Some(left);
        }
        if left == hb || right == hb {
            return None;
        }
        if rules & 1 != 0 && left == right {
            return Some(left);
        }
        if rules & 2 != 0 {
            const BORDERS: &str = "|/\\[]{}()<>";
            if left == '_' && BORDERS.contains(right) {
                return Some(right);
            }
            if right == '_' && BORDERS.contains(left) {
                return Some(left);
            }
        }
        if rules & 4 != 0 {
            const CLASSES: [&str; 6] = ["|", "/\\", "[]", "{}", "()", "<>"];
            let class = |c: char| CLASSES.iter().position(|set| set.contains(c));
            if let (Some(l), Some(r)) = (class(left), class(right)) {
                if l < r {
                    return Some(right);
                }
                if r < l {
                    return Some(left);
                }
            }
        }
        if rules & 8 != 0 {
            match (left, right) {
                ('[', ']') | (']', '[') | ('{', '}') | ('}', '{') | ('(', ')') | (')', '(') => {
                    return Some('|');
                }
                _ => {}
            }
        }
        if rules & 16 != 0 {
            match (left, right) {
                ('/', '\\') => return Some('|'),
                ('\\', '/') => return Some('Y'),
                ('>', '<') => return Some('X'),
                _ => {}
            }
        }
        None
    }

    /// figlet's smushamt(): how many columns the next character may slide left.
    /// `None` stands for the end of figlet's C string, past the last column.
    fn overlap(&self, rows: &[Vec<char>], glyph: &[Vec<char>], widths: (usize, usize)) -> usize {
        if matches!(self.layout, Layout::FullWidth) {
            return 0;
        }
        let line_len = rows[0].len();
        let mut amount = widths.1;
        for (line, chars) in rows.iter().zip(glyph) {
            let mut line_end = line_len;
            while line_end > 0 && line.get(line_end).is_none_or(|c| *c == ' ') {
                line_end -= 1;
            }
            let left = line.get(line_end).copied();
            let char_start = chars.iter().position(|c| *c != ' ').unwrap_or(chars.len());
            let mut row_amount = char_start as isize + line_len as isize - 1 - line_end as isize;
            match (left, chars.get(char_start)) {
                (None | Some(' '), _) => row_amount += 1,
                (Some(left), Some(right)) if self.smush(left, *right, widths).is_some() => {
                    row_amount += 1
                }
                _ => {}
            }
            amount = amount.min(row_amount.max(0) as usize);
        }
        amount
    }

    fn render(&self, text: &str) -> Result<Vec<String>, String> {
        let mut rows: Vec<Vec<char>> = vec![Vec::new(); self.height];
        let mut previous_width = 0;
        for ch in text.chars() {
            let glyph = self.glyph(ch)?;
            let width = glyph.iter().map(Vec::len).max().unwrap_or(0);
            let widths = (previous_width, width);
            let amount = self.overlap(&rows, glyph, widths);
            for (line, chars) in rows.iter_mut().zip(glyph) {
                // figlet's addchar(): overlapped columns smush into the line,
                // those left of its start fold into column 0 or vanish when the
                // line is still empty.
                for (k, right) in chars.iter().take(amount).enumerate() {
                    let column = (line.len() + k).saturating_sub(amount);
                    if let Some(left) = line.get(column).copied() {
                        line[column] = self.smush(left, *right, widths).unwrap_or(*right);
                    }
                }
                line.extend(chars.iter().skip(amount));
            }
            previous_width = width;
        }

        Ok(rows
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|c| if c == self.hardblank { ' ' } else { c })
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect())
    }

    fn width(&self, text: &str) -> Result<usize, String> {
        Ok(self
            .render(text)?
            .iter()
            .map(|row| row.chars().count())
            .max()
            .unwrap_or(0))
    }

    /// Greedy word wrap on the width the words take once drawn, which is what
    /// "Wrap at" promises; a word wider than the limit is broken between letters.
    fn wrap(&self, line: &str, limit: usize) -> Result<Vec<String>, String> {
        let mut segments = Vec::new();
        let mut current = String::new();
        for word in line.split(' ').filter(|w| !w.is_empty()) {
            let candidate = if current.is_empty() {
                word.to_string()
            } else {
                format!("{current} {word}")
            };
            if self.width(&candidate)? <= limit {
                current = candidate;
                continue;
            }
            if !current.is_empty() {
                segments.push(std::mem::take(&mut current));
            }
            for ch in word.chars() {
                let candidate = format!("{current}{ch}");
                if !current.is_empty() && self.width(&candidate)? > limit {
                    segments.push(std::mem::take(&mut current));
                    current.push(ch);
                } else {
                    current = candidate;
                }
            }
        }
        if !current.is_empty() {
            segments.push(current);
        }
        Ok(segments)
    }
}

/// Pads every row of one rendered segment by the same amount, as figlet does:
/// rows are drawn as a block, and padding each by its own width shifted the
/// rows whose trailing blanks were trimmed (the top row of "Hi" moved a column).
fn align_block(rows: Vec<String>, target_width: usize, align: &str) -> Vec<String> {
    let width = rows.iter().map(|row| row.len()).max().unwrap_or(0);
    let padding = target_width.saturating_sub(width);
    let left = match align {
        "right" => padding,
        "center" => padding / 2,
        _ => 0,
    };
    rows.into_iter()
        .map(|row| format!("{}{}", " ".repeat(left), row))
        .collect()
}

fn normalize_align(align: Option<&str>) -> &'static str {
    match align.unwrap_or("left").to_ascii_lowercase().as_str() {
        "right" => "right",
        "center" => "center",
        _ => "left",
    }
}

pub(crate) fn list_ascii_fonts_internal() -> Vec<String> {
    FONTS.iter().map(|(name, _)| name.to_string()).collect()
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
    if trimmed.chars().count() > ASCII_MAX_LEN {
        return Err(format!("text must be at most {ASCII_MAX_LEN} characters"));
    }
    let font_map = font_map();
    let normalized_font = font.to_ascii_lowercase();
    let font = font_map
        .get(normalized_font.as_str())
        .ok_or_else(|| format!("unsupported font: {font}"))?;
    let renderer = Renderer::new(font);
    let limit = width
        .unwrap_or(ASCII_DEFAULT_WIDTH)
        .clamp(ASCII_MIN_WRAP, ASCII_MAX_WRAP) as usize;
    let align = normalize_align(align);

    let mut rendered = Vec::new();
    for line in trimmed.lines() {
        // figlet keeps drawn lines strictly narrower than the width
        // (outlinelenlimit = outputwidth - 1); its alignment uses the full width.
        for segment in renderer.wrap(line, limit - 1)? {
            rendered.extend(align_block(renderer.render(&segment)?, limit, align));
        }
    }
    Ok(rendered.join("\n"))
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
