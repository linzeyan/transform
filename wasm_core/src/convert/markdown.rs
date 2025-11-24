// Minimal Markdown ↔ HTML helpers for the converter pair tool (no external crates to keep wasm light).
use regex::Regex;
use std::sync::OnceLock;

/// Converts a subset of Markdown into simple HTML, keeping output deterministic for previews.
///
/// # Example
/// ```
/// use wasm_core::convert::markdown::markdown_to_html;
/// let html = markdown_to_html("# Title")?;
/// assert!(html.contains("<h1>Title</h1>"));
/// # Ok::<(), String>(())
/// ```
pub fn markdown_to_html(input: &str) -> Result<String, String> {
    let normalized = input.replace("\r\n", "\n");
    let lines: Vec<&str> = normalized.lines().collect();
    let mut result = String::new();
    let mut in_list = false;
    let mut in_code_block = false;
    for (idx, raw_line) in lines.iter().enumerate() {
        let raw_line = *raw_line;
        let line = raw_line.trim_end();
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            if in_code_block {
                result.push_str("</code></pre>\n");
                in_code_block = false;
            } else {
                result.push_str("<pre><code>");
                in_code_block = true;
            }
            continue;
        }
        if in_code_block {
            result.push_str(&html_escape(raw_line));
            result.push('\n');
            continue;
        }
        if trimmed.is_empty() {
            if in_list {
                result.push_str("</ul>\n");
                in_list = false;
            }
            continue;
        }
        if trimmed.starts_with("- ") || trimmed.starts_with("* ") {
            if !in_list {
                result.push_str("<ul>\n");
                in_list = true;
            }
            let item = trimmed[2..].trim();
            result.push_str("<li>");
            result.push_str(&apply_inline_markdown(item));
            result.push_str("</li>\n");
            continue;
        }
        if in_list {
            result.push_str("</ul>\n");
            in_list = false;
        }
        let heading = markdown_heading_level(trimmed);
        if heading > 0 {
            let content = trimmed[heading..].trim();
            result.push_str(&format!(
                "<h{level}>{content}</h{level}>\n",
                level = heading,
                content = apply_inline_markdown(content)
            ));
            continue;
        }
        if idx + 1 < lines.len() && lines[idx + 1].trim().is_empty() {
            result.push_str("<p>");
            result.push_str(&apply_inline_markdown(trimmed));
            result.push_str("</p>\n");
            continue;
        }
        result.push_str(&apply_inline_markdown(trimmed));
        result.push('\n');
    }
    if in_list {
        result.push_str("</ul>\n");
    }
    if in_code_block {
        result.push_str("</code></pre>\n");
    }
    Ok(result)
}

fn markdown_heading_level(line: &str) -> usize {
    let mut count = 0;
    for ch in line.chars() {
        if ch == '#' {
            count += 1;
        } else {
            break;
        }
    }
    count.min(6)
}

fn apply_inline_markdown(text: &str) -> String {
    let mut out = html_escape(text);
    out = replace_delimited(&out, "**", "<strong>", "</strong>");
    out = replace_delimited(&out, "*", "<em>", "</em>");
    out = replace_delimited(&out, "`", "<code>", "</code>");
    convert_markdown_links(&out)
}

fn replace_delimited(text: &str, marker: &str, open: &str, close: &str) -> String {
    let parts: Vec<&str> = text.split(marker).collect();
    if parts.len() < 2 {
        return text.to_string();
    }
    let mut out = String::new();
    for (idx, part) in parts.iter().enumerate() {
        if idx % 2 == 1 {
            out.push_str(open);
            out.push_str(part);
            out.push_str(close);
        } else {
            out.push_str(part);
        }
    }
    out
}

fn convert_markdown_links(text: &str) -> String {
    let mut result = text.to_string();
    let mut start = 0;
    while let Some(idx) = result[start..].find('[') {
        let absolute = start + idx;
        if let Some(close) = result[absolute..].find(']') {
            let mid = absolute + close;
            if mid + 1 >= result.len() || result.as_bytes()[mid + 1] != b'(' {
                start = mid + 1;
                continue;
            }
            if let Some(end) = result[mid + 2..].find(')') {
                let end_idx = mid + 2 + end;
                let label = &result[absolute + 1..mid];
                let href = &result[mid + 2..end_idx];
                let replacement = format!(
                    "<a href=\"{}\">{}</a>",
                    html_escape(href),
                    html_escape(label)
                );
                result = format!(
                    "{}{}{}",
                    &result[..absolute],
                    replacement,
                    &result[end_idx + 1..]
                );
                start = absolute + replacement.len();
                continue;
            }
        }
        start = absolute + 1;
    }
    result
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn html_unescape(input: &str) -> String {
    input
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Converts basic HTML back into Markdown headings/paragraphs/lists used by the UI.
///
/// # Example
/// ```
/// use wasm_core::convert::markdown::html_to_markdown;
/// let md = html_to_markdown("<ul><li>Item</li></ul>")?;
/// assert!(md.contains("- Item"));
/// # Ok::<(), String>(())
/// ```
pub fn html_to_markdown(input: &str) -> Result<String, String> {
    let mut text = input.replace("\r\n", "\n");
    text = regex_script().replace_all(&text, "").to_string();
    text = regex_style().replace_all(&text, "").to_string();
    text = regex_code_block()
        .replace_all(&text, |caps: &regex::Captures| {
            let inner = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            format!("```\n{}\n```\n\n", html_unescape(inner.trim()))
        })
        .to_string();
    text = regex_break().replace_all(&text, "\n").to_string();
    text = regex_heading()
        .replace_all(&text, |caps: &regex::Captures| {
            let level = caps
                .get(1)
                .and_then(|m| m.as_str().parse::<usize>().ok())
                .unwrap_or(1)
                .clamp(1, 6);
            let content = html_unescape_caps(caps.get(2));
            format!(
                "{hashes} {content}\n\n",
                hashes = "#".repeat(level),
                content = content.trim()
            )
        })
        .to_string();
    text = regex_paragraph().replace_all(&text, "\n$1\n\n").to_string();
    text = regex_div().replace_all(&text, "\n$1\n").to_string();
    text = regex_list_item().replace_all(&text, "\n- $1").to_string();
    text = text.replace("</ul>", "\n\n");
    text = text.replace("</ol>", "\n\n");
    text = regex_strong().replace_all(&text, "**$1**").to_string();
    text = regex_em().replace_all(&text, "*$1*").to_string();
    text = regex_inline_code().replace_all(&text, "`$1`").to_string();
    text = regex_link()
        .replace_all(&text, |caps: &regex::Captures| {
            let href = html_unescape_caps(caps.get(1));
            let label = strip_tags(&html_unescape_caps(caps.get(2)));
            format!("[{label}]({href})")
        })
        .to_string();
    text = regex_tag().replace_all(&text, "").to_string();
    let unescaped = html_unescape(&text);
    let lines: Vec<&str> = unescaped.lines().collect();
    let mut compact = Vec::new();
    for line in lines {
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            if compact.last().map(|l: &&str| l.is_empty()).unwrap_or(false) {
                continue;
            }
            compact.push("");
        } else {
            compact.push(trimmed);
        }
    }
    Ok(compact.join("\n").trim().to_string())
}

fn html_unescape_caps(mat: Option<regex::Match<'_>>) -> String {
    mat.map(|m| html_unescape(m.as_str())).unwrap_or_default()
}

fn strip_tags(text: &str) -> String {
    regex_tag()
        .replace_all(text, "")
        .to_string()
        .trim()
        .to_string()
}

fn regex_script() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<script[^>]*>.*?</script>").unwrap())
}

fn regex_style() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<style[^>]*>.*?</style>").unwrap())
}

fn regex_heading() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<h([1-6])[^>]*>(.*?)</h[1-6]>").unwrap())
}

fn regex_paragraph() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<p[^>]*>(.*?)</p>").unwrap())
}

fn regex_div() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<div[^>]*>(.*?)</div>").unwrap())
}

fn regex_list_item() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<li[^>]*>(.*?)</li>").unwrap())
}

fn regex_strong() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<(?:strong|b)[^>]*>(.*?)</(?:strong|b)>").unwrap())
}

fn regex_em() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<(?:em|i)[^>]*>(.*?)</(?:em|i)>").unwrap())
}

fn regex_code_block() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<pre[^>]*><code[^>]*>(.*?)</code></pre>").unwrap())
}

fn regex_inline_code() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<code[^>]*>(.*?)</code>").unwrap())
}

fn regex_link() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?is)<a[^>]*href=["'](.*?)["'][^>]*>(.*?)</a>"#).unwrap())
}

fn regex_break() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<br\s*/?>").unwrap())
}

fn regex_tag() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?is)<[^>]+>").unwrap())
}
