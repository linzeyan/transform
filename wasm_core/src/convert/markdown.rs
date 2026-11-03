// Markdown ↔ HTML for the converter pair tool, as GitHub Flavored Markdown.
// A hand-rolled line converter used to stand here; it knew headings, flat
// bullet lists and three inline marks, and wrote broken attributes for images.

/// Converts GitHub Flavored Markdown into HTML: tables, task lists,
/// strikethrough, autolinks and footnotes included. Raw HTML passes through as
/// in pandoc and cmark-gfm: the output is source text, shown in a textarea and
/// never rendered here, so escaping it would only corrupt the conversion.
///
/// # Example
/// ```
/// use wasm_core::convert::markdown::markdown_to_html;
/// let html = markdown_to_html("# Title")?;
/// assert!(html.contains("<h1>Title</h1>"));
/// # Ok::<(), String>(())
/// ```
pub fn markdown_to_html(input: &str) -> Result<String, String> {
    let mut options = comrak::Options::default();
    options.extension.strikethrough = true;
    options.extension.table = true;
    options.extension.autolink = true;
    options.extension.tasklist = true;
    options.extension.footnotes = true;
    options.render.r#unsafe = true;
    Ok(comrak::markdown_to_html(input, &options))
}

/// Converts HTML into Markdown: headings, lists (nested and ordered), quotes,
/// code, links, images and tables. Scripts and styles are dropped.
///
/// # Example
/// ```
/// use wasm_core::convert::markdown::html_to_markdown;
/// let md = html_to_markdown("<ul><li>Item</li></ul>")?;
/// assert!(md.contains("Item"));
/// # Ok::<(), String>(())
/// ```
pub fn html_to_markdown(input: &str) -> Result<String, String> {
    // htmd writes CommonMark, which has no strikethrough or task lists: without
    // these two, the GFM that markdown_to_html writes lost both on the way back.
    let converter = htmd::HtmlToMarkdown::builder()
        .skip_tags(vec!["script", "style", "head"])
        .add_handler(
            vec!["del", "s", "strike"],
            |handlers: &dyn htmd::element_handler::Handlers, element: htmd::Element| {
                let content = handlers.walk_children(element.node).content;
                let text = content.trim();
                (!text.is_empty()).then(|| format!("~~{text}~~").into())
            },
        )
        .add_handler(
            vec!["input"],
            |_: &dyn htmd::element_handler::Handlers, element: htmd::Element| {
                let attr = |name: &str| {
                    element
                        .attrs
                        .iter()
                        .find(|attr| &*attr.name.local == name)
                        .map(|attr| attr.value.to_string())
                };
                if attr("type").as_deref() != Some("checkbox") {
                    return None;
                }
                Some(
                    if attr("checked").is_some() {
                        "[x]"
                    } else {
                        "[ ]"
                    }
                    .into(),
                )
            },
        )
        .options(htmd::options::Options {
            heading_style: htmd::options::HeadingStyle::Atx,
            code_block_style: htmd::options::CodeBlockStyle::Fenced,
            bullet_list_marker: htmd::options::BulletListMarker::Dash,
            ..Default::default()
        })
        .build();
    converter
        .convert(input)
        .map(|md| md.trim().to_string())
        .map_err(|err| err.to_string())
}
