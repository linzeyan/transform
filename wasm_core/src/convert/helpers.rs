// Shared name-shaping helpers used by multiple format converters (Structs, GraphQL, Protobuf).
/// Converts an arbitrary key into an exported Go-style identifier (leading letter, camel-cased).
pub fn export_name(key: &str) -> String {
    let mut runes = Vec::new();
    let mut cap_next = true;
    for ch in key.chars() {
        if ch.is_alphanumeric() {
            if cap_next {
                runes.push(ch.to_ascii_uppercase());
                cap_next = false;
            } else {
                runes.push(ch);
            }
        } else {
            cap_next = true;
        }
    }
    let mut out: String = runes.into_iter().collect();
    while let Some(ch) = out.chars().next() {
        if ch.is_alphabetic() || ch == '_' {
            break;
        }
        out.remove(0);
    }
    if let Some(first) = out.chars().next() {
        if first.is_ascii_lowercase() {
            let mut chars: Vec<char> = out.chars().collect();
            chars[0] = first.to_ascii_uppercase();
            out = chars.into_iter().collect();
        }
    }
    out
}

/// Converts a key into snake_case for targets like Protobuf field names.
pub fn snake_name(key: &str) -> String {
    let mut normalized = String::new();
    for ch in key.chars() {
        if ch.is_alphanumeric() {
            normalized.push(ch);
        } else {
            normalized.push('_');
        }
    }
    let mut words: Vec<String> = Vec::new();
    for token in normalized.split('_') {
        for part in split_words(token) {
            if !part.is_empty() {
                words.push(part.to_lowercase());
            }
        }
    }
    if words.is_empty() {
        return "field".into();
    }
    words.join("_")
}

/// Lower-cases the first word of a camel/pascal string while preserving acronyms.
pub fn lower_first(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let words = split_words(s);
    if words.is_empty() {
        return s.to_lowercase();
    }
    let mut result = String::new();
    result.push_str(&words[0].to_lowercase());
    for word in words.iter().skip(1) {
        if word.is_empty() {
            continue;
        }
        if is_all_upper(word) {
            result.push_str(word);
            continue;
        }
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            result.push(first.to_ascii_uppercase());
            result.push_str(&chars.as_str().to_lowercase());
        }
    }
    result
}

/// Splits a string into word-like segments using case changes, digits, and underscores.
pub fn split_words(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = s.chars().peekable();
    current.push(chars.next().unwrap());
    while let Some(&ch) = chars.peek() {
        let prev = current.chars().last().unwrap_or(ch);
        let next_lower = {
            let mut iter = chars.clone();
            iter.next();
            iter.next().is_some_and(|c| c.is_lowercase())
        };
        match ch {
            c if c.is_uppercase() => {
                if prev.is_lowercase()
                    || prev.is_ascii_digit()
                    || (prev.is_uppercase() && next_lower)
                {
                    parts.push(current);
                    current = String::new();
                }
                current.push(ch);
            }
            c if c.is_ascii_digit() => {
                if prev.is_ascii_digit() || prev.is_uppercase() {
                    current.push(ch);
                } else {
                    parts.push(current);
                    current = String::new();
                    current.push(ch);
                }
            }
            _ => {
                if prev.is_ascii_digit() {
                    parts.push(current);
                    current = String::new();
                    current.push(ch);
                } else {
                    current.push(ch);
                }
            }
        }
        chars.next();
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

/// Returns true when the entire string is uppercase (non-letters ignored).
pub fn is_all_upper(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|ch| !ch.is_alphabetic() || ch.is_uppercase())
}
