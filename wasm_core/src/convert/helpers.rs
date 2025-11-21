// Shared name-shaping helpers used by multiple format converters (Structs, GraphQL, Protobuf).
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
        } else if ch == '_' {
            runes.push('_');
            cap_next = true;
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
    out
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_name_cleans_symbols() {
        // Leading non-letters are stripped; underscores preserve next-capital behavior.
        assert_eq!(export_name("123foo_bar"), "foo_Bar");
    }

    #[test]
    fn lower_first_handles_pascal_case() {
        assert_eq!(lower_first("UserName"), "userName");
    }
}

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

pub fn is_all_upper(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|ch| !ch.is_alphabetic() || ch.is_uppercase())
}
