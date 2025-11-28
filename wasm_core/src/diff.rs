//! Text diff functionality using patience diff algorithm for comparing two texts.
//! Generates git-style diff output with unified format.

use serde::{Deserialize, Serialize};
use similar::{DiffTag, TextDiff};

/// Represents a single line in the diff output
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiffLine {
    /// Line number in the original text (1-indexed), None for additions
    pub old_line: Option<usize>,
    /// Line number in the new text (1-indexed), None for deletions
    pub new_line: Option<usize>,
    /// The content of the line (without the +/- prefix)
    pub content: String,
    /// Type of change
    pub change_type: DiffChangeType,
}

/// Type of change in a diff line
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DiffChangeType {
    /// Line present in both texts (context)
    Context,
    /// Line added in new text
    Addition,
    /// Line removed from old text
    Deletion,
}

/// Result of a text diff operation
#[derive(Serialize, Deserialize, Debug)]
pub struct DiffResult {
    /// Individual diff lines
    pub lines: Vec<DiffLine>,
    /// Summary statistics
    pub stats: DiffStats,
}

/// Statistics about the diff
#[derive(Serialize, Deserialize, Debug)]
pub struct DiffStats {
    /// Number of lines added
    pub additions: usize,
    /// Number of lines deleted
    pub deletions: usize,
    /// Number of context lines
    pub context: usize,
}

/// Configuration for diff generation
#[derive(Debug, Clone)]
pub struct DiffConfig {
    /// Number of context lines around changes (default: 3)
    pub context_lines: usize,
}

impl Default for DiffConfig {
    fn default() -> Self {
        Self { context_lines: 3 }
    }
}

/// Generate a diff between two texts using patience diff algorithm
///
/// # Arguments
/// * `old_text` - The original text
/// * `new_text` - The modified text
/// * `config` - Configuration for diff generation
///
/// # Returns
/// DiffResult containing the diff lines and statistics
pub fn generate_diff(old_text: &str, new_text: &str, _config: &DiffConfig) -> DiffResult {
    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();

    let diff = TextDiff::from_slices(&old_lines, &new_lines);

    let mut lines = Vec::new();
    let mut old_line_num = 1;
    let mut new_line_num = 1;
    let mut additions = 0;
    let mut deletions = 0;
    let mut context = 0;

    for op in diff.ops() {
        match op.tag() {
            DiffTag::Equal => {
                for (i, line) in old_lines[op.old_range()].iter().enumerate() {
                    lines.push(DiffLine {
                        old_line: Some(old_line_num + i),
                        new_line: Some(new_line_num + i),
                        content: line.to_string(),
                        change_type: DiffChangeType::Context,
                    });
                }
                old_line_num += op.old_range().len();
                new_line_num += op.new_range().len();
                context += op.old_range().len();
            }
            DiffTag::Delete => {
                for (i, line) in old_lines[op.old_range()].iter().enumerate() {
                    lines.push(DiffLine {
                        old_line: Some(old_line_num + i),
                        new_line: None,
                        content: line.to_string(),
                        change_type: DiffChangeType::Deletion,
                    });
                }
                old_line_num += op.old_range().len();
                deletions += op.old_range().len();
            }
            DiffTag::Insert => {
                for (i, line) in new_lines[op.new_range()].iter().enumerate() {
                    lines.push(DiffLine {
                        old_line: None,
                        new_line: Some(new_line_num + i),
                        content: line.to_string(),
                        change_type: DiffChangeType::Addition,
                    });
                }
                new_line_num += op.new_range().len();
                additions += op.new_range().len();
            }
            DiffTag::Replace => {
                // Handle replace as delete followed by insert
                for (i, line) in old_lines[op.old_range()].iter().enumerate() {
                    lines.push(DiffLine {
                        old_line: Some(old_line_num + i),
                        new_line: None,
                        content: line.to_string(),
                        change_type: DiffChangeType::Deletion,
                    });
                }
                old_line_num += op.old_range().len();
                deletions += op.old_range().len();

                for (i, line) in new_lines[op.new_range()].iter().enumerate() {
                    lines.push(DiffLine {
                        old_line: None,
                        new_line: Some(new_line_num + i),
                        content: line.to_string(),
                        change_type: DiffChangeType::Addition,
                    });
                }
                new_line_num += op.new_range().len();
                additions += op.new_range().len();
            }
        }
    }

    DiffResult {
        lines,
        stats: DiffStats {
            additions,
            deletions,
            context,
        },
    }
}

/// Generate unified diff format string (similar to git diff)
///
/// # Arguments
/// * `old_text` - The original text
/// * `new_text` - The modified text
/// * `old_name` - Name/label for old text (e.g., "a/file.txt")
/// * `new_name` - Name/label for new text (e.g., "b/file.txt")
/// * `config` - Configuration for diff generation
///
/// # Returns
/// A string containing the unified diff format
pub fn generate_unified_diff(
    old_text: &str,
    new_text: &str,
    old_name: &str,
    new_name: &str,
    config: &DiffConfig,
) -> String {
    let result = generate_diff(old_text, new_text, config);

    if result.lines.is_empty() {
        return String::new();
    }

    let mut output = String::new();

    // Find the range of changed lines
    let changed_lines: Vec<_> = result
        .lines
        .iter()
        .filter(|line| line.change_type != DiffChangeType::Context)
        .collect();

    if changed_lines.is_empty() {
        return String::new();
    }

    // Calculate hunk ranges
    let mut hunks = Vec::new();
    let mut current_hunk_start = None;
    let mut current_hunk_end = None;

    for (i, line) in result.lines.iter().enumerate() {
        if line.change_type != DiffChangeType::Context {
            if current_hunk_start.is_none() {
                // Find context before this change
                let context_start = i.saturating_sub(config.context_lines);
                current_hunk_start = Some(context_start);
            }
            current_hunk_end = Some(i + 1 + config.context_lines);
        }
    }

    if let (Some(start), Some(end)) = (current_hunk_start, current_hunk_end) {
        let hunk_end = std::cmp::min(end, result.lines.len());
        hunks.push((start, hunk_end));
    }

    // Generate unified diff header
    output.push_str(&format!("--- {}\n", old_name));
    output.push_str(&format!("+++ {}\n", new_name));

    for (hunk_start, hunk_end) in hunks {
        let hunk_lines = &result.lines[hunk_start..hunk_end];

        // Find the line numbers for this hunk
        let old_start = hunk_lines
            .iter()
            .find_map(|line| line.old_line)
            .unwrap_or(1);
        let new_start = hunk_lines
            .iter()
            .find_map(|line| line.new_line)
            .unwrap_or(1);

        let old_count = hunk_lines
            .iter()
            .filter(|line| line.old_line.is_some())
            .count();
        let new_count = hunk_lines
            .iter()
            .filter(|line| line.new_line.is_some())
            .count();

        output.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            old_start, old_count, new_start, new_count
        ));

        for line in hunk_lines {
            match line.change_type {
                DiffChangeType::Context => output.push(' '),
                DiffChangeType::Addition => output.push('+'),
                DiffChangeType::Deletion => output.push('-'),
            }
            output.push_str(&line.content);
            output.push('\n');
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_texts() {
        let text = "line 1\nline 2\nline 3";
        let result = generate_diff(text, text, &DiffConfig::default());

        assert_eq!(result.stats.additions, 0);
        assert_eq!(result.stats.deletions, 0);
        assert_eq!(result.stats.context, 3);
        assert_eq!(result.lines.len(), 3);
    }

    #[test]
    fn test_simple_addition() {
        let old = "line 1\nline 2";
        let new = "line 1\nline 2\nline 3";
        let result = generate_diff(old, new, &DiffConfig::default());

        assert_eq!(result.stats.additions, 1);
        assert_eq!(result.stats.deletions, 0);
        assert_eq!(result.lines.len(), 3);

        let addition = result
            .lines
            .iter()
            .find(|line| line.change_type == DiffChangeType::Addition);
        assert!(addition.is_some());
        assert_eq!(addition.unwrap().content, "line 3");
    }

    #[test]
    fn test_simple_deletion() {
        let old = "line 1\nline 2\nline 3";
        let new = "line 1\nline 2";
        let result = generate_diff(old, new, &DiffConfig::default());

        assert_eq!(result.stats.additions, 0);
        assert_eq!(result.stats.deletions, 1);
        assert_eq!(result.lines.len(), 3);

        let deletion = result
            .lines
            .iter()
            .find(|line| line.change_type == DiffChangeType::Deletion);
        assert!(deletion.is_some());
        assert_eq!(deletion.unwrap().content, "line 3");
    }

    #[test]
    fn test_unified_diff_format() {
        let old = "line 1\nline 2\nline 3";
        let new = "line 1\nline 2\nline 4";
        let diff =
            generate_unified_diff(old, new, "a/file.txt", "b/file.txt", &DiffConfig::default());

        assert!(diff.contains("--- a/file.txt"));
        assert!(diff.contains("+++ b/file.txt"));
        assert!(diff.contains("@@"));
        assert!(diff.contains("-line 3"));
        assert!(diff.contains("+line 4"));
    }

    #[test]
    fn test_line_numbers() {
        let old = "line 1\nline 2\nline 3";
        let new = "line 1\nline 2\nline 4";
        let result = generate_diff(old, new, &DiffConfig::default());

        // Check that line numbers are correct
        for line in &result.lines {
            match line.change_type {
                DiffChangeType::Context => {
                    assert!(line.old_line.is_some());
                    assert!(line.new_line.is_some());
                }
                DiffChangeType::Deletion => {
                    assert!(line.old_line.is_some());
                    assert!(line.new_line.is_none());
                }
                DiffChangeType::Addition => {
                    assert!(line.old_line.is_none());
                    assert!(line.new_line.is_some());
                }
            }
        }
    }
}
