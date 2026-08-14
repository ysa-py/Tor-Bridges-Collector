//! Deterministic text-list rendering.

use std::collections::BTreeSet;

/// Render bridge lines into a deterministic text-list body.
///
/// Lines are trimmed, empty lines are dropped, exact duplicates are removed,
/// and the survivors are sorted lexicographically. A single trailing newline
/// is appended when `trailing_newline` is set and the body is non-empty.
pub fn render_text_list<'a>(
    lines: impl IntoIterator<Item = &'a str>,
    trailing_newline: bool,
) -> String {
    let unique: BTreeSet<&str> = lines
        .into_iter()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();

    let mut body = String::new();
    for (index, line) in unique.iter().enumerate() {
        if index > 0 {
            body.push('\n');
        }
        body.push_str(line);
    }
    if !body.is_empty() && trailing_newline {
        body.push('\n');
    }
    body
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sorts_dedupes_and_terminates() {
        let rendered = render_text_list(["b line", "a line", "a line", "  b line  "], true);
        assert_eq!(rendered, "a line\nb line\n");
    }

    #[test]
    fn empty_input_renders_empty() {
        assert_eq!(render_text_list(std::iter::empty::<&str>(), true), "");
        assert_eq!(render_text_list(["", "   "], true), "");
    }

    #[test]
    fn trailing_newline_is_optional() {
        assert_eq!(render_text_list(["a"], false), "a");
    }
}
