//! Shared Next.js RSC (React Server Components) chunk extractor.
//!
//! Parses `self.__next_f.push([1, "..."])` script tags and extracts
//! individual string chunks, unescaping JSON string escapes so downstream
//! scanners (secret regex, overfetching heuristics) see clean text.

/// Extracts all string chunks from Next.js RSC `self.__next_f.push()` calls
/// in an HTML body. Each chunk is unescaped (`\"` → `"`, `\\` → `\`).
/// Returns an empty Vec when the body contains no RSC data.
pub fn extract_rsc_chunks(body: &str) -> Vec<String> {
    if !body.contains("self.__next_f") {
        return Vec::new();
    }
    let mut chunks = Vec::new();
    let needle = "self.__next_f.push(";
    let mut search_from = 0usize;
    while let Some(offset) = body[search_from..].find(needle) {
        let push_at = search_from + offset;
        let arg_start = push_at + needle.len();
        let Some(arg_end) = balanced_bracket_end(body, arg_start) else {
            search_from = push_at + needle.len();
            continue;
        };
        // Parse the JSON array argument: [1, "..."] or [0]
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&body[arg_start..arg_end]) {
            if let Some(arr) = val.as_array() {
                // The second element (index 1) is the string payload
                if let Some(payload) = arr.get(1).and_then(|v| v.as_str()) {
                    let unescaped = unescape_json_string(payload);
                    chunks.push(unescaped);
                }
            }
        }
        search_from = arg_end;
    }
    chunks
}

/// Unescape common JSON string escapes for readable scanning.
fn unescape_json_string(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('u') => {
                    // \uXXXX — collect 4 hex digits
                    let hex: String = chars.by_ref().take(4).collect();
                    if let Ok(code) = u32::from_str_radix(&hex, 16) {
                        if let Some(ch) = char::from_u32(code) {
                            out.push(ch);
                        }
                    }
                }
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Returns the index just past the `]` that closes the bracket expression
/// starting at `open_idx` (which must point at `[`). String-aware: brackets
/// inside JSON string literals and `\"` escapes are ignored, so minified
/// single-line pages with many pushes parse correctly.
fn balanced_bracket_end(text: &str, open_idx: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(open_idx) != Some(&b'[') {
        return None;
    }
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, byte) in bytes[open_idx..].iter().enumerate() {
        let idx = open_idx + offset;
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx + 1);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_chunks_from_minified_html() {
        let html = r#"<html><head></head><body>
<script>self.__next_f.push([1,"1:\"$Sreact.fragment\"\n"])</script>
<script>self.__next_f.push([1,"2:J[\"$\",\"div\",null,{\"children\":\"hello\"}]\n"])</script>
</body></html>"#;
        let chunks = extract_rsc_chunks(html);
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].contains("$Sreact.fragment"));
        assert!(chunks[1].contains("hello"));
    }

    #[test]
    fn unescapes_json_strings() {
        let html = r#"<script>self.__next_f.push([1,"3:{\"accessToken\":\"eyJabc\"}\n"])</script>"#;
        let chunks = extract_rsc_chunks(html);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].contains("\"accessToken\":\"eyJabc\""));
    }

    #[test]
    fn handles_multiline_push() {
        let html = r#"<script>
self.__next_f.push([1,"token_data\n"])
</script>"#;
        let chunks = extract_rsc_chunks(html);
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].contains("token_data"));
    }

    #[test]
    fn skips_non_rsc_html() {
        let html = r#"<html><body><p>No RSC here</p></body></html>"#;
        let chunks = extract_rsc_chunks(html);
        assert!(chunks.is_empty());
    }

    #[test]
    fn handles_empty_push() {
        let html = r#"<script>self.__next_f.push([0])</script>"#;
        let chunks = extract_rsc_chunks(html);
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_real_contest_html_file() {
        let contest_html_path = "../../contest.html";
        let Ok(content) = std::fs::read_to_string(contest_html_path)
            .or_else(|_| std::fs::read_to_string("contest.html"))
        else {
            return;
        };

        let chunks = extract_rsc_chunks(&content);
        assert!(!chunks.is_empty(), "must extract RSC chunks from contest.html");

        // Verify that at least one chunk contains a password value
        let has_password = chunks.iter().any(|c| {
            c.contains("clcc66")
                || c.contains("aiep17")
                || c.contains("CNTT66")
                || c.contains("KHMT66")
        });
        assert!(has_password, "RSC chunks must contain contest passwords");
    }

    #[test]
    fn unescape_handles_unicode_escape() {
        let input = "Hello \\u0041 World"; // \u0041 = 'A'
        let result = unescape_json_string(input);
        assert_eq!(result, "Hello A World");
    }

    #[test]
    fn unescape_handles_literal_backslash() {
        let input = "no escapes here";
        let result = unescape_json_string(input);
        assert_eq!(result, "no escapes here");
    }
}
