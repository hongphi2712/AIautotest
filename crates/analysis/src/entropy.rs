//! Shannon-entropy scanning for credential-like values that have no fixed
//! pattern (custom API tokens, opaque session secrets) which regex tiers miss.
//!
//! Tiered-detection research places entropy analysis directly after regex
//! matching: machine-generated tokens land around 4.7-5.5 bits/char while
//! human-readable text stays below 4.0. Sampling caps matter: a string of
//! length L cannot exceed log2(L) bits/char, so short candidates (~28-40
//! chars) need near-unique characters to qualify - structured formats such as
//! JWTs stay covered by their dedicated rules instead.
//!
//! Precision guards (tuned against real captures full of MongoDB ObjectIds):
//! pure-hex lengths 24/32/40/64 (ObjectId, MD5, SHA-1, SHA-256) and UUID-shaped
//! values are excluded, as are well-known benign key families (`id`, `hash`,
//! `etag`, ...).

use serde_json::Value;

/// Upper bound on visited JSON nodes per body so adversarial payloads cannot
/// turn the walk into an unbounded operation.
const MAX_VISITED_NODES: usize = 20_000;

/// Key-name fragments excluded from entropy candidacy; they overwhelmingly
/// hold benign identifiers, hashes, cursors or timestamps rather than creds.
/// Media/base64 keys are excluded because image payloads measure high entropy
/// while never being credentials.
const EXCLUDED_KEY_FRAGMENTS: &[&str] = &[
    "id", "hash", "etag", "checksum", "digest", "cursor", "slug", "nonce",
    "csrf", "state", "date", "time", "fingerprint", "avatar", "image",
    "photo", "thumb", "icon", "logo", "attachment", "blob", "classname",
    "class_name", "__html", "html",
];

/// A string value whose measured randomness suggests a generated credential.
#[derive(Debug, Clone, PartialEq)]
pub struct EntropyFinding {
    /// Dotted path inside the JSON tree, e.g. `result.data[0].access_token`.
    pub key_path: String,
    pub value_len: usize,
    pub entropy_bits: f64,
}

/// Shannon entropy in bits per byte over the UTF-8 encoding of `text`.
pub fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut frequencies = [0u32; 256];
    let mut total = 0usize;
    for byte in text.as_bytes() {
        frequencies[*byte as usize] += 1;
        total += 1;
    }
    let total_f = total as f64;
    frequencies
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / total_f;
            -probability * probability.log2()
        })
        .sum()
}

/// Walks a JSON tree collecting string values that look like generated
/// credentials. Results are ordered strongest-first and capped at
/// `max_findings`; the walk itself is bounded by `MAX_VISITED_NODES`.
pub fn scan_high_entropy_values(
    root: &Value,
    min_length: usize,
    min_bits: f64,
    max_findings: usize,
) -> Vec<EntropyFinding> {
    let mut state = ScanState {
        findings: Vec::new(),
        visited: 0,
        min_length,
        min_bits,
        max_findings,
    };
    walk(root, "", &mut state);
    state.findings.sort_by(|a, b| {
        b.entropy_bits
            .partial_cmp(&a.entropy_bits)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    state.findings.truncate(max_findings);
    state.findings
}

struct ScanState {
    findings: Vec<EntropyFinding>,
    visited: usize,
    min_length: usize,
    min_bits: f64,
    max_findings: usize,
}

fn walk(value: &Value, path: &str, state: &mut ScanState) {
    if state.visited >= MAX_VISITED_NODES || state.findings.len() >= state.max_findings {
        return;
    }
    state.visited += 1;
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if state.visited >= MAX_VISITED_NODES
                    || state.findings.len() >= state.max_findings
                {
                    return;
                }
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                match child {
                    Value::String(text) => {
                        state.visited += 1;
                        if !is_excluded_key(key) && is_candidate(text, state.min_length, state.min_bits) {
                            state.findings.push(EntropyFinding {
                                key_path: child_path,
                                value_len: text.chars().count(),
                                entropy_bits: shannon_entropy(text),
                            });
                        }
                    }
                    Value::Object(_) | Value::Array(_) => walk(child, &child_path, state),
                    _ => {}
                }
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                if state.visited >= MAX_VISITED_NODES
                    || state.findings.len() >= state.max_findings
                {
                    return;
                }
                walk(child, &format!("{path}[{index}]"), state);
            }
        }
        _ => {}
    }
}

fn is_candidate(text: &str, min_length: usize, min_bits: f64) -> bool {
    if text.chars().count() < min_length {
        return false;
    }
    if is_uuid_shaped(text) || is_common_hash_hex(text) {
        return false;
    }
    shannon_entropy(text) >= min_bits
}

/// Crate-internal predicate for the overfetching analyzer: does this
/// key/value pair qualify as a high-entropy credential candidate?
pub(crate) fn pair_is_candidate(key: &str, text: &str, min_length: usize, min_bits: f64) -> bool {
    !is_excluded_key(key)
        && !text.starts_with("data:")
        && is_candidate(text, min_length, min_bits)
}

fn is_excluded_key(key: &str) -> bool {
    let lowered = key.to_lowercase();
    EXCLUDED_KEY_FRAGMENTS
        .iter()
        .any(|fragment| lowered.contains(fragment))
}

fn is_uuid_shaped(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(expected, part)| part.len() == *expected && part.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Pure-hex values at canonical hash lengths: MongoDB ObjectId (24), MD5 (32),
/// SHA-1 (40), SHA-256 (64).
fn is_common_hash_hex(value: &str) -> bool {
    matches!(value.len(), 24 | 32 | 40 | 64)
        && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn entropy_basics_match_information_theory() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 0.0);
        // Alternating two symbols: exactly one bit per byte.
        assert!((shannon_entropy("ababababab") - 1.0).abs() < f64::EPSILON);
        // Uniform four-symbol alphabet: exactly two bits per byte.
        assert!((shannon_entropy("abcdabcdabcd") - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn generated_token_clears_threshold_but_prose_does_not() {
        let token = "Zx9Qm2Lp7Vb4Kd8Rn3Wj6Hf5Yt1Cs0AgEu";
        assert!(token.len() >= 28);
        assert!(
            shannon_entropy(token) > 4.6,
            "random-ish token should measure high, got {}",
            shannon_entropy(token)
        );
        let prose = "this is a perfectly normal sentence about nothing";
        assert!(shannon_entropy(prose) < 4.2);
    }

    #[test]
    fn scan_flags_token_and_skips_identifiers() {
        let root = json!({
            "access_token": "Zx9Qm2Lp7Vb4Kd8Rn3Wj6Hf5Yt1Cs0AgEu",
            "_id": "6860c71b7e3751ba29c75cd6",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "session_ref": "8c1f4e2a-9b3d-4c5e-8f6a-7d2e1b0a9c8d",
            "note": "low entropy repeated text value here!!"
        });

        let findings = scan_high_entropy_values(&root, 28, 4.7, 20);

        assert_eq!(findings.len(), 1, "only the token qualifies: {findings:?}");
        assert_eq!(findings[0].key_path, "access_token");
    }

    #[test]
    fn scan_respects_thresholds_and_cap() {
        let token = |seed: u8| {
            seed.to_string()
                + "Zx9Qm2Lp7Vb4Kd8Rn3Wj6Hf5Yt1Cs0AgEuQx9mVb4Lp7"
        };
        let root = json!({
            "tokens": [
                { "secret": token(b'a') },
                { "secret": token(b'b') },
                { "secret": token(b'c') },
                { "secret": token(b'd') }
            ]
        });

        let strict = scan_high_entropy_values(&root, 28, 4.7, 20);
        assert_eq!(strict.len(), 4);

        let capped = scan_high_entropy_values(&root, 28, 4.7, 2);
        assert_eq!(capped.len(), 2);

        let unreachable = scan_high_entropy_values(&root, 28, 5.99, 20);
        assert!(unreachable.is_empty());
    }

    #[test]
    fn common_hashes_and_uuids_are_never_candidates() {
        let root = json!({
            "whatever": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7b8c9d0a1b2c3d4a5b6c7d8e9f0a1b2",
            "other": "A1B2C3D4-E2F3-4A5B-8C9D-0E1F2A3B4C5D"
        });
        let findings = scan_high_entropy_values(&root, 28, 4.7, 20);
        assert!(findings.is_empty());
    }
}
