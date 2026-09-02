//! Generic sensitive-field taxonomy: classifies JSON keys into semantic
//! groups (credentials, tokens, PII, payment, assessment content) so the
//! overfetching analyzer works on ANY target instead of hardcoded literals.
//!
//! Design notes (from industry practice):
//! - Datadog Sensitive Data Scanner groups rules by category with keyword +
//!   pattern pairs; we mirror that with key-fragment matching per group.
//! - A signal only fires when the KEY matches AND the value passes a
//!   validator (non-placeholder, checksum for cards) — Presidio-style
//!   "name + content" confidence boost, cutting false positives hard.
//! - The dictionary is flat-config extensible (`extra_sensitive_keys`) with a
//!   built-in benign-fragment blocklist; a future host→keys profile layer can
//!   wrap `classify_key` without touching detector logic.

/// Semantic groups a field name can belong to.
pub const CREDENTIAL: &str = "credential";
pub const TOKEN: &str = "token";
pub const PII_CONTACT: &str = "pii_contact";
pub const PII_GOV_ID: &str = "pii_gov_id";
pub const PAYMENT: &str = "payment";
pub const ANSWER_CONTENT: &str = "answer_content";
pub const CUSTOM: &str = "custom";

/// Built-in dictionary. Fragments are matched case-insensitively as substrings
/// of the lowercased key.
const GROUPS: &[(&str, &[&str])] = &[
    (
        CREDENTIAL,
        &[
            "password", "passwd", "pwd", "passphrase", "matkhau", "mat_khau",
        ],
    ),
    (
        TOKEN,
        &[
            "token", "api_key", "apikey", "apisecret", "api_secret",
            "client_secret", "bearer", "authorization",
        ],
    ),
    (
        PII_CONTACT,
        &[
            "email", "phone", "mobile", "dienthoai", "dien_thoai",
            "sodienthoai", "so_dien_thoai", "sdt",
        ],
    ),
    (
        PII_GOV_ID,
        &[
            "ssn", "citizen_id", "citizenid", "cccd", "cmnd", "national_id",
            "nationalid", "tax_id", "taxid", "mst", "masothue",
        ],
    ),
    (
        PAYMENT,
        &["card_number", "cardnumber", "card_no", "cardno", "credit_card", "creditcard"],
    ),
    (
        ANSWER_CONTENT,
        &[
            "answer", "solution", "problemstatement", "problem_statement",
            "statement", "question", "exam", "dethi", "de_thi", "debai",
            "de_bai", "dapan", "da_pan", "dap_an",
        ],
    ),
];

/// Key fragments that are benign even though they contain sensitive-sounding
/// substrings — pagination cursors are the classic trap ("nextPageToken"),
/// and CSS's `className` happens to embed "ssn".
const BUILTIN_EXCLUDED: &[&str] = &[
    "cursor", "page_token", "pagetoken", "pagination", "pagestate", "classname",
    "prepare",
];

/// Returns the group id for a lowercased key, honoring user config:
/// `excluded` wins first, then built-in groups, then `extra` keys land in the
/// `custom` group.
pub fn classify_key(lowered_key: &str, extra_keys: &[String], excluded_keys: &[String]) -> Option<&'static str> {
    if is_excluded(lowered_key, excluded_keys) {
        return None;
    }
    for (group, fragments) in GROUPS {
        if fragments
            .iter()
            .any(|fragment| fragment_matches_key(lowered_key, fragment))
        {
            return Some(group);
        }
    }
    if extra_keys.iter().any(|extra| {
        let lowered_extra = extra.to_lowercase();
        lowered_key.contains(&lowered_extra)
            || compact(lowered_key)
                .contains(&compact(&lowered_extra))
    }) {
        return Some(CUSTOM);
    }
    None
}

/// Separator-stripped form so config authors can write natural snake_case
/// (`so_tai_khoan`) while APIs use camel/no-separator variants (`soTaiKhoan`).
fn compact(text: &str) -> String {
    text.chars()
        .filter(|c| *c != '_' && *c != '-')
        .collect()
}

/// Splits a lowercased key into words at separators and camelCase boundaries
/// (`"nextpagetoken"` stays whole; `"so_tai_khoan"` → so/tai/khoan).
fn key_words(lowered: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut previous_kind = CharKind::Other;
    for ch in lowered.chars() {
        let kind = if ch.is_ascii_lowercase() {
            CharKind::Lower
        } else if ch.is_ascii_uppercase() {
            CharKind::Upper
        } else if ch.is_ascii_digit() {
            CharKind::Digit
        } else {
            CharKind::Other
        };
        let boundary = match (previous_kind, kind) {
            (CharKind::Other, _) | (_, CharKind::Other) => true,
            (a, b) => a != b && !(a == CharKind::Lower && b == CharKind::Digit),
        };
        if boundary && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        if kind != CharKind::Other {
            // Normalize camelCase to lowercase for comparison.
            current.push(ch.to_ascii_lowercase());
        }
        previous_kind = kind;
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

#[derive(Clone, Copy, PartialEq)]
enum CharKind {
    Lower,
    Upper,
    Digit,
    Other,
}

/// Long fragments (≥5 chars) are distinctive enough for substring matching;
/// short ones (≤4) require word boundaries so `exam` no longer hides inside
/// `example` and `ssn` inside `className`.
fn fragment_matches_key(lowered_key: &str, fragment: &str) -> bool {
    if fragment.len() >= 5 {
        return lowered_key.contains(fragment);
    }
    key_words(lowered_key)
        .iter()
        .any(|word| word == fragment || word.ends_with(fragment))
}

/// Returns the builtin key fragments for a group id (`classify_key`'s groups).
pub fn fragments_for(group: &str) -> Option<&'static [&'static str]> {
    GROUPS
        .iter()
        .find_map(|(id, fragments)| (*id == group).then_some(*fragments))
}

/// All builtin group ids in declaration order.
pub fn group_ids() -> impl Iterator<Item = &'static str> {
    GROUPS.iter().map(|(id, _)| *id)
}

fn is_excluded(lowered_key: &str, excluded_keys: &[String]) -> bool {
    BUILTIN_EXCLUDED.iter().any(|fragment| lowered_key.contains(fragment))
        || excluded_keys
            .iter()
            .any(|fragment| lowered_key.contains(fragment.to_lowercase().as_str()))
}

/// Credential-like values are collected for evidence; everything else must at
/// least not be an obvious placeholder.
pub fn value_is_meaningful(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() < 4 {
        return false;
    }
    let lowered = trimmed.to_lowercase();
    !matches!(
        lowered.as_str(),
        "null" | "none" | "true" | "false" | "example" | "test" | "changeme"
            | "change_me" | "placeholder" | "<masked>" | "***" | "xxxx" | "n/a" | "na"
    ) && !lowered.starts_with('<')
}

/// Luhn checksum for card-shaped digit strings (spaces/dashes ignored).
/// Regex alone lets ~1 in 10 random digit runs through; the checksum rejects
/// nearly all of them.
pub fn luhn_valid(text: &str) -> bool {
    let digits: Vec<u32> = text
        .chars()
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for digit in digits.iter().rev() {
        let mut value = *digit;
        if double {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
        double = !double;
    }
    sum % 10 == 0
}

/// National-ID digit shapes: CCCD/CMND (9–12 digits), generic tax IDs.
/// Accepts separators; rejects anything with letters or wrong length.
pub fn gov_id_like(text: &str) -> bool {
    let digits: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    let only_digits = digits.len() == text.chars().filter(|c| !c.is_whitespace()).count();
    only_digits && matches!(digits.len(), 9..=12)
}

/// Vietnamese/international mobile shapes: 9–12 digits after normalization
/// (`+84`, `84`, `0` prefixes). Deliberately conservative to limit noise.
pub fn phone_like(text: &str) -> bool {    let normalized: String = text
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    let stripped = normalized
        .strip_prefix("8400")
        .or_else(|| normalized.strip_prefix("84"))
        .unwrap_or(&normalized);
    if let Some(local) = stripped.strip_prefix('0') {
        return (9..=10).contains(&local.len());
    }
    matches!(stripped.len(), 9..=10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_matches_builtin_groups_case_insensitively() {
        // Contract: keys arrive lowercased (callers normalize).
        assert_eq!(classify_key("password", &[], &[]), Some(CREDENTIAL));
        assert_eq!(classify_key("matkhau", &[], &[]), Some(CREDENTIAL));
        assert_eq!(classify_key("refresh_token", &[], &[]), Some(TOKEN));
        assert_eq!(classify_key("useremail", &[], &[]), Some(PII_CONTACT));
        assert_eq!(classify_key("socmnd", &[], &[]), Some(PII_GOV_ID));
        assert_eq!(classify_key("cardnumber", &[], &[]), Some(PAYMENT));
        assert_eq!(classify_key("dap_an", &[], &[]), Some(ANSWER_CONTENT));
        // Unrelated keys stay unclassified.
        assert_eq!(classify_key("createdat", &[], &[]), None);
        assert_eq!(classify_key("totalcount", &[], &[]), None);
    }

    #[test]
    fn excluded_and_extra_keys_override_behavior() {
        assert_eq!(
            classify_key("nextpagetoken", &[], &[]),
            None,
            "pagination cursor must never count as a token leak"
        );
        assert_eq!(
            classify_key("sessiontoken", &["ignored".into()], &["sessiontoken".into()]),
            None,
            "user exclusion wins over builtin groups"
        );
        assert_eq!(
            classify_key("sotaikhoan", &["so_tai_khoan".into()], &[]),
            Some(CUSTOM)
        );
    }

    #[test]
    fn short_fragments_require_word_boundaries() {
        // ≤4-char fragments must not hide inside unrelated words...
        assert_eq!(classify_key("example_field", &[], &[]), None);
        assert_eq!(classify_key("classname", &[], &[]), None);
        assert_eq!(classify_key("lastname", &[], &[]), None, "name is not ssn");
        // ...but legitimate compound forms still match.
        assert_eq!(classify_key("socccd", &[], &[]), Some(PII_GOV_ID));
        assert_eq!(classify_key("exam_paper", &[], &[]), Some(ANSWER_CONTENT));
        assert_eq!(classify_key("pwd", &[], &[]), Some(CREDENTIAL));
        // ≥5-char fragments keep substring semantics.
        assert_eq!(classify_key("mypasswordhash", &[], &[]), Some(CREDENTIAL));
        // SQL/Java naming trap is blocked explicitly.
        assert_eq!(classify_key("preparedstatement", &[], &[]), None);
    }

    #[test]
    fn camel_case_keys_split_into_words() {
        // Contract: keys arrive lowercased (callers normalize before calling).
        assert_eq!(
            classify_key("nextpagetoken", &[], &[]),
            None,
            "pagination cursor stays benign"
        );
        assert_eq!(classify_key("refreshtoken", &[], &[]), Some(TOKEN));
        assert_eq!(
            classify_key("sotaikhoan", &["so_tai_khoan".into()], &[]),
            Some(CUSTOM)
        );
    }

    #[test]
    fn placeholder_values_are_rejected() {
        for junk in ["", "  ", "null", "true", "test", "changeme", "<masked>", "***", "ab"] {
            assert!(!value_is_meaningful(junk), "{junk:?} must be rejected");
        }
        assert!(value_is_meaningful("clcc66"));
        assert!(value_is_meaningful("sk-real-secret-value"));
    }

    #[test]
    fn luhn_accepts_real_cards_and_rejects_ids() {
        assert!(luhn_valid("4111111111111111"));
        assert!(luhn_valid("4111 1111 1111 1111"));
        assert!(luhn_valid("5555-5555-5555-4444"));
        assert!(!luhn_valid("4111111111111112"));
        assert!(!luhn_valid("1234567890123"));
        assert!(!luhn_valid("20250815"), "dates must not pass");
        assert!(!luhn_valid(""), "empty must not pass");
    }

    #[test]
    fn vn_phone_shapes_validate() {
        assert!(phone_like("0912345678"));
        assert!(phone_like("+84912345678"));
        assert!(phone_like("84912345678"));
        assert!(phone_like("091-234-5678"));
        assert!(!phone_like("12345"));
        assert!(!phone_like("012345678901234"), ">11 digits is not a phone");
        assert!(!phone_like("not-a-phone"));
    }
}
