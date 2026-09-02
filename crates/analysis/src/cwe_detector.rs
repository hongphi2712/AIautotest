#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CweFinding {
    pub cwe_id: &'static str,
    pub title: &'static str,
    pub evidence: String,
}

pub struct CweDetector;

impl CweDetector {
    /// Scans an HTTP response body for CWE exposure patterns (CWE-215, CWE-209, CWE-284).
    pub fn detect(body: &str) -> Vec<CweFinding> {
        let mut findings = Vec::new();
        let body_lower = body.to_lowercase();

        // 🎯 CWE-215: Insertion of Sensitive Information into Debug Code (Debug / Dev Mode / Path Exposure)
        if body_lower.contains("\"env\":\"development\"")
            || body_lower.contains("\"env\": \"development\"")
            || body_lower.contains("\"debug\":true")
            || body_lower.contains("\"debug\": true")
            || body.contains(".js.map")
        {
            findings.push(CweFinding {
                cwe_id: "CWE-215",
                title: "Debug Mode & Source Map Exposure",
                evidence: "Response contains development environment flags or .js.map source map references.".into(),
            });
        }

        if body.contains("D:\\Coding\\") || body.contains("/var/www/") || body.contains("C:\\Users\\") {
            findings.push(CweFinding {
                cwe_id: "CWE-215",
                title: "Internal Server File Path Exposure",
                evidence: "Response contains internal file system absolute paths.".into(),
            });
        }

        // 🎯 CWE-209: Generation of Error Message Containing Sensitive Information (Stack Trace Leak)
        if body_lower.contains("cast to objectid failed")
            || body_lower.contains("mongoerror")
            || body_lower.contains("syntaxerror: unexpected token")
            || body_lower.contains("at process.process-ticks-and-rejections")
            || body_lower.contains("traceback (most recent call last):")
        {
            findings.push(CweFinding {
                cwe_id: "CWE-209",
                title: "Unhandled Stack Trace / Database Error Exposure",
                evidence: "Response exposes unhandled application stack traces or database driver exceptions.".into(),
            });
        }

        // 🎯 CWE-284: Improper Access Control (Internal Admin Route Leak in State)
        if body_lower.contains("/api/internal/")
            || body_lower.contains("/admin/database")
            || body_lower.contains("/api/v1/admin/users/delete")
        {
            findings.push(CweFinding {
                cwe_id: "CWE-284",
                title: "Internal Admin Endpoint Exposure",
                evidence: "Response payload exposes restricted internal administration endpoints.".into(),
            });
        }

        findings.sort_by(|a, b| a.cwe_id.cmp(b.cwe_id));
        findings.dedup();
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_debug_mode() {
        let body = r#"{"status": "ok", "env": "development", "debug": true}"#;
        let findings = CweDetector::detect(body);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].cwe_id, "CWE-215");
    }

    #[test]
    fn test_detects_stack_trace() {
        let body = r#"Error: Cast to ObjectId failed for value "123" at path "_id""#;
        let findings = CweDetector::detect(body);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].cwe_id, "CWE-209");
    }
}
