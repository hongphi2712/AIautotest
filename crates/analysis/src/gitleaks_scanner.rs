use serde::Deserialize;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

/// Hard cap on piped input: scanning multi-megabyte bodies through the CLI is
/// not worth the latency, and secrets almost never live beyond the first MB.
const MAX_INPUT_BYTES: usize = 1024 * 1024;

/// Kill switch for a hung gitleaks process so callers can never block forever.
const SCAN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GitleaksFinding {
    #[serde(rename = "RuleID")]
    pub rule_id: String,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "Secret")]
    pub secret: String,
    #[serde(rename = "StartLine")]
    pub start_line: usize,
}

pub struct GitleaksScanner;

impl GitleaksScanner {
    /// Scans a text/HTML/JSON payload using the Gitleaks CLI if available.
    /// Passes content via stdin (`gitleaks detect --pipe`) for zero disk I/O.
    ///
    /// Bounded by design: input is capped at `MAX_INPUT_BYTES`, a hung process
    /// is killed after `SCAN_TIMEOUT`, and a missing binary degrades silently
    /// to "no findings" (the built-in regex scanner still runs).
    pub fn scan_pipe(content: &str) -> Vec<GitleaksFinding> {
        if content.trim().is_empty() {
            return Vec::new();
        }
        let Some(program) = gitleaks_binary() else {
            // Not installed and no winget fallback found; skip quietly.
            return Vec::new();
        };
        let bytes = capped_input(content);

        let mut child = match Command::new(program)
            .args([
                "detect",
                "--pipe",
                "--no-banner",
                "--report-format",
                "json",
                "--report-path",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                eprintln!("[analysis] gitleaks spawn failed: {error}");
                return Vec::new();
            }
        };

        // stdin/stdout are driven on helper threads: write_all on a large body
        // blocks until the child consumes bytes, and reading stdout inline can
        // deadlock if the child fills its pipe before exiting. Killing the
        // child closes both pipes, which unblocks either thread immediately.
        let stdin = child.stdin.take();
        let writer = thread::spawn(move || {
            if let Some(mut stdin) = stdin {
                let _ = stdin.write_all(&bytes);
            }
        });

        let stdout = child.stdout.take();
        let reader = thread::spawn(move || {
            let mut report = String::new();
            if let Some(mut stdout) = stdout {
                let _ = stdout.read_to_string(&mut report);
            }
            report
        });

        let deadline = Instant::now() + SCAN_TIMEOUT;
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        eprintln!("[analysis] gitleaks scan timed out after {SCAN_TIMEOUT:?}");
                        timed_out = true;
                        break None;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => {
                    eprintln!("[analysis] gitleaks wait failed: {error}");
                    break None;
                }
            }
        };

        if !timed_out {
            // The child exited on its own; the writer finishes (or already hit
            // EOF/EPIPE) promptly. Join to keep both threads accounted for.
            let _ = writer.join();
        }

        if let Some(status) = status {
            // Exit code contract: 0 = clean, 1 = leaks found (both fine);
            // anything else means the scan itself failed.
            if status.code().is_some_and(|code| code > 1) {
                eprintln!("[analysis] gitleaks exited abnormally: {status}");
            }
        }

        let report = reader.join().unwrap_or_default();
        serde_json::from_str::<Vec<GitleaksFinding>>(&report).unwrap_or_default()
    }
}

/// Truncates oversized payloads instead of piping unbounded data to the CLI.
fn capped_input(content: &str) -> Vec<u8> {
    let mut bytes = content.as_bytes();
    if bytes.len() > MAX_INPUT_BYTES {
        bytes = &bytes[..MAX_INPUT_BYTES];
    }
    bytes.to_vec()
}

/// Resolves the gitleaks executable: PATH first, then the winget install
/// location (mirrors `.githooks/pre-commit` so runtime scans work whenever the
/// commit hook works). The positive result is cached; a miss retries PATH on
/// every call, which stays cheap because `SecretScanner::analyze` caches scans.
fn gitleaks_binary() -> Option<PathBuf> {
    static RESOLVED: OnceLock<Option<PathBuf>> = OnceLock::new();
    if let Some(resolved) = RESOLVED.get() {
        return resolved.clone();
    }

    let from_winget = winget_gitleaks_path();
    if from_winget.is_some() {
        let _ = RESOLVED.set(from_winget.clone());
        return from_winget;
    }

    // Probe PATH with a cheap `--version`; only cache successful lookups so a
    // later install still gets picked up without a restart.
    match Command::new("gitleaks").arg("--version").output() {
        Ok(_) => Some(PathBuf::from("gitleaks")),
        Err(_) => None,
    }
}

fn winget_gitleaks_path() -> Option<PathBuf> {
    let local_app_data = std::env::var_os("LOCALAPPDATA")?;
    let winget = PathBuf::from(local_app_data)
        .join("Microsoft")
        .join("WinGet");
    // Package layout: Packages/Gitleaks.Gitleaks_<id>/gitleaks.exe
    if let Some(path) = find_gitleaks_under(&winget.join("Packages")) {
        return Some(path);
    }
    // Shim layout: Links/gitleaks.exe
    let link = winget.join("Links").join("gitleaks.exe");
    link.is_file().then_some(link)
}

fn find_gitleaks_under(base: &Path) -> Option<PathBuf> {
    let entries = std::fs::read_dir(base).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().to_lowercase().contains("gitleaks") {
            continue;
        }
        let path = entry.path();
        let candidate = if path.is_dir() {
            path.join("gitleaks.exe")
        } else {
            path
        };
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gitleaks_pipe_scan_jwt() {
        let jwt_sample = r#"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY4OGMyZTFkMGVhMDlhMTRiZjA4ZDhjYyIsImlhdCI6MTc4NzMwMTE0MSwiZXhwIjoxNzg3OTA1OTQxfQ.NGKma2iYv8tEATjT2GrsjinldlDlsSY2IVK-ehgFgKc"#;
        let findings = GitleaksScanner::scan_pipe(jwt_sample);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "jwt");
    }

    #[test]
    fn empty_content_skips_process_spawn() {
        assert!(GitleaksScanner::scan_pipe("   \n\t ").is_empty());
    }

    #[test]
    fn oversized_input_is_capped() {
        let big = "x".repeat(MAX_INPUT_BYTES + 4096);
        assert_eq!(capped_input(&big).len(), MAX_INPUT_BYTES);
        assert_eq!(capped_input("short").len(), 5);
    }
}
