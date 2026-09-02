use std::fs;
use std::path::Path;

use api_tester_domain::AppConfig;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read config file {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("could not write config file {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid config JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Domain(#[from] api_tester_domain::DomainError),
}

pub struct ConfigLoader;

impl ConfigLoader {
    pub fn load(path: Option<&Path>) -> Result<AppConfig, ConfigError> {
        let mut config = match path {
            Some(path) if path.exists() => {
                let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
                    path: path.display().to_string(),
                    source,
                })?;
                // Strip UTF-8 BOM (EF BB BF) if present — editors on Windows
                // may emit BOM which breaks serde_json parsing.
                let contents = contents.strip_prefix('\u{feff}').unwrap_or(&contents);
                serde_json::from_str(contents)?
            }
            _ => AppConfig::default(),
        };

        Self::apply_environment_overrides(&mut config)?;
        config.validate()?;
        Ok(config)
    }

    pub fn save(config: &AppConfig, path: &Path) -> Result<(), ConfigError> {
        config.validate()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| ConfigError::Write {
                path: path.display().to_string(),
                source,
            })?;
        }
        let contents = serde_json::to_string_pretty(config)?;
        fs::write(path, contents).map_err(|source| ConfigError::Write {
            path: path.display().to_string(),
            source,
        })?;
        Ok(())
    }

    fn apply_environment_overrides(config: &mut AppConfig) -> Result<(), ConfigError> {
        if let Some(host) = std::env::var_os("API_TESTER_PROXY_HOST") {
            config.proxy.host = host.to_string_lossy().into_owned();
        }
        if let Some(port) = std::env::var_os("API_TESTER_PROXY_PORT") {
            config.proxy.port = port.to_string_lossy().parse().map_err(|_| {
                ConfigError::Domain(api_tester_domain::DomainError::InvalidValue(
                    "API_TESTER_PROXY_PORT must be a valid port".to_owned(),
                ))
            })?;
        }
        if let Some(level) = std::env::var_os("API_TESTER_LOG_LEVEL") {
            config.log_level = level.to_string_lossy().into_owned();
        }
        if let Ok(key) = std::env::var("DEEPSEEK_API_KEY") {
            if !key.trim().is_empty() {
                config.ai.api_key = Some(key.trim().to_owned());
            }
        }
        if let Some(model) = std::env::var_os("API_TESTER_AI_MODEL") {
            config.ai.model = model.to_string_lossy().into_owned();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use api_tester_domain::{
        AppConfig, DEFAULT_BUFFER_DEDUP_LIMIT, DEFAULT_BUFFER_MAX_BYTES, DEFAULT_BUFFER_SIZE,
        DEFAULT_IDLE_TIMEOUT_SECS, DEFAULT_MAX_BODY_BYTES, DEFAULT_MAX_CONNECTIONS,
        DEFAULT_UPSTREAM_VERIFY_TLS,
    };

    use super::ConfigLoader;

    #[test]
    fn defaults_match_python_contract() {
        let config = ConfigLoader::load(None).unwrap();

        assert_eq!(config.proxy.host, "127.0.0.1");
        assert_eq!(config.proxy.port, 8080);
        assert_eq!(config.buffer.max_size, DEFAULT_BUFFER_SIZE);
        assert_eq!(config.buffer.max_bytes, DEFAULT_BUFFER_MAX_BYTES);
        assert_eq!(config.buffer.dedup_limit, DEFAULT_BUFFER_DEDUP_LIMIT);
        assert_eq!(config.scanner.max_concurrent_requests, 50);
        assert_eq!(config.proxy.max_body_bytes, DEFAULT_MAX_BODY_BYTES);
        assert_eq!(
            config.proxy.upstream_verify_tls,
            DEFAULT_UPSTREAM_VERIFY_TLS
        );
        assert_eq!(config.proxy.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert_eq!(config.proxy.idle_timeout_secs, DEFAULT_IDLE_TIMEOUT_SECS);
    }

    #[test]
    fn config_round_trips_as_json() {
        let config = AppConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let decoded: AppConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(config, decoded);
    }

    #[test]
    fn repository_example_config_is_compatible() {
        let config: AppConfig =
            serde_json::from_str(include_str!("../../../config.example.json")).unwrap();

        config.validate().unwrap();
        assert_eq!(config.proxy.port, 8080);
        assert_eq!(config.scanner.max_concurrent_requests, 50);
        assert_eq!(config.security.max_requests, 200);
        assert_eq!(config.security.timeout_secs, 15);
        assert_eq!(config.security.concurrency, 1);
    }

    #[test]
    fn security_config_defaults_are_valid() {
        let config = AppConfig::default();
        config.validate().unwrap();
        assert_eq!(config.security.max_requests, 200);
        assert_eq!(config.security.timeout_secs, 15);
        assert_eq!(config.security.retry_limit, 1);
        assert_eq!(config.security.concurrency, 1);
    }

    #[test]
    fn security_max_requests_zero_is_rejected() {
        let mut config = AppConfig::default();
        config.security.max_requests = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn security_timeout_zero_is_rejected() {
        let mut config = AppConfig::default();
        config.security.timeout_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn security_concurrency_out_of_range_is_rejected() {
        let mut config = AppConfig::default();
        config.security.concurrency = 0;
        assert!(config.validate().is_err());
        config.security.concurrency = 5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn invalid_port_is_rejected() {
        let mut config = AppConfig::default();
        config.proxy.port = 0;

        assert!(ConfigLoader::save(&config, std::path::Path::new("target/invalid.json")).is_err());
    }

    #[test]
    fn config_load_strips_utf8_bom() {
        let dir = std::path::Path::new("target");
        let _ = std::fs::create_dir_all(dir);
        let path = dir.join("bom_test_config.json");
        // Write config with BOM prefix
        let mut bom_content = vec![0xEF, 0xBB, 0xBF]; // UTF-8 BOM
        let json = r#"{"proxy":{"host":"127.0.0.1","port":9999},"buffer":{},"scanner":{},"oast":{},"scope":{},"security":{"max_requests":200,"timeout_secs":15,"concurrency":1},"ai":{},"log_level":"INFO","output_dir":"./output"}"#;
        bom_content.extend_from_slice(json.as_bytes());
        std::fs::write(&path, &bom_content).unwrap();

        let config = ConfigLoader::load(Some(&path)).unwrap();
        assert_eq!(config.proxy.port, 9999);
    }
}
