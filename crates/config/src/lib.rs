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
                serde_json::from_str(&contents)?
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use api_tester_domain::{AppConfig, DEFAULT_BUFFER_SIZE};

    use super::ConfigLoader;

    #[test]
    fn defaults_match_python_contract() {
        let config = ConfigLoader::load(None).unwrap();

        assert_eq!(config.proxy.host, "127.0.0.1");
        assert_eq!(config.proxy.port, 8080);
        assert_eq!(config.buffer.max_size, DEFAULT_BUFFER_SIZE);
        assert_eq!(config.scanner.max_concurrent_requests, 50);
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
    }

    #[test]
    fn invalid_port_is_rejected() {
        let mut config = AppConfig::default();
        config.proxy.port = 0;

        assert!(ConfigLoader::save(&config, std::path::Path::new("target/invalid.json")).is_err());
    }
}
