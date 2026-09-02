mod backend;
mod dashboard;
mod http_client;
mod routes;
mod security_service;
mod serialization;
mod state;
mod workflow_service;
mod ws;

use std::sync::Arc;

use api_tester_config::ConfigLoader;
use axum::serve;
use tokio::net::TcpListener;

use crate::state::{AppState, data_dir};

const WEB_ADDR: &str = "127.0.0.1:2712";

/// Exclusive process-lifetime lock on `<data>/server.lock`. A second instance
/// sharing the SQLite file is the main source of `database is locked` /
/// `attempt to write a readonly database` errors, so refuse to start instead.
fn acquire_single_instance_lock() -> Result<(), String> {
    let lock_path = data_dir().join("server.lock");
    std::fs::create_dir_all(data_dir())
        .map_err(|error| format!("cannot create data dir: {error}"))?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|error| format!("cannot open {}: {error}", lock_path.display()))?;
    match file.try_lock() {
        Ok(()) => {
            std::mem::forget(file);
            Ok(())
        }
        Err(error) => {
            let reason = match error {
                std::fs::TryLockError::Error(io) => io.to_string(),
                _ => "already held by another process".to_owned(),
            };
            Err(format!(
                "cannot acquire instance lock {} ({reason}) - another API-AutoTester instance is likely running; close it or delete the lock file after killing all api-tester-server.exe processes",
                lock_path.display()
            ))
        }
    }
}

/// Resolves the frontend directory relative to the crate manifest.
fn resolve_ui_dir() -> String {
    format!("{}/ui", env!("CARGO_MANIFEST_DIR"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    acquire_single_instance_lock()
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
    let config_path = data_dir().join("config.json");
    let config = ConfigLoader::load(if config_path.exists() {
        Some(&config_path)
    } else {
        None
    })
    .map_err(|error| -> Box<dyn std::error::Error> { error.to_string().into() })?;
    // Response-analysis thresholds come from `[analysis]` in config.json;
    // without the section the analyzer keeps its built-in defaults.
    api_tester_analysis::init_analysis_config(config.analysis.clone());
    api_tester_analysis::init_host_profiles(config.host_profiles.clone());
    let state = Arc::new(
        AppState::new(config).map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
    );

    let listener = TcpListener::bind(WEB_ADDR)
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
    println!("API-AutoTester UI: http://{WEB_ADDR}");

    let app = routes::router(state, resolve_ui_dir());
    let _ = open::that(format!("http://{WEB_ADDR}"));

    serve(listener, app)
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
    Ok(())
}
