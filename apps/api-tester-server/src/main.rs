mod backend;
mod dashboard;
mod http_client;
mod routes;
mod serialization;
mod state;
mod ws;

use std::sync::Arc;

use api_tester_config::ConfigLoader;
use axum::serve;
use tokio::net::TcpListener;

use crate::state::{AppState, data_dir};

const WEB_ADDR: &str = "127.0.0.1:2712";

/// Resolves the frontend directory (`ui/`) relative to the crate manifest
/// (embedded at compile time), so the static server works regardless of the
/// process working directory.
fn resolve_ui_dir() -> String {
    format!("{}/ui", env!("CARGO_MANIFEST_DIR"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = data_dir().join("config.json");
    let config = ConfigLoader::load(if config_path.exists() {
        Some(&config_path)
    } else {
        None
    })
    .map_err(|error| -> Box<dyn std::error::Error> { error.to_string().into() })?;
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
