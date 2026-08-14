mod commands;
mod dashboard;
mod http_client;
mod serialization;
mod state;

use api_tester_config::ConfigLoader;
use tauri::Manager;

use crate::state::{AppState, data_dir};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let config_path = data_dir().join("config.json");
            let config = ConfigLoader::load(if config_path.exists() {
                Some(&config_path)
            } else {
                None
            })
            .map_err(|error| -> Box<dyn std::error::Error> { error.to_string().into() })?;
            let state = AppState::new(config)
                .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_health,
            commands::list_flows,
            commands::flow_detail,
            commands::repeater_send,
            commands::start_proxy,
            commands::stop_proxy,
            commands::proxy_status,
            commands::open_browser,
            commands::cert_info,
            commands::install_ca,
            commands::list_sessions,
            commands::intercept_set_enabled,
            commands::intercept_set_scopes,
            commands::intercept_status,
            commands::intercept_list,
            commands::intercept_detail,
            commands::intercept_forward,
            commands::intercept_drop,
            commands::intercept_clear,
        ])
        .run(tauri::generate_context!())
        .expect("error while running API-AutoTester");
}
