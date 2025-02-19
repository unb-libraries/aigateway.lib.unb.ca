use std::collections::HashMap;

use serde::Deserialize;
use tokio::fs;

#[derive(Deserialize)]
pub struct Config {
    pub port: u16,
    pub adapter: String,
    pub endpoints: HashMap<String, EndpointConfig>,
    pub logging: String,
    pub license_key: String,
    pub messages: MessagesConfig,
}

#[derive(Clone, Deserialize)]
pub struct EndpointConfig {
    pub adapter: String,
    pub url: String,
}

#[derive(Deserialize)]
pub struct MessagesConfig {
    pub auth_failure: String,
}

/// Loads the configuration.
///
/// # Returns
///
/// A `Config` struct containing the configuration data.
///
/// # Panics
///
/// This function will panic if the `config.json` file cannot be read or if the
/// contents cannot be parsed into a `Config` struct.
pub async fn load_config() -> Config {
    let contents_file_path = concat!(env!("CARGO_MANIFEST_DIR"), "/data/config.json");
    let contents = fs::read_to_string(contents_file_path)
        .await
        .expect(format!("Error: Failed to read {}", contents_file_path).as_str());
    serde_json::from_str(&contents).expect(format!("Error: Failed to parse {}", contents_file_path).as_str())
}
