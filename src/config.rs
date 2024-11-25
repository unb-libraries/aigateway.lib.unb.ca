//! Configuration module for AI Gateway
use serde::Deserialize;
use std::collections::HashMap;
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
    let contents = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/data/config.json"))
        .await
        .expect("Failed to read config.json");
    serde_json::from_str(&contents).expect("Failed to parse config.json")
}
