//!
//! This module provides functionality to log data to New Relic using their API.
//!
//! Functions:
//! - log_to_new_relic: Logs data to New Relic.

use reqwest::Client;
use serde_json::Value;
use log::error;
use uuid::Uuid;

/// Logs data to New Relic.
///
/// # Arguments
///
/// * `log_data` - A JSON value containing the log data to be sent.
/// * `request_id` - A UUID representing the unique request ID.
/// * `new_relic_api_key` - A string slice containing the New Relic API key.
///
/// # Example
///
/// ```rust
/// use serde_json::json;
/// use uuid::Uuid;
///
/// let log_data = json!({"message": "This is a log message"});
/// let request_id = Uuid::new_v4();
/// let new_relic_api_key = "your_new_relic_api_key";
///
/// log_to_new_relic(log_data, request_id, new_relic_api_key).await;
/// ```
pub async fn log_to_new_relic(log_data: Value, request_id: Uuid, new_relic_api_key: &str) {
    let client = Client::new();
    let new_relic_url = "https://log-api.newrelic.com/log/v1";

    let res = client.post(new_relic_url)
        .header("Content-Type", "application/json")
        .header("X-Insert-Key", new_relic_api_key)
        .body(log_data.to_string())
        .send()
        .await;

    if let Err(err) = res {
        error!("Error forwarding logs to New Relic for request ID: {}. Error: {}", request_id, err);
    }
}