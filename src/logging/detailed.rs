//! This module provides detailed logging functionality for the LLM proxy requests.
//!
//! The primary function in this module is `log_llm_request`, which logs detailed information
//! about each request made to the LLM proxy. This includes the request method, URI, headers,
//! body, status code, and other relevant metadata. The logs can be sent to external services
//! such as New Relic for monitoring and analysis.
//!
//! # Functions
//! - `log_llm_request`: Logs detailed information about the LLM proxy request.
//! - `log_llm_request_response`: Logs detailed information about the upstream response to the LLM query.

use std::sync::Arc;

use serde_json::json;
use uuid::Uuid;

use crate::config::Config;
use crate::logging::newrelic::log_to_new_relic;

/// Logs detailed information about the LLM proxy request.
///
/// # Parameters
/// - `message`: A message describing the request.
/// - `req_time`: The time the request was received.
/// - `response_time`: The time taken to process the request.
/// - `request_method`: The HTTP method used for the request.
/// - `request_uri`: The URI of the request.
/// - `request_headers`: The headers of the request.
/// - `request_body`: The body of the request.
/// - `request_id`: A unique identifier for the request.
/// - `request_address`: The application address of the request.
/// - `request_client_address`: The client address sending the request.
/// - `request_status`: The HTTP status code of the request.
/// - `is_error`: A flag indicating whether the request resulted in an error.
/// - `config`: A reference to the configuration object.
///
/// # Example
/// ```
/// use std::sync::Arc;
/// use uuid::Uuid;
/// use crate::config::Config;
/// use crate::logging::detailed::log_llm_request;
///
/// #[tokio::main]
/// async fn main() {
///     let config = Arc::new(Config::new());
///     let request_id = Uuid::new_v4();
///     log_llm_request(
///         "Request message",
///         "GET",
///         "/api/v1/resource",
///         "headers",
///         "body",
///         request_id,
///         200,
///         false,
///         &config,
///     ).await;
/// }
/// ```
pub async fn log_llm_request(
    message : &str,
    req_time: chrono::DateTime<chrono::Utc>,
    response_time: i64,
    request_method: &str,
    request_uri: &str,
    request_headers: &str,
    request_body: &str,
    request_id: Uuid,
    request_address: &str,
    request_client_address: &str,
    request_status: u16,
    is_error: bool,
    config: &Arc<Config>,
) {
    let log_data = json!({
        "timestamp": req_time.timestamp(),
        "message": message,
        "type": "aigateway",
        "operation": "request",
        "uri": "aigateway.lib.unb.ca",
        "request_id": request_id.to_string(),
        "status": request_status,
        "failed": is_error,
        "response_time": response_time,
        "client": {
            "address": request_client_address,
            "ip": request_address,
        },
        "request": {
            "method": request_method,
            "uri": request_uri,
            "headers": request_headers,
            "body": request_body,
        }
    });

    // If the logging value in the config is "newrelic", log to New Relic
    if config.logging == "newrelic" {
        // Check if the license key is set. If not, error.
        if config.license_key.is_empty() {
            log::error!("New Relic license key is not set. Cannot log to New Relic.");
            return;
        }
        log_to_new_relic(log_data, request_id, &config.license_key).await;
    }
}

/// Logs detailed information about the upstream response to the LLM query.
/// 
/// # Arguments
/// 
/// * `message` - The message to be logged.
/// * `req_time` - The time the request was received.
/// * `response_time` - The time taken to process the request.
/// * `response_headers` - A string slice that holds the response headers to be logged.
/// * `response_body` - A string slice that holds the response body to be logged.
/// * `request_id` - A UUID that uniquely identifies the request.
/// - `request_address`: The application address of the request.
/// - `request_client_address`: The client address sending the request.
/// * `response_status` - A 16-bit unsigned integer that holds the response status code.
/// * `is_error` - A boolean that indicates whether the response is an error.
/// * `config` - A reference-counted pointer to the configuration settings.
/// 
/// # Examples
/// 
/// ```
/// let request_id = Uuid::new_v4();
/// log_llm_request_response(
///     "Request processed successfully",
///     "headers",
///     "body",
///     request_id,
///     200,
///     false,
///     &config
/// ).await;
/// ```
pub async fn log_llm_request_response(
    message : &str,
    req_time: chrono::DateTime<chrono::Utc>,
    response_time: i64,
    response_headers: &str,
    response_body: &str,
    request_id: Uuid,
    request_address: &str,
    request_client_address: &str,
    response_status: u16,
    is_error: bool,
    config: &Arc<Config>,
) {
    let log_data = json!({
        "timestamp": req_time.timestamp(),
        "message": message,
        "type": "aigateway",
        "operation": "response",
        "uri": "aigateway.lib.unb.ca",
        "request_id": request_id.to_string(),
        "failed": is_error,
        "response_time": response_time,
        "client": {
            "address": request_client_address,
            "ip": request_address,
        },
        "response": {
            "status": response_status,
            "headers": response_headers,
            "body": response_body,
        }
    });

    // If the logging value in the config is "newrelic", log to New Relic
    if config.logging == "newrelic" {
        // Check if the license key is set. If not, error.
        if config.license_key.is_empty() {
            log::error!("New Relic license key is not set. Cannot log to New Relic.");
            return;
        }
        log_to_new_relic(log_data, request_id, &config.license_key).await;
    }
}
