//! Provides general logging methods for the proxy.
//!
//! This module provides general logging functions for both stdout/stderr and detailed upstream logging.
//!
//! # Functions
//! - `log_llm_query`: Logs the details of an incoming query request.
//! - `log_llm_query_response`: Logs the upstream response of an LLM query.

use std::sync::Arc;

use log::{info, error};
use uuid::Uuid;

use crate::config::Config;
use crate::logging::detailed::{log_llm_request, log_llm_request_response};

/// Logs the details of an incoming query.
/// 
/// # Arguments
///
/// * request_id - The unique identifier for the request.
/// * req_time - The time the request was received.
/// * response_time - The time taken to process the request.
/// * request_address - The application address of the request.
/// * request_client_address - The client address sending the request.
/// * request_method - The HTTP method of the request.
/// * request_uri - The URI of the request.
/// * request_headers - The headers of the request.
/// * request_body - The body of the request.
/// * request_status - The status code of the request.
/// * message - A message describing the log entry.
/// * config - The configuration settings.
/// 
pub async fn log_llm_query(
    request_id: Uuid,
    req_time: chrono::DateTime<chrono::Utc>,
    response_time: i64,
    request_address: &str,
    request_client_address: &str,
    request_method: &str,
    request_uri: &str,
    request_headers: &str,
    request_body: &str,
    request_status: u16,
    message: &str,
    config: &Arc<Config>,
) {
    let is_error = response_is_error(request_status).await;
    let log_msg = format!(
        "[{}] {} [{}]({}) - Method: {}, URI: {}, Status: {}, Request: {}, API Route Time: {}ms",
        req_time.timestamp(),
        request_id,
        request_address,
        request_client_address,
        request_method,
        request_uri,
        request_status,
        truncate_request_response_body(message, 128),
        response_time
    );
    if is_error {
        error!("{}", log_msg);
    } else {
        info!("{}", log_msg);
    }

    log_llm_request(
        log_msg.as_str(),
        req_time,
        response_time,
        request_method,
        request_uri,
        request_headers,
        request_body,
        request_id,
        request_address,
        request_client_address,
        request_status,
        is_error,
        config,
    ).await;
}

/// Logs the details of an inference response.
/// 
/// # Arguments
///
/// * request_id - The unique identifier for the request.
/// * req_time - The time the request was received.
/// * response_time - The time taken to process the request.
/// * request_address - The application address of the request.
/// * request_client_address - The client address sending the request.
/// * response_headers - The headers of the response.
/// * response_body - The body of the response.
/// * response_status - The status code of the response.
/// * message - A message describing the log entry.
/// * config - The configuration settings.
///
pub async fn log_llm_query_response(
    request_id: Uuid,
    req_time: chrono::DateTime<chrono::Utc>,
    response_time: i64,
    request_address: &str,
    request_client_address: &str,
    response_headers: &str,
    response_body: &str,
    response_status: u16,
    message : &str,
    config: &Arc<Config>,
) {
    let is_error = response_is_error(response_status).await;
    let log_msg = format!(
        "[{}] {} [{}]({}) - Status: {}, Response: {}, Response Time: {}ms",
        req_time.timestamp(),
        request_id,
        request_address,
        request_client_address,
        response_status,
        truncate_request_response_body(message, 128),
        response_time
    );
    if is_error {
        error!("{}", log_msg);
    } else {
        info!("{}", log_msg);
    }

    log_llm_request_response(
        log_msg.as_str(),
        req_time,
        response_time,
        response_headers,
        response_body,
        request_id,
        request_address,
        request_client_address,
        response_status,
        is_error,
        config,
    ).await;
}

/// Determines if a response is an error.
///
/// # Arguments
/// * `response_status` - The status code of the response.
/// 
/// # Returns
///  A boolean indicating if the response is an error.
///
async fn response_is_error(response_status: u16) -> bool {
    response_status != 200 && response_status != 308
}

fn truncate_request_response_body(body: &str, max_length: usize) -> String {
    if body.len() > max_length {
        format!("{}...", &body[..max_length])
    } else {
        body.to_string()
    }
}
