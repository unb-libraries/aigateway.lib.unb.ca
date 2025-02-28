//!
//! This module provides functionality to interface with the TyrellLLMv1 adapter.
//!
//! Functions:
//! - `TyrellLLMv1::new`: Creates a new instance of the TyrellLLMv1 adapter.
//! - `TyrellLLMv1::handle_request`: Handles an incoming HTTP request with the TyrellLLMv1 adapter.
//!

use std::sync::Arc;
use async_trait::async_trait;

use hyper::{Request, Response, Body};
use uuid::Uuid;

use crate::adapters::GenericInferenceEndpointAdapter;
use crate::config::{Config, EndpointConfig};
use crate::client::metadata::RequestMetadata;

pub struct TyrellLLMv1;

impl TyrellLLMv1 {

    pub fn new() -> Self {
        TyrellLLMv1
    }

    /// Public wrapper for the private `handle_request` function.
    pub async fn p_handle_request(
        &self,
        req: Request<Body>,
        endpoint: &EndpointConfig,
        config: Arc<Config>,
        request_id: Uuid,
        addr: String,
        req_time: chrono::DateTime<chrono::Utc>,
    ) -> Result<Response<Body>, hyper::Error> {
        self.handle_request(req, endpoint, config, request_id, addr, req_time).await
    }
}

#[async_trait]
impl GenericInferenceEndpointAdapter for TyrellLLMv1 {

    const USER_AGENT: &'static str = "TyrellLLMv1";
    const BODY_VALUE_FIELD_TO_LOG: &'static str = "query";

    /// Checks the metadata of a request to ensure it meets the required criteria.
    /// 
    /// # Arguments
    /// 
    /// * `request_metadata` - A reference to the metadata of the request that needs to be checked.
    /// 
    /// # Returns
    /// 
    /// * `Result<(), Error>` - Returns `Ok(())` if the metadata is valid, otherwise returns an `Error`.
    ///
    /// # Errors
    ///
    /// This function will return an error if the metadata does not meet the required criteria.
    async fn check_request_metadata(&self, request_metadata: RequestMetadata) -> (bool, Option<String>) {
        if request_metadata.method != hyper::Method::POST {
            return (false, Some("Request method is not POST".to_string()));
        }

        if !request_metadata.headers.contains_key("content-type") {
            return (false, Some("Request header does not contain 'content-type'".to_string()));
        }

        if request_metadata.headers.get("content-type").unwrap() != "application/json" {
            return (false, Some("Request header 'content-type' is not 'application/json'".to_string()));
        }

        if request_metadata.body.is_empty() {
            return (false, Some("Request body is empty".to_string()));
        }

        let body_json: serde_json::Value = match serde_json::from_str(&request_metadata.body) {
            Ok(json) => json,
            Err(_) => return (false, Some("Request body is not valid JSON".to_string())),
        };

        // Check that body_json contains a 'query' value
        if !body_json.as_object().unwrap().contains_key("query") {
            return (false, Some("Request body does not contain 'query' key".to_string()));
        }

        if !body_json.as_object().unwrap().contains_key("pipeline") {
            return (false, Some("Request body does not contain 'pipeline' key".to_string()));
        }

        (true, None)
    }

}
