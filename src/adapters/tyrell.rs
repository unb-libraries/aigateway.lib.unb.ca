//!
//! This module provides functionality to interface with the Tyrell LLMv1 adapter.
//!
//! Functions:
//! - `TyrellLLMv1::new`: Creates a new instance of the TyrellLLMv1 adapter.
//! - `TyrellLLMv1::handle_request`: Handles an incoming HTTP request with the TyrellLLMv1 adapter.
//!
use std::sync::Arc;

use hyper::{Request, Client, Response, Body};
use hyper::client::HttpConnector;
use uuid::Uuid;

use crate::config::{Config, EndpointConfig};
use crate::client::metadata::RequestMetadata;
use crate::logging::proxy::{log_llm_query, log_llm_query_response};

pub struct TyrellLLMv1;

impl TyrellLLMv1 {
    pub fn new() -> Self {
        TyrellLLMv1
    }

    /// Request handler for the TyrellLLMv1 adapter.
    ///
    /// # Arguments
    ///
    /// * `req` - The incoming HTTP request.
    /// * `client` - The HTTP client used to send requests.
    /// * `endpoint` - Configuration for the endpoint.
    /// * `config` - Shared configuration for the application.
    /// * `request_id` - Unique identifier for the request.
    /// * `addr` - Client's IP address.
    ///
    /// # Returns
    ///
    /// A `Result` containing either the HTTP response or an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the request processing fails.
    ///
    /// # Examples
    ///
    /// ```
    /// let response = deckard_llmv1.handle_request(req, endpoint, config, request_id, addr).await?;
    /// ```
    pub async fn handle_request(
        &self,
        req: Request<Body>,
        endpoint: &EndpointConfig,
        config: Arc<Config>,
        request_id: Uuid,
        addr: String,
        req_time: chrono::DateTime<chrono::Utc>,
    ) -> Result<Response<Body>, hyper::Error> {
        let config_clone = config.clone();

        // Depending on the endpoint url, we may need to build this as http or https.
        let connector = HttpConnector::new();
        let client = Client::builder()
            .http2_adaptive_window(true)
            .build(connector);

        // @SEE This mess, as well as the dozen other times this appears in the codebase, is because the request cannot be cloned.
        // We have to extract the data we need from the request, then reconstruct the request.
        let (request_metadata, req) = RequestMetadata::from_request(req, addr.clone(), false).await;

        // Check request data for required fields.
        let (is_valid, reason) = self.check_request_metadata(request_metadata).await;

        let (request_metadata, req) = RequestMetadata::from_request(req, addr.clone(), false).await;
        if !is_valid {
            let response_time = chrono::Utc::now().signed_duration_since(req_time).num_milliseconds();

            tokio::spawn(async move {
                log_llm_query(
                    request_id.clone(),
                    req_time,
                    response_time,
                    request_metadata.ip.as_str(),
                    request_metadata.client_ip.as_str(),
                    request_metadata.method.as_str(),
                    request_metadata.uri.path(),
                    format!("{:?}", request_metadata.headers).as_str(),
                    request_metadata.body.as_str(),
                    400,
                    format!("Request metadata is invalid: {:?}", reason).as_str(),
                    &config,
                ).await;
            });
            // Construct a response with a malformed status code.
            let mut response = Response::new(Body::from("Bad request"));
            *response.status_mut() = hyper::StatusCode::BAD_REQUEST;
            return Ok(response);
        }

        // Preprocess requests specifically for this endpoint.
        let req = self.preprocess_request(req).await;

        // Get the query string from the request body.
        let body_json: serde_json::Value = serde_json::from_str(&request_metadata.body).unwrap();
        let query_string = body_json["query"].as_str().unwrap().to_string();

        let (request_metadata, req) = RequestMetadata::from_request(req, addr.clone(), false).await;
        let response_time = chrono::Utc::now().signed_duration_since(req_time).num_milliseconds();

        tokio::spawn(async move {
            log_llm_query(
                request_id.clone(),
                req_time.clone(),
                response_time,
                request_metadata.ip.as_str(),
                request_metadata.client_ip.as_str(),
                request_metadata.method.as_str(),
                request_metadata.uri.path(),
                format!("{:?}", request_metadata.headers).as_str(),
                request_metadata.body.as_str(),
                200,
                format!("Query: {:?}", query_string).as_str(),
                &config_clone,
            ).await;
        });

        // Build the proxied request.
        let (request_metadata, req) = RequestMetadata::from_request(req, addr.clone(), true).await;
        let mut proxied_request = Request::builder()
            .method(request_metadata.method.clone())
            .header("content-type", "application/json")
            .header("user-agent", "TyrellLLMv1")
            .uri(endpoint.url.clone())
            .body(req.into_body())
            .expect("Failed to build request");
        *proxied_request.headers_mut() = request_metadata.headers;

        // Send the request to the upstream server.
        match client.request(proxied_request).await {
            Ok(response) => {
                // Postprocess requests specifically for this endpoint.
                let response = self.postprocess_response(response).await;
                Ok(response)
            }
            Err(err) => {
                let error_message = format!("Error: {}", err);
                let response_time = chrono::Utc::now().signed_duration_since(req_time).num_milliseconds();

                tokio::spawn(async move {
                    log_llm_query_response(
                        request_id,
                        req_time,
                        response_time,
                        request_metadata.ip.as_str(),
                        request_metadata.client_ip.as_str(),
                        "",
                        "",
                        503,
                        error_message.as_str(),
                        &config,
                    ).await;
                });

                Err(err)
            }
        }
    }

    /// Preprocesses an incoming request to prepare it for upstream.
    /// 
    /// @TODO: THIS IS STUBBED OUT AND NEEDS TO BE IMPLEMENTED.
    ///
    /// # Arguments
    /// 
    /// * `request` - A mutable reference to the request that needs to be preprocessed.
    /// 
    /// # Returns
    /// 
    /// * `Result<(), Error>` - Returns `Ok(())` if the preprocessing is successful, otherwise returns an `Error`.
    ///
    /// # Errors
    ///
    /// This function will return an error if the request fails validation or any other preprocessing step.
    async fn preprocess_request(&self, req: Request<Body>) -> Request<Body> {
        req
    }

    /// Postprocesses a response before sending it downstream.
    /// 
    /// @TODO: THIS IS STUBBED OUT AND NEEDS TO BE IMPLEMENTED.
    ///
    /// # Arguments
    /// 
    /// * `res` - A mutable reference to the response that needs to be postprocessed.
    /// 
    /// # Returns
    /// 
    /// * `Response<Body>` - Returns the postprocessed response.
    ///
    /// # Errors
    ///
    /// This function will return an error if the postprocessing fails.
    async fn postprocess_response(&self, res: Response<Body>) -> Response<Body> {
        res
    }

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

        // Check that body_json contains a 'document' value
        if !body_json.as_object().unwrap().contains_key("document") {
            return (false, Some("Request body does not contain 'document' key".to_string()));
        }

        (true, None)
    }

}
