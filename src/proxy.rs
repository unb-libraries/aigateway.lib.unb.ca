//! # Proxy Module
//! 
//! This module handles proxying incoming HTTP requests to the appropriate upstream server.
//! 
//! ## Functions
//! - `proxy_request`: Proxies the incoming request to the appropriate upstream server.
//! - `check_key_access`: Checks if the provided keys have access to the requested resource.
//! - `preprocess_request`: Global preprocesses for all adapters before sending request to the upstream server.
//! - `postprocess_response`: lobal postprocesses for all adapters before returning response to the client.

use std::sync::Arc;

use hyper::{Body, Client, Request, Response, StatusCode};
use hyper::client::HttpConnector;
use uuid::Uuid;

use crate::adapters::deckard_llm::DeckardLLMv1;
use crate::auth::{self, KeyEntry};
use crate::client::metadata::{RequestMetadata, ResponseMetadata};
use crate::config::Config;
use crate::logging::proxy::{log_llm_query, log_llm_query_response};

/// Proxies the incoming request to the appropriate upstream server.
/// 
/// # Arguments
/// 
/// * `req` - The incoming HTTP request.
/// * `config` - Shared configuration settings.
/// * `request_id` - Unique identifier for the request.
/// * `addr` - Client's IP address.
/// * `auth_keys` - Authentication keys.
/// * `req_time` - Timestamp when the request was received.
/// 
/// # Returns
/// 
/// * `Result<Response<Body>, hyper::Error>` - The HTTP response or an error.
pub async fn proxy_request(req: Request<Body>, config: Arc<Config>, request_id: Uuid, addr: String, auth_keys: Arc<Vec<KeyEntry>>, req_time: chrono::DateTime<chrono::Utc>) -> Result<Response<Body>, hyper::Error> {
    let connector = HttpConnector::new();
    let client = Client::builder()
        .http2_adaptive_window(true)
        .build(connector);
    let path = req.uri().path().to_string();

    // Key authentication.
    let result = check_key_access(auth_keys, req, &path, config.clone(), request_id, addr.clone(), req_time.clone()).await;
    let (req, _) = match result {
        Ok(val) => val,
        Err(response) => return Ok(response),
    };

    // Determine the adapter.
    let config_clone = config.clone();
    let endpoint = config_clone.endpoints.get(&path).unwrap();
    let _adapter_name = endpoint.adapter.as_str();

    // Preprocess all requests.
    let req = preprocess_request(req).await;

    // @TODO These should pass through dynamic adapters in the future based on config.
    // Adapters? Interfaces? Endpoints? Not sure what to call them yet.
    // For now we'll just manually specify the DeckardLLMv1 adapter.
    let adapter = DeckardLLMv1::new();

    // Send the request to the upstream server.
    let response = adapter.handle_request(req, client, &endpoint, config.clone(), request_id, addr.clone(), req_time).await?;

    // If the response is an error, return it. The error should be logged at the adapter.
    if response.status().is_server_error() {
        return Ok(response);
    }

    // Postprocess all valid responses.
    let response = postprocess_response(response).await;

    // Finally log the successful response.
    let (response_metadata, response) = ResponseMetadata::from_response(response, addr.clone()).await;
    let query_response = "Placeholder for query response";
    let response_time = chrono::Utc::now().signed_duration_since(req_time).num_milliseconds();

    tokio::spawn(async move {
        log_llm_query_response(
            request_id,
            req_time,
            response_time,
            response_metadata.ip.as_str(),
            response_metadata.client_ip.as_str(),
            format!("{:?}", response_metadata.headers).as_str(),
            response_metadata.body.as_str(),
            response_metadata.status.as_u16(),
            query_response,
            &config,
        ).await;
    });

    Ok(response)
}

/// Preprocesses the HTTP request.
///
/// @TODO: THIS IS STUBBED OUT AND NEEDS TO BE IMPLEMENTED.
///
/// # Arguments
///
/// * `req` - The incoming HTTP request.
///
/// # Returns
///
/// * `Request<Body>` - The preprocessed HTTP request.
async fn preprocess_request(req: Request<Body>) -> Request<Body> {
    req
}

/// Postprocess the reponse.
///
/// @TODO: THIS IS STUBBED OUT AND NEEDS TO BE IMPLEMENTED.
///
/// # Arguments
///
/// * `req` - The incoming HTTP request.
///
/// # Returns
///
/// * `Request<Body>` - The preprocessed HTTP request.
async fn postprocess_response(res: Response<Body>) -> Response<Body> {
    res
}

/// Checks if the provided key has access to the requested endpoint.
///
/// This takes a bit of time (~100ms) Performance could be presumably improved by caching or using something like
/// Kong. !Important!: ~100ms is generally small compared to the time the actual inference takes. The benefits
/// may not be worth the effort.
/// 
/// # Arguments
///
/// * `keys` - Authentication keys.
/// * `req` - The incoming HTTP request.
/// * `path` - The requested path.
/// * `config` - Shared configuration settings.
/// * `request_id` - Unique identifier for the request.
/// * `addr` - Client's IP address.
/// * `req_time` - Timestamp when the request was received.
///
/// # Returns
///
/// * `Result<(Request<Body>, ()), Response<Body>>` - The request if access is granted, or a forbidden response.
async fn check_key_access(keys: Arc<Vec<KeyEntry>>, req: Request<Body>, path: &str, config: Arc<Config>, request_id: Uuid, addr: String, req_time: chrono::DateTime<chrono::Utc>) -> Result<(Request<Body>, ()), Response<Body>> {
    let (request_metadata, req) = RequestMetadata::from_request(req, addr.clone()).await;
    let auth_failure_message = &config.clone().messages.auth_failure; // Update to use auth_failure
    let mut key_fail_message = "";
    let pub_key = request_metadata.pub_key.clone().unwrap_or_default();

    if pub_key == "" {
        key_fail_message = "PubKey is empty";
    }
    else if !auth::key_exists(keys.clone(), pub_key.clone()).await {
        key_fail_message = "PubKey does not exist";
    }
    else if !auth::key_is_unexpired(keys.clone(),pub_key.clone()).await {
        key_fail_message = "PubKey is expired";
    }
    else if !auth::key_has_endpoint_access(keys.clone(), pub_key.clone(), &path).await {
        key_fail_message = "PubKey does not have access to the endpoint";
    }
    else if !auth::validate_key(keys, pub_key, request_metadata.auth_key_value.unwrap_or_default()).await {
        key_fail_message = "Private key does not validate";
    }

    if key_fail_message != "" {
        let response_time = chrono::Utc::now().signed_duration_since(req_time).num_milliseconds();
        tokio::spawn(async move {
            log_llm_query(
                request_id,
                req_time,
                response_time,
                request_metadata.ip.as_str(),
                request_metadata.client_ip.as_str(),
                request_metadata.method.as_str(),
                request_metadata.uri.path(),
                format!("{:?}", request_metadata.headers).as_str(),
                request_metadata.body.as_str(),
                503,
                key_fail_message,
                &config,
            ).await;
        });
        let mut response = Response::new(Body::from(auth_failure_message.clone()));
        *response.status_mut() = StatusCode::FORBIDDEN;
        return Err(response);
    }
    Ok((req, ()))
}

