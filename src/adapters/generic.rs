use std::sync::Arc;

use async_trait::async_trait;
use hyper::{Client, Request, Response, Body};
use hyper::client::HttpConnector;
use uuid::Uuid;

use crate::config::{Config, EndpointConfig};
use crate::client::metadata::RequestMetadata;

use crate::logging::proxy::{log_llm_query, log_llm_query_response};

#[async_trait]
pub trait GenericInferenceEndpointAdapter {

    const BODY_VALUE_FIELD_TO_LOG: &'static str;
    const USER_AGENT: &'static str;

    async fn handle_request(
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
        // The design intent is to only use HTTP from the balancer inward.
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
            let log_reason = reason.clone().unwrap();
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
                    format!("Request metadata is invalid: {:?}", log_reason).as_str(),
                    &config,
                ).await;
            });
            // Construct a response with a malformed status code.
            let mut response = Response::new(Body::from(format!("Bad request: {}", reason.unwrap())));
            *response.status_mut() = hyper::StatusCode::BAD_REQUEST;
            return Ok(response);
        }

        // Preprocess requests specifically for this endpoint.
        let req = self.preprocess_request(req).await;

        // Get the query string from the request body.
        let body_json: serde_json::Value = serde_json::from_str(&request_metadata.body).unwrap();
        let value_to_log = body_json[Self::BODY_VALUE_FIELD_TO_LOG].as_str().unwrap().to_string();

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
                format!("Query: {:?}", value_to_log).as_str(),
                &config_clone,
            ).await;
        });

        // Build the proxied request.
        let (request_metadata, req) = RequestMetadata::from_request(req, addr.clone(), true).await;
        let mut proxied_request = Request::builder()
            .method(request_metadata.method.clone())
            .header("content-type", "application/json")
            .header("user-agent", Self::USER_AGENT)
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

    async fn check_request_metadata(&self, request_metadata: RequestMetadata) -> (bool, Option<String>);

}
