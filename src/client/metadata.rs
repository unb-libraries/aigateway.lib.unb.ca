//!
//! This module provides functionality for extracting metadata from HTTP requests and responses.
//!
//! Functions:
//! - `RequestMetadata::from_request`: Extracts metadata from an HTTP request.
//! - `ResponseMetadata::from_response`: Extracts metadata from an HTTP response.
use hyper::{Body, HeaderMap, Method, Request, Response, StatusCode, Uri};
use hyper::header::HeaderValue;
use serde_json;

/// Metadata describing an HTTP request.
/// 
/// Fields:
/// - `_auth_header`: An optional header value for authentication.
/// - `pub_key`: String value for the public key.
/// - `auth_key_value`: String value for the authentication key.
/// - `body`: The body of the request as a String.
/// - `headers`: The headers of the request.
/// - `ip`: The IP address of the request.
/// - `client_ip`: The client's IP address.
/// - `method`: The HTTP method of the request.
/// - `uri`: The URI of the request.
///
pub struct RequestMetadata {
    pub _auth_header: Option<HeaderValue>,
    pub pub_key: Option<String>,
    pub auth_key_value: Option<String>,
    pub body: String,
    pub headers: HeaderMap,
    pub ip: String,
    pub client_ip: String,
    pub method: Method,
    pub uri: Uri,
}

/// Metadata describing an HTTP response.
/// 
/// Fields:
/// - `body`: The body of the response as a String.
/// - `headers`: The headers of the response.
/// - `ip`: The IP address of the response.
/// - `client_ip`: The client's IP address.
/// - `status`: The status code of the response.
///
pub struct ResponseMetadata {
    pub body: String,
    pub headers: HeaderMap,
    pub ip: String,
    pub client_ip: String,
    pub status: StatusCode,
    pub response: String,
}

impl RequestMetadata {
    /// Creates a `RequestMetadata` instance from an HTTP request.
    ///
    /// This function takes an HTTP request, extracts its parts, and constructs a `RequestMetadata`
    /// instance containing the request's body, headers, method, URI, and an optional API key. It also
    /// returns a clone of the original request. This is necessary because the request object cannot
    /// be cloned directly. Yes, there is a GitHub issue about this. No, they aren't going to fix it.
    ///
    /// # Arguments
    ///
    /// * `req` - The HTTP request to extract metadata from.
    /// * `addr` - The IP address of the client.
    ///
    /// # Returns
    ///
    /// A tuple containing the `RequestMetadata` instance and the original HTTP request.
    ///
    /// # Example
    ///
    /// ```
    /// let (metadata, req) = RequestMetadata::from_request(request).await;
    /// ```
    pub async fn from_request(req: Request<Body>, addr: String, strip_auth: bool) -> (Self, Request<Body>) {
        let (mut parts, body) = req.into_parts();
        let body_bytes = hyper::body::to_bytes(body).await.unwrap();
        let req_body = String::from_utf8(body_bytes.to_vec()).unwrap();
        
        let req_auth_header = parts.headers.get("x-api-key").cloned();
        let req_auth_key_value = req_auth_header.as_ref().and_then(|h| h.to_str().ok()).map(String::from);

        let req_pub_key = parts.headers.get("x-pub-key").cloned();
        let req_pub_key_value = req_pub_key.as_ref().and_then(|h| h.to_str().ok()).map(String::from);

        let req_uri = parts.uri.clone();
        let req_method = parts.method.clone();
        let req_headers = parts.headers.clone();
        let client_ip_address = parts.headers.get("x-forwarded-for").cloned().unwrap_or_else(|| HeaderValue::from_str(&addr).unwrap());
        
        // Strip the auth header if specified.
        if strip_auth {
            parts.headers.remove("x-api-key");
            parts.headers.remove("x-pub-key");
            // recalclate the content-length header
            let content_length = body_bytes.len();
            parts.headers.insert("content-length", HeaderValue::from(content_length));
        }

        let req_clone = Request::from_parts(parts, Body::from(body_bytes.clone()));

        let metadata = RequestMetadata {
            body: req_body,
            _auth_header: req_auth_header,
            auth_key_value: req_auth_key_value,
            pub_key: req_pub_key_value,
            uri: req_uri,
            method: req_method,
            headers: req_headers,
            ip: addr,
            client_ip: client_ip_address.to_str().unwrap().to_string(),
        };

        (metadata, req_clone)
    }
}

impl ResponseMetadata {
    /// Creates a `ResponseMetadata` instance from a given `Response<Body>`.
    ///
    /// This function takes an HTTP response, extracts its parts (headers, status, and body),
    /// and constructs a `ResponseMetadata` object containing these parts. It also returns
    /// a clone of the original response. This is due to the fact that the response is consumed.
    ///
    /// # Arguments
    ///
    /// * `res` - An HTTP response of type `Response<Body>`.
    /// * `addr` - The IP address of the client.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - `ResponseMetadata` instance with the extracted metadata.
    /// - A clone of the original `Response<Body>`.
    ///
    /// # Panics
    ///
    /// This function will panic if the body bytes cannot be converted to a UTF-8 string.
    pub async fn from_response(res: Response<Body>, addr: String) -> (Self, Response<Body>) {
        let (parts, body) = res.into_parts();
        let body_bytes = hyper::body::to_bytes(body).await.unwrap();
        let res_body = String::from_utf8(body_bytes.to_vec()).unwrap();
        let res_headers = parts.headers.clone();
        let client_ip_address = parts.headers.get("x-forwarded-for").cloned().unwrap_or_else(|| HeaderValue::from_str(&addr).unwrap());
        let res_status = parts.status.clone();
        
        let body_json: serde_json::Value = match serde_json::from_str(&res_body) {
            Ok(json) => json,
            Err(_) => serde_json::Value::Null,
        };
        let response = body_json.get("response").unwrap_or(&serde_json::Value::Null);

        let req_clone = Response::from_parts(parts, Body::from(body_bytes.clone()));
        
        let metadata = ResponseMetadata {
            body: res_body,
            headers: res_headers,
            status: res_status,
            ip: addr,
            client_ip: client_ip_address.to_str().unwrap().to_string(),
            response: response.to_string(),
        };

        (metadata, req_clone)
    }
}
