
use std::sync::Arc;

use hyper::{server::conn::AddrStream, service::{make_service_fn, service_fn}, Body, Request, Server};
use uuid::Uuid;

use crate::auth::load_keys;
use crate::config::load_config;

/// Starts the gateway.
///
/// # Returns
/// 
/// A `Result` which is `Ok` if the server runs successfully, or an `Err` if an error occurs.
///
/// # Errors
///
/// This function will return an error if the server fails to bind to the specified address and port,
/// or if there is an error while running the server.
pub async fn start_server() -> Result<(), Box<dyn std::error::Error>> {
    let config = Arc::new(load_config().await);
    let server_config = Arc::clone(&config);

    let keys = Arc::new(load_keys().await);
    let key_config = Arc::clone(&keys);

    let make_svc = make_service_fn(move |conn: &AddrStream| {
        let config = Arc::clone(&server_config);
        let keys = Arc::clone(&key_config);
        let remote_addr = conn.remote_addr().to_string();
        let req_time = chrono::Utc::now();

        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                let config = Arc::clone(&config);
                let keys = Arc::clone(&keys);
                let request_id = Uuid::new_v4();
                let addr = remote_addr.clone();
                crate::proxy::proxy_request(req, config, request_id, addr, keys, req_time)
            }))
        }
    });

    // Start the server
    let addr = (config.adapter.parse::<std::net::IpAddr>()?, config.port).into();
    let server = Server::bind(&addr).serve(make_svc);
    println!("Server running on http://{}", addr);

    // Run the server
    server.await?;
    Ok(())
}
