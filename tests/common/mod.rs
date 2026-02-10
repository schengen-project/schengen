// SPDX-License-Identifier: GPL-3.0-or-later

//! Common utilities for integration tests

use schengen::server::{Builder as ServerBuilder, Position};
use tokio::net::TcpListener;

/// Spawn a test server on a random port with a single configured client
///
/// Returns the server and the port it's listening on
#[allow(dead_code)]
pub async fn spawn_test_server(client_name: &str) -> (schengen::server::Server, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let client = schengen::server::ClientBuilder::new(client_name)
        .position(Position::Left)
        .build();

    let server = ServerBuilder::new()
        .add_client(client)
        .unwrap()
        .listen_on_stream(listener)
        .await
        .unwrap();

    (server, port)
}

/// Spawn a test server with multiple configured clients
///
/// Returns the server and the port it's listening on
#[allow(dead_code)]
pub async fn spawn_test_server_multi(
    clients: Vec<(String, Position, Option<String>)>,
) -> (schengen::server::Server, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let mut builder = ServerBuilder::new();
    let mut built_clients = std::collections::HashMap::new();

    // First pass: add clients without references
    for (name, position, reference) in &clients {
        if reference.is_none() {
            let client = schengen::server::ClientBuilder::new(name)
                .position(*position)
                .build();
            built_clients.insert(name.clone(), client.clone());
            builder = builder.add_client(client).unwrap();
        }
    }

    // Second pass: add clients with references
    for (name, position, reference) in &clients {
        if let Some(ref_name) = reference {
            let ref_client = built_clients
                .get(ref_name)
                .expect("Reference client not found");
            let client = schengen::server::ClientBuilder::new(name)
                .position(*position)
                .relative_to(ref_client)
                .build();
            built_clients.insert(name.clone(), client.clone());
            builder = builder.add_client(client).unwrap();
        }
    }

    let server = builder.listen_on_stream(listener).await.unwrap();

    (server, port)
}

/// Create a test client builder with default dimensions
#[allow(dead_code)]
pub fn test_client_builder() -> schengen::client::Builder<schengen::client::NeedsAddress> {
    schengen::client::Builder::new().dimensions(1920, 1080)
}

/// Wait for a condition with timeout
#[allow(dead_code)]
pub async fn wait_for<F, Fut>(mut condition: F, timeout_ms: u64) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(timeout_ms);

    while start.elapsed() < timeout {
        if condition().await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    false
}
