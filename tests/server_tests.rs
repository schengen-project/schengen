// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests for schengen server

mod common;

use schengen::server::{Builder, ClientBuilder, Position};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_server_binds_to_port() {
    let client = ClientBuilder::new("test-client")
        .position(Position::Left)
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _port = listener.local_addr().unwrap().port();

    let server = Builder::new()
        .add_client(client)
        .unwrap()
        .listen_on_stream(listener)
        .await;

    assert!(server.is_ok(), "Server should start successfully");

    // Verify we can get clients list
    let server = server.unwrap();
    let clients = server.clients().await;
    assert_eq!(clients.len(), 0, "No clients should be connected yet");
}

#[tokio::test]
async fn test_server_rejects_duplicate_positions() {
    let client1 = ClientBuilder::new("client1")
        .position(Position::Left)
        .build();

    let client2 = ClientBuilder::new("client2")
        .position(Position::Left)
        .build();

    let result = Builder::new()
        .add_client(client1)
        .unwrap()
        .add_client(client2);

    assert!(result.is_err(), "Should reject duplicate positions");
}

#[tokio::test]
async fn test_server_accepts_different_positions() {
    let laptop = ClientBuilder::new("laptop")
        .position(Position::Left)
        .build();

    let desktop = ClientBuilder::new("desktop")
        .position(Position::Right)
        .build();

    let tablet = ClientBuilder::new("tablet")
        .position(Position::Above)
        .build();

    let phone = ClientBuilder::new("phone")
        .position(Position::Below)
        .build();

    let result = Builder::new()
        .add_client(laptop)
        .unwrap()
        .add_client(desktop)
        .unwrap()
        .add_client(tablet)
        .unwrap()
        .add_client(phone);

    assert!(
        result.is_ok(),
        "Should accept clients at different positions"
    );
}

#[tokio::test]
async fn test_server_relative_positioning() {
    let laptop = ClientBuilder::new("laptop")
        .position(Position::Left)
        .build();

    let monitor = ClientBuilder::new("monitor")
        .position(Position::Below)
        .relative_to(&laptop)
        .build();

    let result = Builder::new()
        .add_client(laptop)
        .unwrap()
        .add_client(monitor);

    assert!(result.is_ok(), "Should accept relative positioning");
}

#[tokio::test]
async fn test_server_rejects_relative_to_nonexistent_client() {
    let laptop = ClientBuilder::new("laptop")
        .position(Position::Left)
        .build();

    let phantom = ClientBuilder::new("phantom")
        .position(Position::Right)
        .build();

    let monitor = ClientBuilder::new("monitor")
        .position(Position::Below)
        .relative_to(&phantom)
        .build();

    let result = Builder::new()
        .add_client(laptop)
        .unwrap()
        .add_client(monitor);

    assert!(
        result.is_err(),
        "Should reject reference to non-added client"
    );
}

#[tokio::test]
async fn test_server_rejects_duplicate_relative_positions() {
    let laptop = ClientBuilder::new("laptop")
        .position(Position::Left)
        .build();

    let monitor1 = ClientBuilder::new("monitor1")
        .position(Position::Below)
        .relative_to(&laptop)
        .build();

    let monitor2 = ClientBuilder::new("monitor2")
        .position(Position::Below)
        .relative_to(&laptop)
        .build();

    let result = Builder::new()
        .add_client(laptop)
        .unwrap()
        .add_client(monitor1)
        .unwrap()
        .add_client(monitor2);

    assert!(
        result.is_err(),
        "Should reject duplicate relative positions"
    );
}

#[tokio::test]
async fn test_server_port_configuration() {
    let client = ClientBuilder::new("test").position(Position::Left).build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _port = listener.local_addr().unwrap().port();

    let server = Builder::new()
        .add_client(client)
        .unwrap()
        .listen_on_stream(listener)
        .await
        .unwrap();

    // Server should be listening (we can't directly check the port from Server API,
    // but the fact that it started successfully is verification enough)
    let clients = server.clients().await;
    assert_eq!(clients.len(), 0);
}

#[tokio::test]
async fn test_server_clients_list_empty_on_start() {
    let (server, _port) = common::spawn_test_server("test-client").await;

    let clients = server.clients().await;
    assert_eq!(
        clients.len(),
        0,
        "Server should start with no connected clients"
    );
}

#[tokio::test]
async fn test_server_multiple_clients_configuration() {
    let clients = vec![
        ("laptop".to_string(), Position::Left, None),
        ("desktop".to_string(), Position::Right, None),
        (
            "tablet".to_string(),
            Position::Below,
            Some("laptop".to_string()),
        ),
    ];

    let (server, _port) = common::spawn_test_server_multi(clients).await;

    let connected = server.clients().await;
    assert_eq!(
        connected.len(),
        0,
        "No clients should be connected yet (only configured)"
    );
}
