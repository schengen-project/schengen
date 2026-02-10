// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests for schengen client

mod common;

use schengen::client::{Builder, ClientError};
use std::time::Duration;

#[tokio::test]
async fn test_client_builder_requires_server_address() {
    // Builder should require server_addr before connect
    let _builder = Builder::new().name("test-client").dimensions(1920, 1080);

    // This shouldn't compile if we tried to call .connect() here
    // (enforced by typestate pattern)
}

#[tokio::test]
async fn test_client_connection_retry_with_max_retries() {
    let result = Builder::new()
        .server_addr("127.0.0.1:9999")
        .unwrap() // Use a port that's definitely not listening
        .name("test-client")
        .dimensions(1920, 1080)
        .retry_count(1) // Only try once
        .retry_interval(Duration::from_millis(10))
        .connect()
        .await;

    assert!(
        result.is_err(),
        "Should fail to connect to non-existent server"
    );

    if let Err(ClientError::MaxRetriesExceeded(count)) = result {
        assert_eq!(count, 1, "Should report correct retry count");
    } else {
        panic!("Expected MaxRetriesExceeded error");
    }
}

#[tokio::test]
async fn test_client_connection_timeout() {
    let result = Builder::new()
        .server_addr("127.0.0.1:9998")
        .unwrap()
        .name("test-client")
        .dimensions(1920, 1080)
        .retry_count(100) // High retry count
        .retry_interval(Duration::from_millis(100))
        .connection_timeout(Duration::from_millis(250)) // But short timeout
        .connect()
        .await;

    assert!(result.is_err(), "Should timeout before max retries");

    if let Err(ClientError::ConnectionTimeoutExceeded(_)) = result {
        // Expected
    } else {
        panic!("Expected ConnectionTimeoutExceeded error");
    }
}

#[tokio::test]
async fn test_client_dimension_configuration() {
    let _builder = Builder::new().dimensions(2560, 1440).name("test");

    // Dimensions should be stored (we can't directly verify without connecting,
    // but the builder accepts them)
}

#[tokio::test]
async fn test_client_retry_interval_configuration() {
    let _builder = Builder::new()
        .retry_interval(Duration::from_secs(5))
        .name("test");

    // Configuration should be accepted
}

#[tokio::test]
async fn test_client_name_configuration() {
    let _builder = Builder::new().name("my-custom-client");

    // Name should be stored
}

#[tokio::test]
async fn test_client_parse_host_port_ipv4() {
    let result = Builder::new().server_addr("192.168.1.100:24801");
    assert!(result.is_ok(), "Should parse IPv4:port");
}

#[tokio::test]
async fn test_client_parse_host_port_ipv4_default() {
    let result = Builder::new().server_addr("192.168.1.100");
    assert!(result.is_ok(), "Should parse IPv4 with default port");
}

#[tokio::test]
async fn test_client_parse_host_port_hostname() {
    let result = Builder::new().server_addr("localhost:24801");
    assert!(result.is_ok(), "Should parse hostname:port");
}

#[tokio::test]
async fn test_client_parse_host_port_ipv6_bracketed() {
    let result = Builder::new().server_addr("[::1]:24801");
    assert!(result.is_ok(), "Should parse [IPv6]:port");
}

#[tokio::test]
async fn test_client_parse_host_port_ipv6_no_port() {
    let result = Builder::new().server_addr("[::1]");
    assert!(result.is_ok(), "Should parse [IPv6] with default port");
}

#[tokio::test]
async fn test_client_parse_host_port_ipv6_bare() {
    let result = Builder::new().server_addr("::1");
    assert!(result.is_ok(), "Should parse bare IPv6");
}

#[tokio::test]
async fn test_client_parse_host_port_ipv6_full() {
    let result = Builder::new().server_addr("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    assert!(result.is_ok(), "Should parse full IPv6");
}
