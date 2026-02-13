# schengen

`schengen` is a Rust library for building Synergy/Deskflow-compatible clients
and servers for mouse and keyboard sharing across multiple computers.

This crate provides the core protocol implementation and high-level APIs for
parsing and serializing Synergy/Deskflow protocol messages and building
Synergy/Deskflow clients and servers.

The goal is to be able to build a client or server without needing much
knowledge of the protocol itself.

This crate is part of the schengen project:
- [schengen](https://github.com/schengen-project/schengen) for the protocol implementation
- [schengen-server](https://github.com/schengen-project/schengen-server) for a synergy-compatible server
- [schengen-client](https://github.com/schengen-project/schengen-client) for a client that can connect to this server
- [schengen-debugger](https://github.com/schengen-project/schengen-debugger) for a protocol debugger

## About the Protocol

Schengen implements the Synergy/Deskflow protocol, which is compatible with:
- [Synergy](https://symless.com/synergy) - the original implementation
- [Barrier](https://github.com/debauchee/barrier) - a fork of Synergy 1.9
- [Input-Leap](https://github.com/input-leap/input-leap) - a fork of Barrier
- [Deskflow](https://github.com/deskflow/deskflow/) - the currently maintained core

For more details on protocol compatibility, see the crate documentation.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
schengen = "0.1"
```

### Building a Client

```rust
use schengen::client::{Builder, ClientEvent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Builder::new()
        .server_addr("localhost:24801")?
        .name("my-client")
        .dimensions(1920, 1080)
        .connect()
        .await?;

    loop {
        match client.recv_event().await? {
            ClientEvent::CursorEntered { x, y, .. } => {
                println!("Cursor entered at ({}, {})", x, y);
            }
            ClientEvent::CursorLeft => {
                println!("Cursor left");
                break;
            }
            _ => {}
        }
    }

    Ok(())
}
```

### Building a Server

```rust
use schengen::server::{Builder, ClientBuilder, Position, ServerEvent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let laptop = ClientBuilder::new("laptop")
        .position(Position::Left)
        .build();

    let mut server = Builder::new()
        .listen_addr("0.0.0.0:24801")?
        .add_client(laptop)
        .build()
        .await?;

    loop {
        let event = server.recv_event().await?;
        // Handle server events
    }

    Ok(())
}
```

### Working with the Protocol

```rust
use schengen::protocol::{Message, parse_message, ProtocolMessage};

// Parse a message from bytes
let data = b"CALV";
let msg = parse_message(data)?;
```

## Building

This is a typical Rust crate. Build with:

```
$ cargo build
$ cargo test
```

## Documentation

Build the documentation with:

```
$ cargo doc --open
```

## License

GPLv3 or later
