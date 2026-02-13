// SPDX-License-Identifier: GPL-3.0-or-later

//! # Schengen Protocol
//!
//! A Rust implementation of the Synergy/Deskflow protocol for mouse and keyboard sharing.
//!
//! This module provides a protocol-level API for parsing and serializing Synergy/Deskflow
//! protocol messages. It only handles the protocol encoding/decoding, not the actual I/O.
//!
//! ## Protocol Overview
//!
//! The Synergy protocol uses a simple binary format where each message consists of:
//! - A 4-byte big-endian length prefix (length of the message data, not including the prefix)
//! - The message data, which starts with a 4-character ASCII prefix (e.g., "CINN", "DMMV")
//! - Additional fields depending on the message type
//!
//! ## Working with Protocol Messages
//!
//! All protocol messages implement the [`ProtocolMessage`] trait, which provides:
//! - `from_bytes()` - Parse a message from raw bytes
//! - `to_bytes()` - Serialize a message to raw bytes
//! - `CODE` - The protocol code constant for the message type
//!
//! You can work with individual message types directly using the trait, or use the
//! [`Message`] enum for polymorphic message handling.
//!
//! ## Example Usage
//!
//! ```
//! use schengen::protocol::{Message, parse_message, ProtocolMessage, MessageKeepAlive};
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Parse a message from bytes (without the length prefix)
//! let data = b"CALV";
//! let msg = parse_message(data)?;
//! match msg {
//!     Message::KeepAlive(m) => println!("Received keepalive"),
//!     _ => println!("Other message: {:?}", msg),
//! }
//!
//! // Work with specific message types using the ProtocolMessage trait
//! let keepalive = MessageKeepAlive;
//! let bytes = keepalive.to_bytes(); // Returns b"CALV"
//!
//! // Use the Message enum for messages with length prefix
//! let msg_enum = Message::KeepAlive(MessageKeepAlive);
//! let bytes_with_length = msg_enum.to_bytes(); // Includes 4-byte length prefix
//! # Ok(())
//! # }
//! ```
//!
//! ## Messages
//!
//! The following protocol messages are supported:
//!
//! | Code | Message Type | Description |
//! |------|--------------|-------------|
//! | `Barrier` | [`MessageHelloBarrier`] | Hello (Barrier/Input-Leap/Deskflow) |
//! | `Synergy` | [`MessageHelloSynergy`] | Hello (legacy Synergy) |
//! | `CNOP` | [`MessageNoOp`] | No operation / keepalive |
//! | `CBYE` | [`MessageClose`] | Close connection |
//! | `CINN` | [`MessageCursorEntered`] | Cursor entered screen |
//! | `COUT` | [`MessageCursorLeft`] | Cursor left screen |
//! | `CCLP` | [`MessageClientClipboard`] | Clipboard from client |
//! | `CSEC` | [`MessageScreenSaverChange`] | Screen saver state change |
//! | `CROP` | [`MessageResetOptions`] | Reset options |
//! | `CIAK` | [`MessageInfoAcknowledgment`] | Info acknowledgment |
//! | `CALV` | [`MessageKeepAlive`] | Keepalive |
//! | `DKDL` | [`MessageKeyDownWithLanguage`] | Key down with language |
//! | `DKDN` | [`MessageKeyDown`] | Key down |
//! | `DKRP` | [`MessageKeyRepeat`] | Key repeat |
//! | `DKUP` | [`MessageKeyUp`] | Key up |
//! | `DMDN` | [`MessageMouseButtonDown`] | Mouse button down |
//! | `DMUP` | [`MessageMouseButtonUp`] | Mouse button up |
//! | `DMMV` | [`MessageMouseMove`] | Mouse move (absolute) |
//! | `DMRM` | [`MessageMouseRelativeMove`] | Mouse move (relative) |
//! | `DMWM` | [`MessageMouseWheel`] | Mouse wheel |
//! | `DCLP` | [`MessageClipboardData`] | Clipboard data |
//! | `DINF` | [`MessageClientInfo`] | Client info |
//! | `DSOP` | [`MessageSetOptions`] | Set options |
//! | `DFTR` | [`MessageFileTransfer`] | File transfer |
//! | `DDRG` | [`MessageDragInfo`] | Drag info |
//! | `SECN` | [`MessageSecureEncryption`] | Secure encryption |
//! | `LSYN` | [`MessageLegacySynergy`] | Legacy synergy |
//! | `QINF` | [`MessageQueryInfo`] | Query info |
//! | `EICV` | [`MessageIncompatibleVersion`] | Incompatible version error |
//! | `EBSY` | [`MessageServerBusy`] | Server busy error |
//! | `EUNK` | [`MessageUnknownClient`] | Unknown client error |
//! | `EBAD` | [`MessageProtocolError`] | Protocol error |

use std::error::Error;
use std::fmt;

/// Errors that can occur during protocol message parsing or serialization
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// Not enough data to parse the message
    InsufficientData { expected: usize, actual: usize },
    /// Unknown message code encountered
    UnknownMessageCode(String),
    /// Invalid UTF-8 string in message data
    InvalidUtf8,
    /// Message code doesn't match expected length
    InvalidMessageCode,
    /// Invalid data format or content
    InvalidData(String),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::InsufficientData { expected, actual } => {
                write!(
                    f,
                    "Insufficient data: expected {} bytes, got {}",
                    expected, actual
                )
            }
            ProtocolError::UnknownMessageCode(code) => {
                write!(f, "Unknown message code: {}", code)
            }
            ProtocolError::InvalidUtf8 => {
                write!(f, "Invalid UTF-8 string in message data")
            }
            ProtocolError::InvalidMessageCode => {
                write!(f, "Invalid message code")
            }
            ProtocolError::InvalidData(msg) => {
                write!(f, "Invalid data: {}", msg)
            }
        }
    }
}

impl Error for ProtocolError {}

/// Result type for protocol operations
pub type Result<T> = std::result::Result<T, ProtocolError>;

// Helper function to read big-endian integers
fn read_u8(data: &[u8], offset: usize) -> Result<u8> {
    data.get(offset)
        .copied()
        .ok_or(ProtocolError::InsufficientData {
            expected: offset + 1,
            actual: data.len(),
        })
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    if data.len() < offset + 2 {
        return Err(ProtocolError::InsufficientData {
            expected: offset + 2,
            actual: data.len(),
        });
    }
    Ok(u16::from_be_bytes([data[offset], data[offset + 1]]))
}

fn read_i16(data: &[u8], offset: usize) -> Result<i16> {
    if data.len() < offset + 2 {
        return Err(ProtocolError::InsufficientData {
            expected: offset + 2,
            actual: data.len(),
        });
    }
    Ok(i16::from_be_bytes([data[offset], data[offset + 1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    if data.len() < offset + 4 {
        return Err(ProtocolError::InsufficientData {
            expected: offset + 4,
            actual: data.len(),
        });
    }
    Ok(u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// A string with a 4-byte big-endian length prefix
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LengthPrefixedString(pub String);

impl LengthPrefixedString {
    /// Read a length-prefixed string from bytes at the given offset
    /// Returns (LengthPrefixedString, bytes_consumed)
    fn from_bytes(data: &[u8], offset: usize) -> Result<(Self, usize)> {
        if data.len() < offset + 4 {
            return Err(ProtocolError::InsufficientData {
                expected: offset + 4,
                actual: data.len(),
            });
        }

        let length = read_u32(data, offset)? as usize;
        let string_start = offset + 4;

        if data.len() < string_start + length {
            return Err(ProtocolError::InsufficientData {
                expected: string_start + length,
                actual: data.len(),
            });
        }

        let string_bytes = &data[string_start..string_start + length];
        let string =
            String::from_utf8(string_bytes.to_vec()).map_err(|_| ProtocolError::InvalidUtf8)?;

        Ok((Self(string), 4 + length))
    }

    /// Write a length-prefixed string to bytes
    fn to_bytes(&self) -> Vec<u8> {
        let string_bytes = self.0.as_bytes();
        let mut result = Vec::with_capacity(4 + string_bytes.len());
        result.extend_from_slice(&(string_bytes.len() as u32).to_be_bytes());
        result.extend_from_slice(string_bytes);
        result
    }
}

impl From<String> for LengthPrefixedString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for LengthPrefixedString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for LengthPrefixedString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Trait for protocol messages that can be serialized to and deserialized from bytes
///
/// This trait provides a common interface for all Synergy/Deskflow protocol messages.
/// Each message type implements this trait to handle its specific binary format.
///
/// # Examples
///
/// ```
/// use schengen::protocol::{ProtocolMessage, MessageKeepAlive};
///
/// // Deserialize from bytes
/// let data = b"CALV";
/// let msg = MessageKeepAlive::from_bytes(data).unwrap();
///
/// // Serialize to bytes (without length prefix)
/// let bytes = msg.to_bytes();
/// assert_eq!(&bytes, b"CALV");
/// ```
pub trait ProtocolMessage: Sized {
    /// The 4-character (or 7-character for Hello messages) protocol code for this message type
    const CODE: &'static str;

    /// Parse a message from bytes (without the length prefix)
    ///
    /// # Arguments
    ///
    /// * `data` - The message data starting with the message code
    ///
    /// # Returns
    ///
    /// Returns the parsed message or an error if the data is malformed or insufficient
    fn from_bytes(data: &[u8]) -> Result<Self>;

    /// Serialize this message to bytes (without the length prefix)
    ///
    /// # Returns
    ///
    /// Returns a byte vector containing the message code followed by the message data
    fn to_bytes(&self) -> Vec<u8>;
}

// Protocol Messages

/// Hello with "Barrier" code. This is used in Barrier/Input-Leap/Deskflow
/// implementations.
///
/// This message is used in two contexts:
/// 1. Server sends to client without client_name (server hello)
/// 2. Client responds with client_name included (hello back)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageHelloBarrier {
    /// Protocol major version number
    pub major: u16,
    /// Protocol minor version number
    pub minor: u16,
    /// Optional client name (present in client's hello response)
    pub client_name: Option<String>,
}

impl ProtocolMessage for MessageHelloBarrier {
    const CODE: &'static str = "Barrier";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 4 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 4,
                actual: data.len(),
            });
        }

        let major = read_u16(data, Self::CODE.len())?;
        let minor = read_u16(data, Self::CODE.len() + 2)?;

        // Check if there's a client name after the version numbers (length-prefixed string)
        let client_name = if data.len() > Self::CODE.len() + 4 {
            let name_length_offset = Self::CODE.len() + 4;

            // Read the 4-byte length prefix
            if data.len() < name_length_offset + 4 {
                return Err(ProtocolError::InsufficientData {
                    expected: name_length_offset + 4,
                    actual: data.len(),
                });
            }

            let name_length = read_u32(data, name_length_offset)? as usize;
            let name_start = name_length_offset + 4;

            if data.len() < name_start + name_length {
                return Err(ProtocolError::InsufficientData {
                    expected: name_start + name_length,
                    actual: data.len(),
                });
            }

            let name_str = std::str::from_utf8(&data[name_start..name_start + name_length])
                .map_err(|_| ProtocolError::InvalidUtf8)?
                .to_string();
            Some(name_str)
        } else {
            None
        };

        Ok(Self {
            major,
            minor,
            client_name,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.extend_from_slice(&self.major.to_be_bytes());
        bytes.extend_from_slice(&self.minor.to_be_bytes());

        // Add client name if present (length-prefixed string)
        if let Some(ref name) = self.client_name {
            let name_bytes = name.as_bytes();
            bytes.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
            bytes.extend_from_slice(name_bytes);
        }

        bytes
    }
}

/// Hello with "Synergy" code. This is not used in Barrier/Input-Leap/Deskflow
/// implementations.
///
/// This message is used in two contexts:
/// 1. Server sends to client without client_name (server hello)
/// 2. Client responds with client_name included (hello back)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageHelloSynergy {
    /// Protocol major version number
    pub major: u16,
    /// Protocol minor version number
    pub minor: u16,
    /// Optional client name (present in client's hello response)
    pub client_name: Option<String>,
}

impl ProtocolMessage for MessageHelloSynergy {
    const CODE: &'static str = "Synergy";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 4 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 4,
                actual: data.len(),
            });
        }

        let major = read_u16(data, Self::CODE.len())?;
        let minor = read_u16(data, Self::CODE.len() + 2)?;

        // Check if there's a client name after the version numbers (length-prefixed string)
        let client_name = if data.len() > Self::CODE.len() + 4 {
            let name_length_offset = Self::CODE.len() + 4;

            // Read the 4-byte length prefix
            if data.len() < name_length_offset + 4 {
                return Err(ProtocolError::InsufficientData {
                    expected: name_length_offset + 4,
                    actual: data.len(),
                });
            }

            let name_length = read_u32(data, name_length_offset)? as usize;
            let name_start = name_length_offset + 4;

            if data.len() < name_start + name_length {
                return Err(ProtocolError::InsufficientData {
                    expected: name_start + name_length,
                    actual: data.len(),
                });
            }

            let name_str = std::str::from_utf8(&data[name_start..name_start + name_length])
                .map_err(|_| ProtocolError::InvalidUtf8)?
                .to_string();
            Some(name_str)
        } else {
            None
        };

        Ok(Self {
            major,
            minor,
            client_name,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.extend_from_slice(&self.major.to_be_bytes());
        bytes.extend_from_slice(&self.minor.to_be_bytes());

        // Add client name if present (length-prefixed string)
        if let Some(ref name) = self.client_name {
            let name_bytes = name.as_bytes();
            bytes.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
            bytes.extend_from_slice(name_bytes);
        }

        bytes
    }
}

/// No operation / keepalive
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageNoOp;

impl ProtocolMessage for MessageNoOp {
    const CODE: &'static str = "CNOP";

    fn from_bytes(_data: &[u8]) -> Result<Self> {
        Ok(Self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        Self::CODE.as_bytes().to_vec()
    }
}

/// Close connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageClose;

impl ProtocolMessage for MessageClose {
    const CODE: &'static str = "CBYE";

    fn from_bytes(_data: &[u8]) -> Result<Self> {
        Ok(Self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        Self::CODE.as_bytes().to_vec()
    }
}

/// Cursor entered screen
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageCursorEntered {
    /// Entry X coordinate - absolute screen position where cursor entered
    pub x: i16,
    /// Entry Y coordinate - absolute screen position where cursor entered
    pub y: i16,
    /// Sequence number used to order messages
    pub sequence: u32,
    /// Modifier key mask indicating which toggle keys (Caps Lock, Num Lock, etc.) are active
    pub mask: u16,
}

impl ProtocolMessage for MessageCursorEntered {
    const CODE: &'static str = "CINN";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 10 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 10,
                actual: data.len(),
            });
        }
        Ok(Self {
            x: read_i16(data, Self::CODE.len())?,
            y: read_i16(data, Self::CODE.len() + 2)?,
            sequence: read_u32(data, Self::CODE.len() + 4)?,
            mask: read_u16(data, Self::CODE.len() + 8)?,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.extend_from_slice(&self.x.to_be_bytes());
        bytes.extend_from_slice(&self.y.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.mask.to_be_bytes());
        bytes
    }
}

/// Cursor left screen
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageCursorLeft;

impl ProtocolMessage for MessageCursorLeft {
    const CODE: &'static str = "COUT";

    fn from_bytes(_data: &[u8]) -> Result<Self> {
        Ok(Self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        Self::CODE.as_bytes().to_vec()
    }
}

/// Clipboard from client
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageClientClipboard {
    /// Clipboard identifier (0 = primary clipboard for Ctrl+C/V, 1 = selection clipboard for middle-click on X11)
    pub id: u8,
    /// Sequence number from most recent Enter message
    pub sequence: u32,
}

impl ProtocolMessage for MessageClientClipboard {
    const CODE: &'static str = "CCLP";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 5 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 5,
                actual: data.len(),
            });
        }
        Ok(Self {
            id: read_u8(data, Self::CODE.len())?,
            sequence: read_u32(data, Self::CODE.len() + 1)?,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.push(self.id);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes
    }
}

/// Screen saver change
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageScreenSaverChange {
    /// Screensaver state (1 = started, 0 = stopped)
    pub state: u8,
}

impl ProtocolMessage for MessageScreenSaverChange {
    const CODE: &'static str = "CSEC";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 1 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 1,
                actual: data.len(),
            });
        }
        Ok(Self {
            state: read_u8(data, Self::CODE.len())?,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.push(self.state);
        bytes
    }
}

/// Reset options
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageResetOptions;

impl ProtocolMessage for MessageResetOptions {
    const CODE: &'static str = "CROP";

    fn from_bytes(_data: &[u8]) -> Result<Self> {
        Ok(Self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        Self::CODE.as_bytes().to_vec()
    }
}

/// Info acknowledgment
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageInfoAcknowledgment;

impl ProtocolMessage for MessageInfoAcknowledgment {
    const CODE: &'static str = "CIAK";

    fn from_bytes(_data: &[u8]) -> Result<Self> {
        Ok(Self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        Self::CODE.as_bytes().to_vec()
    }
}

/// Keepalive
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageKeepAlive;

impl ProtocolMessage for MessageKeepAlive {
    const CODE: &'static str = "CALV";

    fn from_bytes(_data: &[u8]) -> Result<Self> {
        Ok(Self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        Self::CODE.as_bytes().to_vec()
    }
}

/// Key down with language
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageKeyDownWithLanguage {
    /// Virtual key identifier (keysym on Linux/X11, platform-dependent)
    pub keyid: u16,
    /// Active modifier keys bitmask
    pub mask: u16,
    /// Physical key code (keycode/scancode, platform-dependent)
    pub button: u16,
    /// Keyboard language identifier
    pub lang: LengthPrefixedString,
}

impl ProtocolMessage for MessageKeyDownWithLanguage {
    const CODE: &'static str = "DKDL";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 6 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 6,
                actual: data.len(),
            });
        }
        let (lang, _) = LengthPrefixedString::from_bytes(data, Self::CODE.len() + 6)?;
        Ok(Self {
            keyid: read_u16(data, Self::CODE.len())?,
            mask: read_u16(data, Self::CODE.len() + 2)?,
            button: read_u16(data, Self::CODE.len() + 4)?,
            lang,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.extend_from_slice(&self.keyid.to_be_bytes());
        bytes.extend_from_slice(&self.mask.to_be_bytes());
        bytes.extend_from_slice(&self.button.to_be_bytes());
        bytes.extend_from_slice(&self.lang.to_bytes());
        bytes
    }
}

/// Key down
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageKeyDown {
    /// Virtual key identifier (keysym on Linux/X11, platform-dependent)
    pub keyid: u16,
    /// Active modifier keys bitmask
    pub mask: u16,
    /// Physical key code (keycode/scancode, platform-dependent)
    pub button: u16,
}

impl ProtocolMessage for MessageKeyDown {
    const CODE: &'static str = "DKDN";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 6 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 6,
                actual: data.len(),
            });
        }
        Ok(Self {
            keyid: read_u16(data, Self::CODE.len())?,
            mask: read_u16(data, Self::CODE.len() + 2)?,
            button: read_u16(data, Self::CODE.len() + 4)?,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.extend_from_slice(&self.keyid.to_be_bytes());
        bytes.extend_from_slice(&self.mask.to_be_bytes());
        bytes.extend_from_slice(&self.button.to_be_bytes());
        bytes
    }
}

/// Key repeat
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageKeyRepeat {
    /// Virtual key identifier (keysym on Linux/X11, platform-dependent)
    pub keyid: u16,
    /// Active modifier keys bitmask
    pub mask: u16,
    /// Physical key code (keycode/scancode, platform-dependent)
    pub button: u16,
    /// Number of repeat events since the last message
    pub count: u16,
    /// Keyboard language identifier
    pub lang: LengthPrefixedString,
}

impl ProtocolMessage for MessageKeyRepeat {
    const CODE: &'static str = "DKRP";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 8 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 8,
                actual: data.len(),
            });
        }
        let (lang, _) = LengthPrefixedString::from_bytes(data, Self::CODE.len() + 8)?;
        Ok(Self {
            keyid: read_u16(data, Self::CODE.len())?,
            mask: read_u16(data, Self::CODE.len() + 2)?,
            button: read_u16(data, Self::CODE.len() + 4)?,
            count: read_u16(data, Self::CODE.len() + 6)?,
            lang,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.extend_from_slice(&self.keyid.to_be_bytes());
        bytes.extend_from_slice(&self.mask.to_be_bytes());
        bytes.extend_from_slice(&self.button.to_be_bytes());
        bytes.extend_from_slice(&self.count.to_be_bytes());
        bytes.extend_from_slice(&self.lang.to_bytes());
        bytes
    }
}

/// Key up
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageKeyUp {
    /// Virtual key identifier (keysym on Linux/X11, platform-dependent)
    pub keyid: u16,
    /// Active modifier keys bitmask
    pub mask: u16,
    /// Physical key code (keycode/scancode, platform-dependent)
    pub button: u16,
}

impl ProtocolMessage for MessageKeyUp {
    const CODE: &'static str = "DKUP";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 6 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 6,
                actual: data.len(),
            });
        }
        Ok(Self {
            keyid: read_u16(data, Self::CODE.len())?,
            mask: read_u16(data, Self::CODE.len() + 2)?,
            button: read_u16(data, Self::CODE.len() + 4)?,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.extend_from_slice(&self.keyid.to_be_bytes());
        bytes.extend_from_slice(&self.mask.to_be_bytes());
        bytes.extend_from_slice(&self.button.to_be_bytes());
        bytes
    }
}

/// Mouse button down
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageMouseButtonDown {
    /// Mouse button identifier (1=left, 2=right, 3=middle, 4+=additional)
    pub button: u8,
}

impl ProtocolMessage for MessageMouseButtonDown {
    const CODE: &'static str = "DMDN";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 1 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 1,
                actual: data.len(),
            });
        }
        Ok(Self {
            button: read_u8(data, Self::CODE.len())?,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.push(self.button);
        bytes
    }
}

/// Mouse button up
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageMouseButtonUp {
    /// Mouse button identifier (1=left, 2=right, 3=middle, 4+=additional)
    pub button: u8,
}

impl ProtocolMessage for MessageMouseButtonUp {
    const CODE: &'static str = "DMUP";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 1 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 1,
                actual: data.len(),
            });
        }
        Ok(Self {
            button: read_u8(data, Self::CODE.len())?,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.push(self.button);
        bytes
    }
}

/// Mouse move
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageMouseMove {
    /// Absolute X coordinate on secondary screen
    pub x: i16,
    /// Absolute Y coordinate on secondary screen
    pub y: i16,
}

impl ProtocolMessage for MessageMouseMove {
    const CODE: &'static str = "DMMV";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 4 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 4,
                actual: data.len(),
            });
        }
        Ok(Self {
            x: read_i16(data, Self::CODE.len())?,
            y: read_i16(data, Self::CODE.len() + 2)?,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.extend_from_slice(&self.x.to_be_bytes());
        bytes.extend_from_slice(&self.y.to_be_bytes());
        bytes
    }
}

/// Mouse relative move
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageMouseRelativeMove {
    /// Horizontal movement delta (signed)
    pub x: i16,
    /// Vertical movement delta (signed)
    pub y: i16,
}

impl ProtocolMessage for MessageMouseRelativeMove {
    const CODE: &'static str = "DMRM";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 4 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 4,
                actual: data.len(),
            });
        }
        Ok(Self {
            x: read_i16(data, Self::CODE.len())?,
            y: read_i16(data, Self::CODE.len() + 2)?,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.extend_from_slice(&self.x.to_be_bytes());
        bytes.extend_from_slice(&self.y.to_be_bytes());
        bytes
    }
}

/// Mouse wheel
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageMouseWheel {
    /// Horizontal scroll delta (+120 = right, -120 = left, typically multiples of 120)
    pub xdelta: i16,
    /// Vertical scroll delta (+120 = up/away, -120 = down/toward, typically multiples of 120)
    pub ydelta: i16,
}

impl ProtocolMessage for MessageMouseWheel {
    const CODE: &'static str = "DMWM";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 4 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 4,
                actual: data.len(),
            });
        }
        Ok(Self {
            xdelta: read_i16(data, Self::CODE.len())?,
            ydelta: read_i16(data, Self::CODE.len() + 2)?,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.extend_from_slice(&self.xdelta.to_be_bytes());
        bytes.extend_from_slice(&self.ydelta.to_be_bytes());
        bytes
    }
}

/// Clipboard data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageClipboardData {
    /// Clipboard identifier (0 = primary, 1 = selection)
    pub id: u8,
    /// Sequence number (0 for primary, from Enter message for secondary)
    pub sequence: u32,
    /// Streaming flags for large data (0=single chunk, 1=first, 2=middle, 3=final) - v1.6+
    pub mark: u8,
    /// Clipboard content
    pub data: LengthPrefixedString,
}

impl ProtocolMessage for MessageClipboardData {
    const CODE: &'static str = "DCLP";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 6 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 6,
                actual: data.len(),
            });
        }
        let (clipboard_data, _) = LengthPrefixedString::from_bytes(data, Self::CODE.len() + 6)?;
        Ok(Self {
            id: read_u8(data, Self::CODE.len())?,
            sequence: read_u32(data, Self::CODE.len() + 1)?,
            mark: read_u8(data, Self::CODE.len() + 5)?,
            data: clipboard_data,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.push(self.id);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.push(self.mark);
        bytes.extend_from_slice(&self.data.to_bytes());
        bytes
    }
}

/// Client info
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageClientInfo {
    /// Left edge X coordinate of screen
    pub x: u16,
    /// Top edge Y coordinate of screen
    pub y: u16,
    /// Screen width in pixels
    pub width: u16,
    /// Screen height in pixels
    pub height: u16,
    /// Current mouse X position
    pub current_mouse_x: u16,
    /// Current mouse Y position
    pub current_mouse_y: u16,
    /// Obsolete warp zone size (should be 0)
    pub size: u16,
}

impl ProtocolMessage for MessageClientInfo {
    const CODE: &'static str = "DINF";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 14 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 14,
                actual: data.len(),
            });
        }
        Ok(Self {
            x: read_u16(data, Self::CODE.len())?,
            y: read_u16(data, Self::CODE.len() + 2)?,
            width: read_u16(data, Self::CODE.len() + 4)?,
            height: read_u16(data, Self::CODE.len() + 6)?,
            current_mouse_x: read_u16(data, Self::CODE.len() + 8)?,
            current_mouse_y: read_u16(data, Self::CODE.len() + 10)?,
            size: read_u16(data, Self::CODE.len() + 12)?,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.extend_from_slice(&self.x.to_be_bytes());
        bytes.extend_from_slice(&self.y.to_be_bytes());
        bytes.extend_from_slice(&self.width.to_be_bytes());
        bytes.extend_from_slice(&self.height.to_be_bytes());
        bytes.extend_from_slice(&self.current_mouse_x.to_be_bytes());
        bytes.extend_from_slice(&self.current_mouse_y.to_be_bytes());
        bytes.extend_from_slice(&self.size.to_be_bytes());
        bytes
    }
}

/// DSOP (Set Options) option codes
///
/// These options are used in the SetOptions message (DSOP) to configure
/// various aspects of the Synergy/Barrier protocol behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum DsopOption {
    // Keyboard Modifier Options
    /// HDCL - Half-duplex caps lock
    HalfDuplexCapsLock = 0x4844434C,
    /// HDNL - Half-duplex num lock
    HalfDuplexNumLock = 0x48444E4C,
    /// HDSL - Half-duplex scroll lock
    HalfDuplexScrollLock = 0x4844534C,
    /// MMFS - Modifier map for shift
    ModifierMapForShift = 0x4D4D4653,
    /// MMFC - Modifier map for control
    ModifierMapForControl = 0x4D4D4643,
    /// MMFA - Modifier map for alt
    ModifierMapForAlt = 0x4D4D4641,
    /// MMFG - Modifier map for AltGr
    ModifierMapForAltGr = 0x4D4D4647,
    /// MMFM - Modifier map for meta
    ModifierMapForMeta = 0x4D4D464D,
    /// MMFR - Modifier map for super
    ModifierMapForSuper = 0x4D4D4652,

    // Screen Switching Options
    /// SSCM - Screen switch corners
    ScreenSwitchCorners = 0x5353434D,
    /// SSCS - Screen switch corner size
    ScreenSwitchCornerSize = 0x53534353,
    /// SSWT - Screen switch delay
    ScreenSwitchDelay = 0x53535754,
    /// SSTT - Screen switch two-tap
    ScreenSwitchTwoTap = 0x53535454,
    /// SSNS - Screen switch needs shift
    ScreenSwitchNeedsShift = 0x53534E53,
    /// SSNC - Screen switch needs control
    ScreenSwitchNeedsControl = 0x53534E43,
    /// SSNA - Screen switch needs alt
    ScreenSwitchNeedsAlt = 0x53534E41,

    // General Options
    /// HART - Heartbeat interval
    Heartbeat = 0x48415254,
    /// PROT - Protocol version
    Protocol = 0x50524F54,
    /// MDLT - Relative mouse moves (mouse delta)
    RelativeMouseMoves = 0x4D444C54,
    /// LTSS - Default lock-to-screen state
    DefaultLockToScreenState = 0x4C545353,
    /// DLTS - Disable lock-to-screen
    DisableLockToScreen = 0x444C5453,
    /// CLPS - Clipboard sharing
    ClipboardSharing = 0x434C5053,
    /// CLSZ - Clipboard sharing size limit
    ClipboardSharingSize = 0x434C535A,
    /// XTXU - XTest Xinerama unaware
    XTestXineramaUnaware = 0x58545855,
    /// SFOC - Screen preserve focus
    ScreenPreserveFocus = 0x53464F43,
    /// _KFW - Win32 keep foreground
    Win32KeepForeground = 0x5F4B4657,
}

impl DsopOption {
    /// Convert a u32 value to a DsopOption if it matches a known option
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x4844434C => Some(Self::HalfDuplexCapsLock),
            0x48444E4C => Some(Self::HalfDuplexNumLock),
            0x4844534C => Some(Self::HalfDuplexScrollLock),
            0x4D4D4653 => Some(Self::ModifierMapForShift),
            0x4D4D4643 => Some(Self::ModifierMapForControl),
            0x4D4D4641 => Some(Self::ModifierMapForAlt),
            0x4D4D4647 => Some(Self::ModifierMapForAltGr),
            0x4D4D464D => Some(Self::ModifierMapForMeta),
            0x4D4D4652 => Some(Self::ModifierMapForSuper),
            0x5353434D => Some(Self::ScreenSwitchCorners),
            0x53534353 => Some(Self::ScreenSwitchCornerSize),
            0x53535754 => Some(Self::ScreenSwitchDelay),
            0x53535454 => Some(Self::ScreenSwitchTwoTap),
            0x53534E53 => Some(Self::ScreenSwitchNeedsShift),
            0x53534E43 => Some(Self::ScreenSwitchNeedsControl),
            0x53534E41 => Some(Self::ScreenSwitchNeedsAlt),
            0x48415254 => Some(Self::Heartbeat),
            0x50524F54 => Some(Self::Protocol),
            0x4D444C54 => Some(Self::RelativeMouseMoves),
            0x4C545353 => Some(Self::DefaultLockToScreenState),
            0x444C5453 => Some(Self::DisableLockToScreen),
            0x434C5053 => Some(Self::ClipboardSharing),
            0x434C535A => Some(Self::ClipboardSharingSize),
            0x58545855 => Some(Self::XTestXineramaUnaware),
            0x53464F43 => Some(Self::ScreenPreserveFocus),
            0x5F4B4657 => Some(Self::Win32KeepForeground),
            _ => None,
        }
    }

    /// Get the 4-character code for this option
    pub fn code(&self) -> &'static str {
        match self {
            Self::HalfDuplexCapsLock => "HDCL",
            Self::HalfDuplexNumLock => "HDNL",
            Self::HalfDuplexScrollLock => "HDSL",
            Self::ModifierMapForShift => "MMFS",
            Self::ModifierMapForControl => "MMFC",
            Self::ModifierMapForAlt => "MMFA",
            Self::ModifierMapForAltGr => "MMFG",
            Self::ModifierMapForMeta => "MMFM",
            Self::ModifierMapForSuper => "MMFR",
            Self::ScreenSwitchCorners => "SSCM",
            Self::ScreenSwitchCornerSize => "SSCS",
            Self::ScreenSwitchDelay => "SSWT",
            Self::ScreenSwitchTwoTap => "SSTT",
            Self::ScreenSwitchNeedsShift => "SSNS",
            Self::ScreenSwitchNeedsControl => "SSNC",
            Self::ScreenSwitchNeedsAlt => "SSNA",
            Self::Heartbeat => "HART",
            Self::Protocol => "PROT",
            Self::RelativeMouseMoves => "MDLT",
            Self::DefaultLockToScreenState => "LTSS",
            Self::DisableLockToScreen => "DLTS",
            Self::ClipboardSharing => "CLPS",
            Self::ClipboardSharingSize => "CLSZ",
            Self::XTestXineramaUnaware => "XTXU",
            Self::ScreenPreserveFocus => "SFOC",
            Self::Win32KeepForeground => "_KFW",
        }
    }
}

/// Set options
///
/// DSOP message format:
/// - "DSOP" (4 bytes)
/// - Length (4 bytes BE) - number of 4-byte elements including the length itself
/// - Key-value pairs, where each pair is:
///   - Key (4 bytes BE) - see DsopOption
///   - Value (4 bytes BE)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSetOptions {
    /// Vector of (key, value) pairs for options
    pub options: Vec<(u32, u32)>,
}

impl ProtocolMessage for MessageSetOptions {
    const CODE: &'static str = "DSOP";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 4 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 4,
                actual: data.len(),
            });
        }

        let mut offset = Self::CODE.len();

        // Read length (number of 4-byte elements including the length itself)
        let length = read_u32(data, offset)?;
        offset += 4;

        // Calculate number of key-value pairs: (length - 1) / 2
        // Subtract 1 for the length field itself
        if length < 1 {
            return Err(ProtocolError::InvalidData(
                "DSOP length must be at least 1".to_string(),
            ));
        }

        let num_elements = (length - 1) as usize;
        if num_elements % 2 != 0 {
            return Err(ProtocolError::InvalidData(
                "DSOP must have an even number of elements (key-value pairs)".to_string(),
            ));
        }

        let num_pairs = num_elements / 2;
        let expected_size = Self::CODE.len() + 4 + (num_pairs * 8);
        if data.len() < expected_size {
            return Err(ProtocolError::InsufficientData {
                expected: expected_size,
                actual: data.len(),
            });
        }

        let mut options = Vec::new();
        for _ in 0..num_pairs {
            let key = read_u32(data, offset)?;
            offset += 4;
            let value = read_u32(data, offset)?;
            offset += 4;
            options.push((key, value));
        }

        Ok(Self { options })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());

        // Write length: 1 (for length itself) + options.len() * 2 (for key-value pairs)
        let length = 1 + (self.options.len() * 2) as u32;
        bytes.extend_from_slice(&length.to_be_bytes());

        // Write each key-value pair
        for (key, value) in &self.options {
            bytes.extend_from_slice(&key.to_be_bytes());
            bytes.extend_from_slice(&value.to_be_bytes());
        }

        bytes
    }
}

/// File transfer
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageFileTransfer {
    /// Transfer state (1=DataStart with file size, 2=DataChunk with content, 3=DataEnd)
    pub mark: u8,
    /// Content depending on mark (file size for start, file content for chunk, empty for end)
    pub data: LengthPrefixedString,
}

impl ProtocolMessage for MessageFileTransfer {
    const CODE: &'static str = "DFTR";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 1 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 1,
                actual: data.len(),
            });
        }
        let (transfer_data, _) = LengthPrefixedString::from_bytes(data, Self::CODE.len() + 1)?;
        Ok(Self {
            mark: read_u8(data, Self::CODE.len())?,
            data: transfer_data,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.push(self.mark);
        bytes.extend_from_slice(&self.data.to_bytes());
        bytes
    }
}

/// Drag info
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDragInfo {
    /// Number of files being dragged
    pub size: u16,
    /// Null-separated file paths
    pub data: LengthPrefixedString,
}

impl ProtocolMessage for MessageDragInfo {
    const CODE: &'static str = "DDRG";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 2 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 2,
                actual: data.len(),
            });
        }
        let (drag_data, _) = LengthPrefixedString::from_bytes(data, Self::CODE.len() + 2)?;
        Ok(Self {
            size: read_u16(data, Self::CODE.len())?,
            data: drag_data,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.extend_from_slice(&self.size.to_be_bytes());
        bytes.extend_from_slice(&self.data.to_bytes());
        bytes
    }
}

/// Secure encryption
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSecureEncryption {
    /// Application name requesting secure input (macOS feature)
    pub data: LengthPrefixedString,
}

impl ProtocolMessage for MessageSecureEncryption {
    const CODE: &'static str = "SECN";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        let (secure_data, _) = LengthPrefixedString::from_bytes(data, Self::CODE.len())?;
        Ok(Self { data: secure_data })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.extend_from_slice(&self.data.to_bytes());
        bytes
    }
}

/// Legacy synergy
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageLegacySynergy {
    /// Comma-separated list of language codes (ISO 639-1)
    pub data: LengthPrefixedString,
}

impl ProtocolMessage for MessageLegacySynergy {
    const CODE: &'static str = "LSYN";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        let (legacy_data, _) = LengthPrefixedString::from_bytes(data, Self::CODE.len())?;
        Ok(Self { data: legacy_data })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.extend_from_slice(&self.data.to_bytes());
        bytes
    }
}

/// Query info
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageQueryInfo;

impl ProtocolMessage for MessageQueryInfo {
    const CODE: &'static str = "QINF";

    fn from_bytes(_data: &[u8]) -> Result<Self> {
        Ok(Self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        Self::CODE.as_bytes().to_vec()
    }
}

/// Incompatible version error
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageIncompatibleVersion {
    /// Primary's major version number
    pub major_remote: u16,
    /// Primary's minor version number
    pub minor_remote: u16,
}

impl ProtocolMessage for MessageIncompatibleVersion {
    const CODE: &'static str = "EICV";

    fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::CODE.len() + 4 {
            return Err(ProtocolError::InsufficientData {
                expected: Self::CODE.len() + 4,
                actual: data.len(),
            });
        }
        Ok(Self {
            major_remote: read_u16(data, Self::CODE.len())?,
            minor_remote: read_u16(data, Self::CODE.len() + 2)?,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(Self::CODE.as_bytes());
        bytes.extend_from_slice(&self.major_remote.to_be_bytes());
        bytes.extend_from_slice(&self.minor_remote.to_be_bytes());
        bytes
    }
}

/// Server busy error
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageServerBusy;

impl ProtocolMessage for MessageServerBusy {
    const CODE: &'static str = "EBSY";

    fn from_bytes(_data: &[u8]) -> Result<Self> {
        Ok(Self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        Self::CODE.as_bytes().to_vec()
    }
}

/// Unknown client error
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageUnknownClient;

impl ProtocolMessage for MessageUnknownClient {
    const CODE: &'static str = "EUNK";

    fn from_bytes(_data: &[u8]) -> Result<Self> {
        Ok(Self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        Self::CODE.as_bytes().to_vec()
    }
}

/// Protocol error
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageProtocolError;

impl ProtocolMessage for MessageProtocolError {
    const CODE: &'static str = "EBAD";

    fn from_bytes(_data: &[u8]) -> Result<Self> {
        Ok(Self)
    }

    fn to_bytes(&self) -> Vec<u8> {
        Self::CODE.as_bytes().to_vec()
    }
}

/// Main protocol message enum representing all possible messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    HelloBarrier(MessageHelloBarrier),
    HelloSynergy(MessageHelloSynergy),
    NoOp(MessageNoOp),
    Close(MessageClose),
    CursorEntered(MessageCursorEntered),
    CursorLeft(MessageCursorLeft),
    ClientClipboard(MessageClientClipboard),
    ScreenSaverChange(MessageScreenSaverChange),
    ResetOptions(MessageResetOptions),
    InfoAcknowledgment(MessageInfoAcknowledgment),
    KeepAlive(MessageKeepAlive),
    KeyDownWithLanguage(MessageKeyDownWithLanguage),
    KeyDown(MessageKeyDown),
    KeyRepeat(MessageKeyRepeat),
    KeyUp(MessageKeyUp),
    MouseButtonDown(MessageMouseButtonDown),
    MouseButtonUp(MessageMouseButtonUp),
    MouseMove(MessageMouseMove),
    MouseRelativeMove(MessageMouseRelativeMove),
    MouseWheel(MessageMouseWheel),
    ClipboardData(MessageClipboardData),
    ClientInfo(MessageClientInfo),
    SetOptions(MessageSetOptions),
    FileTransfer(MessageFileTransfer),
    DragInfo(MessageDragInfo),
    SecureEncryption(MessageSecureEncryption),
    LegacySynergy(MessageLegacySynergy),
    QueryInfo(MessageQueryInfo),
    IncompatibleVersion(MessageIncompatibleVersion),
    ServerBusy(MessageServerBusy),
    UnknownClient(MessageUnknownClient),
    ProtocolError(MessageProtocolError),
}

impl Message {
    /// Converts this message to bytes with a 4-byte length prefix
    ///
    /// This method wraps the individual message's `ProtocolMessage::to_bytes()`
    /// implementation and adds the required 4-byte length prefix.
    ///
    /// # Example
    ///
    /// ```
    /// use schengen::protocol::{Message, MessageKeepAlive};
    ///
    /// let msg = Message::KeepAlive(MessageKeepAlive);
    /// let bytes = msg.to_bytes();
    /// // First 4 bytes are the length prefix (big-endian)
    /// // Followed by "CALV"
    /// assert_eq!(&bytes[4..8], b"CALV");
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let data = match self {
            Message::HelloBarrier(m) => m.to_bytes(),
            Message::HelloSynergy(m) => m.to_bytes(),
            Message::NoOp(m) => m.to_bytes(),
            Message::Close(m) => m.to_bytes(),
            Message::CursorEntered(m) => m.to_bytes(),
            Message::CursorLeft(m) => m.to_bytes(),
            Message::ClientClipboard(m) => m.to_bytes(),
            Message::ScreenSaverChange(m) => m.to_bytes(),
            Message::ResetOptions(m) => m.to_bytes(),
            Message::InfoAcknowledgment(m) => m.to_bytes(),
            Message::KeepAlive(m) => m.to_bytes(),
            Message::KeyDownWithLanguage(m) => m.to_bytes(),
            Message::KeyDown(m) => m.to_bytes(),
            Message::KeyRepeat(m) => m.to_bytes(),
            Message::KeyUp(m) => m.to_bytes(),
            Message::MouseButtonDown(m) => m.to_bytes(),
            Message::MouseButtonUp(m) => m.to_bytes(),
            Message::MouseMove(m) => m.to_bytes(),
            Message::MouseRelativeMove(m) => m.to_bytes(),
            Message::MouseWheel(m) => m.to_bytes(),
            Message::ClipboardData(m) => m.to_bytes(),
            Message::ClientInfo(m) => m.to_bytes(),
            Message::SetOptions(m) => m.to_bytes(),
            Message::FileTransfer(m) => m.to_bytes(),
            Message::DragInfo(m) => m.to_bytes(),
            Message::SecureEncryption(m) => m.to_bytes(),
            Message::LegacySynergy(m) => m.to_bytes(),
            Message::QueryInfo(m) => m.to_bytes(),
            Message::IncompatibleVersion(m) => m.to_bytes(),
            Message::ServerBusy(m) => m.to_bytes(),
            Message::UnknownClient(m) => m.to_bytes(),
            Message::ProtocolError(m) => m.to_bytes(),
        };

        // Prepend the length
        let mut result = Vec::with_capacity(4 + data.len());
        result.extend_from_slice(&(data.len() as u32).to_be_bytes());
        result.extend_from_slice(&data);
        result
    }
}

/// Parse a protocol message from bytes (without the length prefix)
///
/// # Arguments
///
/// * `data` - The message data starting with the 4-character message code
///
/// # Returns
///
/// Returns the parsed message or an error if the message is unknown or malformed
///
/// # Example
///
/// ```
/// use schengen::protocol::{parse_message, Message};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let data = b"CALV";
/// let msg = parse_message(data)?;
/// match msg {
///     Message::KeepAlive(_) => println!("Got keepalive"),
///     _ => println!("Other message"),
/// }
/// # Ok(())
/// # }
/// ```
pub fn parse_message(data: &[u8]) -> Result<Message> {
    if data.len() < 4 {
        return Err(ProtocolError::InsufficientData {
            expected: 4,
            actual: data.len(),
        });
    }

    // Try to read the message code
    let code = std::str::from_utf8(&data[0..4]).map_err(|_| ProtocolError::InvalidMessageCode)?;

    match code {
        "CNOP" => Ok(Message::NoOp(MessageNoOp::from_bytes(data)?)),
        "CBYE" => Ok(Message::Close(MessageClose::from_bytes(data)?)),
        "CINN" => Ok(Message::CursorEntered(MessageCursorEntered::from_bytes(
            data,
        )?)),
        "COUT" => Ok(Message::CursorLeft(MessageCursorLeft::from_bytes(data)?)),
        "CCLP" => Ok(Message::ClientClipboard(
            MessageClientClipboard::from_bytes(data)?,
        )),
        "CSEC" => Ok(Message::ScreenSaverChange(
            MessageScreenSaverChange::from_bytes(data)?,
        )),
        "CROP" => Ok(Message::ResetOptions(MessageResetOptions::from_bytes(
            data,
        )?)),
        "CIAK" => Ok(Message::InfoAcknowledgment(
            MessageInfoAcknowledgment::from_bytes(data)?,
        )),
        "CALV" => Ok(Message::KeepAlive(MessageKeepAlive::from_bytes(data)?)),
        "DKDL" => Ok(Message::KeyDownWithLanguage(
            MessageKeyDownWithLanguage::from_bytes(data)?,
        )),
        "DKDN" => Ok(Message::KeyDown(MessageKeyDown::from_bytes(data)?)),
        "DKRP" => Ok(Message::KeyRepeat(MessageKeyRepeat::from_bytes(data)?)),
        "DKUP" => Ok(Message::KeyUp(MessageKeyUp::from_bytes(data)?)),
        "DMDN" => Ok(Message::MouseButtonDown(
            MessageMouseButtonDown::from_bytes(data)?,
        )),
        "DMUP" => Ok(Message::MouseButtonUp(MessageMouseButtonUp::from_bytes(
            data,
        )?)),
        "DMMV" => Ok(Message::MouseMove(MessageMouseMove::from_bytes(data)?)),
        "DMRM" => Ok(Message::MouseRelativeMove(
            MessageMouseRelativeMove::from_bytes(data)?,
        )),
        "DMWM" => Ok(Message::MouseWheel(MessageMouseWheel::from_bytes(data)?)),
        "DCLP" => Ok(Message::ClipboardData(MessageClipboardData::from_bytes(
            data,
        )?)),
        "DINF" => Ok(Message::ClientInfo(MessageClientInfo::from_bytes(data)?)),
        "DSOP" => Ok(Message::SetOptions(MessageSetOptions::from_bytes(data)?)),
        "DFTR" => Ok(Message::FileTransfer(MessageFileTransfer::from_bytes(
            data,
        )?)),
        "DDRG" => Ok(Message::DragInfo(MessageDragInfo::from_bytes(data)?)),
        "SECN" => Ok(Message::SecureEncryption(
            MessageSecureEncryption::from_bytes(data)?,
        )),
        "LSYN" => Ok(Message::LegacySynergy(MessageLegacySynergy::from_bytes(
            data,
        )?)),
        "QINF" => Ok(Message::QueryInfo(MessageQueryInfo::from_bytes(data)?)),
        "EICV" => Ok(Message::IncompatibleVersion(
            MessageIncompatibleVersion::from_bytes(data)?,
        )),
        "EBSY" => Ok(Message::ServerBusy(MessageServerBusy::from_bytes(data)?)),
        "EUNK" => Ok(Message::UnknownClient(MessageUnknownClient::from_bytes(
            data,
        )?)),
        "EBAD" => Ok(Message::ProtocolError(MessageProtocolError::from_bytes(
            data,
        )?)),
        _ => {
            // Check for Hello messages which have longer codes
            if data.len() >= 7 && &data[0..7] == b"Barrier" {
                Ok(Message::HelloBarrier(MessageHelloBarrier::from_bytes(
                    data,
                )?))
            } else if data.len() >= 7 && &data[0..7] == b"Synergy" {
                Ok(Message::HelloSynergy(MessageHelloSynergy::from_bytes(
                    data,
                )?))
            } else {
                Err(ProtocolError::UnknownMessageCode(code.to_string()))
            }
        }
    }
}

/// Parse a complete message including the 4-byte length prefix
///
/// # Arguments
///
/// * `data` - The complete message data including the length prefix
///
/// # Returns
///
/// Returns a tuple of (parsed message, bytes consumed) or an error if parsing fails
/// or if there is insufficient data
///
/// # Example
///
/// ```
/// use schengen::protocol::{parse_message_with_length, Message};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Message with length prefix (4 bytes) followed by "CALV"
/// let data = vec![0, 0, 0, 4, b'C', b'A', b'L', b'V'];
/// let (msg, consumed) = parse_message_with_length(&data)?;
/// assert_eq!(consumed, 8); // 4 bytes length + 4 bytes message
/// match msg {
///     Message::KeepAlive(_) => println!("Got keepalive"),
///     _ => println!("Other message"),
/// }
/// # Ok(())
/// # }
/// ```
pub fn parse_message_with_length(data: &[u8]) -> Result<(Message, usize)> {
    if data.len() < 4 {
        return Err(ProtocolError::InsufficientData {
            expected: 4,
            actual: data.len(),
        });
    }

    let length = read_u32(data, 0)? as usize;
    let total_size = 4 + length;

    if data.len() < total_size {
        return Err(ProtocolError::InsufficientData {
            expected: total_size,
            actual: data.len(),
        });
    }

    let msg = parse_message(&data[4..total_size])?;
    Ok((msg, total_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_barrier() {
        // Test server hello (no client name)
        let msg_server = MessageHelloBarrier {
            major: 1,
            minor: 8,
            client_name: None,
        };
        let bytes = msg_server.to_bytes();
        assert_eq!(&bytes[0..7], b"Barrier");
        assert_eq!(&bytes[7..9], &1u16.to_be_bytes());
        assert_eq!(&bytes[9..11], &8u16.to_be_bytes());
        assert_eq!(bytes.len(), 11);

        let parsed = MessageHelloBarrier::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_server);

        // Test client hello (with client name)
        let msg_client = MessageHelloBarrier {
            major: 1,
            minor: 8,
            client_name: Some("testclient".to_string()),
        };
        let bytes = msg_client.to_bytes();
        assert_eq!(&bytes[0..7], b"Barrier");
        assert_eq!(&bytes[7..9], &1u16.to_be_bytes());
        assert_eq!(&bytes[9..11], &8u16.to_be_bytes());
        assert_eq!(&bytes[11..15], &10u32.to_be_bytes()); // length of "testclient"
        assert_eq!(&bytes[15..25], b"testclient");

        let parsed = MessageHelloBarrier::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_client);

        // Test edge case: empty client name
        let msg_empty = MessageHelloBarrier {
            major: 0,
            minor: 0,
            client_name: Some("".to_string()),
        };
        let bytes = msg_empty.to_bytes();
        let parsed = MessageHelloBarrier::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_empty);
    }

    #[test]
    fn test_hello_synergy() {
        // Test server hello (no client name)
        let msg_server = MessageHelloSynergy {
            major: 1,
            minor: 6,
            client_name: None,
        };
        let bytes = msg_server.to_bytes();
        assert_eq!(&bytes[0..7], b"Synergy");
        assert_eq!(&bytes[7..9], &1u16.to_be_bytes());
        assert_eq!(&bytes[9..11], &6u16.to_be_bytes());

        let parsed = MessageHelloSynergy::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_server);

        // Test client hello (with client name)
        let msg_client = MessageHelloSynergy {
            major: 1,
            minor: 6,
            client_name: Some("myclient".to_string()),
        };
        let bytes = msg_client.to_bytes();
        let parsed = MessageHelloSynergy::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_client);
    }

    #[test]
    fn test_cnop() {
        let msg = MessageNoOp;
        let bytes = msg.to_bytes();
        assert_eq!(&bytes, b"CNOP");

        let parsed = MessageNoOp::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_cbye() {
        let msg = MessageClose;
        let bytes = msg.to_bytes();
        assert_eq!(&bytes, b"CBYE");

        let parsed = MessageClose::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_cinn() {
        // Normal case
        let msg = MessageCursorEntered {
            x: 1920,
            y: 1080,
            sequence: 42,
            mask: 0x0003,
        };
        let bytes = msg.to_bytes();
        assert_eq!(&bytes[0..4], b"CINN");
        assert_eq!(&bytes[4..6], &1920i16.to_be_bytes());
        assert_eq!(&bytes[6..8], &1080i16.to_be_bytes());
        assert_eq!(&bytes[8..12], &42u32.to_be_bytes());
        assert_eq!(&bytes[12..14], &0x0003u16.to_be_bytes());

        let parsed = MessageCursorEntered::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);

        // Edge case: negative coordinates
        let msg_neg = MessageCursorEntered {
            x: -100,
            y: -200,
            sequence: 0,
            mask: 0,
        };
        let bytes = msg_neg.to_bytes();
        let parsed = MessageCursorEntered::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_neg);

        // Edge case: maximum values
        let msg_max = MessageCursorEntered {
            x: i16::MAX,
            y: i16::MAX,
            sequence: u32::MAX,
            mask: u16::MAX,
        };
        let bytes = msg_max.to_bytes();
        let parsed = MessageCursorEntered::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_max);
    }

    #[test]
    fn test_cout() {
        let msg = MessageCursorLeft;
        let bytes = msg.to_bytes();
        assert_eq!(&bytes, b"COUT");

        let parsed = MessageCursorLeft::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_cclp() {
        // Normal case
        let msg = MessageClientClipboard {
            id: 0,
            sequence: 123,
        };
        let bytes = msg.to_bytes();
        assert_eq!(&bytes[0..4], b"CCLP");
        assert_eq!(bytes[4], 0);
        assert_eq!(&bytes[5..9], &123u32.to_be_bytes());

        let parsed = MessageClientClipboard::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);

        // Edge case: selection clipboard
        let msg_sel = MessageClientClipboard {
            id: 1,
            sequence: u32::MAX,
        };
        let bytes = msg_sel.to_bytes();
        let parsed = MessageClientClipboard::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_sel);
    }

    #[test]
    fn test_csec() {
        // Screen saver started
        let msg_started = MessageScreenSaverChange { state: 1 };
        let bytes = msg_started.to_bytes();
        assert_eq!(&bytes[0..4], b"CSEC");
        assert_eq!(bytes[4], 1);

        let parsed = MessageScreenSaverChange::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_started);

        // Screen saver stopped
        let msg_stopped = MessageScreenSaverChange { state: 0 };
        let bytes = msg_stopped.to_bytes();
        let parsed = MessageScreenSaverChange::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_stopped);
    }

    #[test]
    fn test_crop() {
        let msg = MessageResetOptions;
        let bytes = msg.to_bytes();
        assert_eq!(&bytes, b"CROP");

        let parsed = MessageResetOptions::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_ciak() {
        let msg = MessageInfoAcknowledgment;
        let bytes = msg.to_bytes();
        assert_eq!(&bytes, b"CIAK");

        let parsed = MessageInfoAcknowledgment::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_calv() {
        let msg = MessageKeepAlive;
        let bytes = msg.to_bytes();
        assert_eq!(&bytes, b"CALV");

        let parsed = MessageKeepAlive::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_dkdl() {
        // Normal case
        let msg = MessageKeyDownWithLanguage {
            keyid: 0x0061,
            mask: 0x0002,
            button: 0x0026,
            lang: "en_US".into(),
        };
        let bytes = msg.to_bytes();
        assert_eq!(&bytes[0..4], b"DKDL");
        assert_eq!(&bytes[4..6], &0x0061u16.to_be_bytes());
        assert_eq!(&bytes[6..8], &0x0002u16.to_be_bytes());
        assert_eq!(&bytes[8..10], &0x0026u16.to_be_bytes());
        assert_eq!(&bytes[10..14], &5u32.to_be_bytes());
        assert_eq!(&bytes[14..19], b"en_US");

        let parsed = MessageKeyDownWithLanguage::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);

        // Edge case: empty language
        let msg_empty = MessageKeyDownWithLanguage {
            keyid: 0,
            mask: 0,
            button: 0,
            lang: "".into(),
        };
        let bytes = msg_empty.to_bytes();
        let parsed = MessageKeyDownWithLanguage::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_empty);
    }

    #[test]
    fn test_dkdn() {
        // Normal case
        let msg = MessageKeyDown {
            keyid: 0x0041,
            mask: 0x0001,
            button: 0x001E,
        };
        let bytes = msg.to_bytes();
        assert_eq!(&bytes[0..4], b"DKDN");
        assert_eq!(&bytes[4..6], &0x0041u16.to_be_bytes());
        assert_eq!(&bytes[6..8], &0x0001u16.to_be_bytes());
        assert_eq!(&bytes[8..10], &0x001Eu16.to_be_bytes());

        let parsed = MessageKeyDown::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);

        // Edge case: all zeros
        let msg_zero = MessageKeyDown {
            keyid: 0,
            mask: 0,
            button: 0,
        };
        let bytes = msg_zero.to_bytes();
        let parsed = MessageKeyDown::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_zero);
    }

    #[test]
    fn test_dkrp() {
        // Normal case
        let msg = MessageKeyRepeat {
            keyid: 0x0061,
            mask: 0,
            button: 0x0026,
            count: 5,
            lang: "de_DE".into(),
        };
        let bytes = msg.to_bytes();
        assert_eq!(&bytes[0..4], b"DKRP");
        assert_eq!(&bytes[4..6], &0x0061u16.to_be_bytes());
        assert_eq!(&bytes[6..8], &0u16.to_be_bytes());
        assert_eq!(&bytes[8..10], &0x0026u16.to_be_bytes());
        assert_eq!(&bytes[10..12], &5u16.to_be_bytes());

        let parsed = MessageKeyRepeat::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);

        // Edge case: high repeat count
        let msg_many = MessageKeyRepeat {
            keyid: 0x0020,
            mask: 0,
            button: 0x0039,
            count: u16::MAX,
            lang: "".into(),
        };
        let bytes = msg_many.to_bytes();
        let parsed = MessageKeyRepeat::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_many);
    }

    #[test]
    fn test_dkup() {
        let msg = MessageKeyUp {
            keyid: 0x0041,
            mask: 0x0001,
            button: 0x001E,
        };
        let bytes = msg.to_bytes();
        assert_eq!(&bytes[0..4], b"DKUP");
        assert_eq!(&bytes[4..6], &0x0041u16.to_be_bytes());
        assert_eq!(&bytes[6..8], &0x0001u16.to_be_bytes());
        assert_eq!(&bytes[8..10], &0x001Eu16.to_be_bytes());

        let parsed = MessageKeyUp::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_dmdn() {
        // Left button
        let msg_left = MessageMouseButtonDown { button: 1 };
        let bytes = msg_left.to_bytes();
        assert_eq!(&bytes[0..4], b"DMDN");
        assert_eq!(bytes[4], 1);

        let parsed = MessageMouseButtonDown::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_left);

        // Right button
        let msg_right = MessageMouseButtonDown { button: 2 };
        let bytes = msg_right.to_bytes();
        let parsed = MessageMouseButtonDown::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_right);

        // Extra button
        let msg_extra = MessageMouseButtonDown { button: 10 };
        let bytes = msg_extra.to_bytes();
        let parsed = MessageMouseButtonDown::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_extra);
    }

    #[test]
    fn test_dmup() {
        let msg = MessageMouseButtonUp { button: 1 };
        let bytes = msg.to_bytes();
        assert_eq!(&bytes[0..4], b"DMUP");
        assert_eq!(bytes[4], 1);

        let parsed = MessageMouseButtonUp::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_dmmv() {
        // Normal case
        let msg = MessageMouseMove { x: 1920, y: 1080 };
        let bytes = msg.to_bytes();
        assert_eq!(&bytes[0..4], b"DMMV");
        assert_eq!(&bytes[4..6], &1920i16.to_be_bytes());
        assert_eq!(&bytes[6..8], &1080i16.to_be_bytes());

        let parsed = MessageMouseMove::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);

        // Edge case: negative coordinates
        let msg_neg = MessageMouseMove { x: -10, y: -20 };
        let bytes = msg_neg.to_bytes();
        let parsed = MessageMouseMove::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_neg);
    }

    #[test]
    fn test_dmrm() {
        // Normal case
        let msg = MessageMouseRelativeMove { x: 10, y: -5 };
        let bytes = msg.to_bytes();
        assert_eq!(&bytes[0..4], b"DMRM");
        assert_eq!(&bytes[4..6], &10i16.to_be_bytes());
        assert_eq!(&bytes[6..8], &(-5i16).to_be_bytes());

        let parsed = MessageMouseRelativeMove::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);

        // Edge case: large deltas
        let msg_large = MessageMouseRelativeMove {
            x: i16::MAX,
            y: i16::MIN,
        };
        let bytes = msg_large.to_bytes();
        let parsed = MessageMouseRelativeMove::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_large);
    }

    #[test]
    fn test_dmwm() {
        // Scroll up
        let msg_up = MessageMouseWheel {
            xdelta: 0,
            ydelta: 120,
        };
        let bytes = msg_up.to_bytes();
        assert_eq!(&bytes[0..4], b"DMWM");
        assert_eq!(&bytes[4..6], &0i16.to_be_bytes());
        assert_eq!(&bytes[6..8], &120i16.to_be_bytes());

        let parsed = MessageMouseWheel::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_up);

        // Scroll down
        let msg_down = MessageMouseWheel {
            xdelta: 0,
            ydelta: -120,
        };
        let bytes = msg_down.to_bytes();
        let parsed = MessageMouseWheel::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_down);

        // Horizontal scroll
        let msg_horiz = MessageMouseWheel {
            xdelta: 120,
            ydelta: 0,
        };
        let bytes = msg_horiz.to_bytes();
        let parsed = MessageMouseWheel::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_horiz);
    }

    #[test]
    fn test_dclp() {
        // Normal case
        let msg = MessageClipboardData {
            id: 0,
            sequence: 42,
            mark: 0,
            data: "Hello World".into(),
        };
        let bytes = msg.to_bytes();
        assert_eq!(&bytes[0..4], b"DCLP");
        assert_eq!(bytes[4], 0);
        assert_eq!(&bytes[5..9], &42u32.to_be_bytes());
        assert_eq!(bytes[9], 0);
        assert_eq!(&bytes[10..14], &11u32.to_be_bytes());
        assert_eq!(&bytes[14..25], b"Hello World");

        let parsed = MessageClipboardData::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);

        // Edge case: empty clipboard
        let msg_empty = MessageClipboardData {
            id: 1,
            sequence: 0,
            mark: 3,
            data: "".into(),
        };
        let bytes = msg_empty.to_bytes();
        let parsed = MessageClipboardData::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_empty);
    }

    #[test]
    fn test_dinf() {
        // Normal case
        let msg = MessageClientInfo {
            x: 0,
            y: 0,
            width: 1920,
            height: 1080,
            current_mouse_x: 960,
            current_mouse_y: 540,
            size: 0,
        };
        let bytes = msg.to_bytes();
        assert_eq!(&bytes[0..4], b"DINF");
        assert_eq!(&bytes[4..6], &0u16.to_be_bytes());
        assert_eq!(&bytes[6..8], &0u16.to_be_bytes());
        assert_eq!(&bytes[8..10], &1920u16.to_be_bytes());
        assert_eq!(&bytes[10..12], &1080u16.to_be_bytes());
        assert_eq!(&bytes[12..14], &960u16.to_be_bytes());
        assert_eq!(&bytes[14..16], &540u16.to_be_bytes());
        assert_eq!(&bytes[16..18], &0u16.to_be_bytes());

        let parsed = MessageClientInfo::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);

        // Edge case: maximum values
        let msg_max = MessageClientInfo {
            x: u16::MAX,
            y: u16::MAX,
            width: u16::MAX,
            height: u16::MAX,
            current_mouse_x: u16::MAX,
            current_mouse_y: u16::MAX,
            size: u16::MAX,
        };
        let bytes = msg_max.to_bytes();
        let parsed = MessageClientInfo::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_max);
    }

    #[test]
    fn test_dsop() {
        // Empty options
        let msg_empty = MessageSetOptions { options: vec![] };
        let bytes = msg_empty.to_bytes();
        assert_eq!(&bytes[0..4], b"DSOP");
        assert_eq!(&bytes[4..8], &1u32.to_be_bytes()); // length = 1 (just the length field)

        let parsed = MessageSetOptions::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_empty);

        // Single option
        let msg_single = MessageSetOptions {
            options: vec![(0x48415254, 3000)], // Heartbeat = 3000
        };
        let bytes = msg_single.to_bytes();
        assert_eq!(&bytes[0..4], b"DSOP");
        assert_eq!(&bytes[4..8], &3u32.to_be_bytes()); // length = 1 + 2 elements
        assert_eq!(&bytes[8..12], &0x48415254u32.to_be_bytes()); // key
        assert_eq!(&bytes[12..16], &3000u32.to_be_bytes()); // value

        let parsed = MessageSetOptions::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_single);

        // Multiple options
        let msg_multi = MessageSetOptions {
            options: vec![
                (0x48415254, 3000), // Heartbeat
                (0x434C5053, 1),    // ClipboardSharing
                (0x4D444C54, 0),    // RelativeMouseMoves
            ],
        };
        let bytes = msg_multi.to_bytes();
        assert_eq!(&bytes[0..4], b"DSOP");
        assert_eq!(&bytes[4..8], &7u32.to_be_bytes()); // length = 1 + 6 elements

        let parsed = MessageSetOptions::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_multi);
    }

    #[test]
    fn test_dftr() {
        // Data start
        let msg_start = MessageFileTransfer {
            mark: 1,
            data: "1024".into(),
        };
        let bytes = msg_start.to_bytes();
        assert_eq!(&bytes[0..4], b"DFTR");
        assert_eq!(bytes[4], 1);
        assert_eq!(&bytes[5..9], &4u32.to_be_bytes());
        assert_eq!(&bytes[9..13], b"1024");

        let parsed = MessageFileTransfer::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_start);

        // Data chunk
        let msg_chunk = MessageFileTransfer {
            mark: 2,
            data: "file content".into(),
        };
        let bytes = msg_chunk.to_bytes();
        let parsed = MessageFileTransfer::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_chunk);

        // Data end
        let msg_end = MessageFileTransfer {
            mark: 3,
            data: "".into(),
        };
        let bytes = msg_end.to_bytes();
        let parsed = MessageFileTransfer::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_end);
    }

    #[test]
    fn test_ddrg() {
        // Normal case
        let msg = MessageDragInfo {
            size: 2,
            data: "/path/to/file1\0/path/to/file2".into(),
        };
        let bytes = msg.to_bytes();
        assert_eq!(&bytes[0..4], b"DDRG");
        assert_eq!(&bytes[4..6], &2u16.to_be_bytes());

        let parsed = MessageDragInfo::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);

        // Edge case: no files
        let msg_empty = MessageDragInfo {
            size: 0,
            data: "".into(),
        };
        let bytes = msg_empty.to_bytes();
        let parsed = MessageDragInfo::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_empty);
    }

    #[test]
    fn test_secn() {
        // Normal case
        let msg = MessageSecureEncryption {
            data: "Terminal".into(),
        };
        let bytes = msg.to_bytes();
        assert_eq!(&bytes[0..4], b"SECN");
        assert_eq!(&bytes[4..8], &8u32.to_be_bytes());
        assert_eq!(&bytes[8..16], b"Terminal");

        let parsed = MessageSecureEncryption::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);

        // Edge case: empty app name
        let msg_empty = MessageSecureEncryption { data: "".into() };
        let bytes = msg_empty.to_bytes();
        let parsed = MessageSecureEncryption::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_empty);
    }

    #[test]
    fn test_lsyn() {
        // Normal case
        let msg = MessageLegacySynergy {
            data: "en,de,fr".into(),
        };
        let bytes = msg.to_bytes();
        assert_eq!(&bytes[0..4], b"LSYN");
        assert_eq!(&bytes[4..8], &8u32.to_be_bytes());
        assert_eq!(&bytes[8..16], b"en,de,fr");

        let parsed = MessageLegacySynergy::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);

        // Edge case: single language
        let msg_single = MessageLegacySynergy { data: "en".into() };
        let bytes = msg_single.to_bytes();
        let parsed = MessageLegacySynergy::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_single);
    }

    #[test]
    fn test_qinf() {
        let msg = MessageQueryInfo;
        let bytes = msg.to_bytes();
        assert_eq!(&bytes, b"QINF");

        let parsed = MessageQueryInfo::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_eicv() {
        // Normal case
        let msg = MessageIncompatibleVersion {
            major_remote: 2,
            minor_remote: 0,
        };
        let bytes = msg.to_bytes();
        assert_eq!(&bytes[0..4], b"EICV");
        assert_eq!(&bytes[4..6], &2u16.to_be_bytes());
        assert_eq!(&bytes[6..8], &0u16.to_be_bytes());

        let parsed = MessageIncompatibleVersion::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);

        // Edge case: version 0.0
        let msg_zero = MessageIncompatibleVersion {
            major_remote: 0,
            minor_remote: 0,
        };
        let bytes = msg_zero.to_bytes();
        let parsed = MessageIncompatibleVersion::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg_zero);
    }

    #[test]
    fn test_ebsy() {
        let msg = MessageServerBusy;
        let bytes = msg.to_bytes();
        assert_eq!(&bytes, b"EBSY");

        let parsed = MessageServerBusy::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_eunk() {
        let msg = MessageUnknownClient;
        let bytes = msg.to_bytes();
        assert_eq!(&bytes, b"EUNK");

        let parsed = MessageUnknownClient::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn test_ebad() {
        let msg = MessageProtocolError;
        let bytes = msg.to_bytes();
        assert_eq!(&bytes, b"EBAD");

        let parsed = MessageProtocolError::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, msg);
    }

    // General error tests
    #[test]
    fn test_insufficient_data() {
        let data = b"CI"; // Too short
        let result = parse_message(data);
        assert!(matches!(
            result,
            Err(ProtocolError::InsufficientData { .. })
        ));
    }

    #[test]
    fn test_unknown_message() {
        let data = b"XXXX";
        let result = parse_message(data);
        assert!(matches!(result, Err(ProtocolError::UnknownMessageCode(_))));
    }
}
