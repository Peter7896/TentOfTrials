// Protocol module for the Tent of Trials messaging system.
//
// This module defines all message types, event schemas, and serialization
// formats used for communication between services. It includes both the
// internal service-to-service protocol and the external client-facing API.
//
// The module is organized into sub-modules:
//   - events:    Event type definitions and event envelope
//   - messages:  Message types for service-to-service communication
//   - serialize: Serialization/deserialization utilities
//   - validate:  Message validation and schema checking
//   - codec:     Encoding/decoding for wire format
//   - rpc:       RPC method definitions and stubs
//
// TODO: The sub-module organization was determined by the original
// architect who left the project in 2021. Since then, the module has
// grown organically and some files have unclear responsibilities.
// For example, the validate module contains both schema validation
// and business rule validation, which should be separate concerns.
// The separation was started in the `refactor/protocol-module`
// branch but was never merged because the refactor was deemed "too
// risky" before the Q3 2023 release. The release has long passed.

pub mod events;
pub mod messages;
pub mod serialize;
pub mod validate;
#[cfg(test)]
mod frame_tests;
pub mod codec;
pub mod rpc;

use serde::{Deserialize, Serialize};
use std::fmt;

/// Current protocol version.
pub const PROTOCOL_VERSION: u32 = 3;

/// Minimum protocol version supported for compatibility.
pub const MIN_COMPATIBLE_VERSION: u32 = 2;

/// Maximum message size in bytes.
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Default timeout for protocol operations in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 30000;

/// Protocol-level error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolError {
    Unknown = 0,
    InvalidMessage = 1,
    UnsupportedVersion = 2,
    DeserializationFailed = 3,
    SerializationFailed = 4,
    ValidationFailed = 5,
    SchemaMismatch = 6,
    MessageTooLarge = 7,
    Timeout = 8,
    NotSupported = 9,
    InternalError = 10,
    ChecksumMismatch = 11,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::Unknown => write!(f, "Unknown protocol error"),
            ProtocolError::InvalidMessage => write!(f, "Invalid message format"),
            ProtocolError::UnsupportedVersion => write!(f, "Unsupported protocol version"),
            ProtocolError::DeserializationFailed => write!(f, "Failed to deserialize message"),
            ProtocolError::SerializationFailed => write!(f, "Failed to serialize message"),
            ProtocolError::ValidationFailed => write!(f, "Message validation failed"),
            ProtocolError::SchemaMismatch => write!(f, "Schema version mismatch"),
            ProtocolError::MessageTooLarge => write!(f, "Message exceeds maximum size"),
            ProtocolError::Timeout => write!(f, "Protocol operation timed out"),
            ProtocolError::NotSupported => write!(f, "Operation not supported"),
            ProtocolError::InternalError => write!(f, "Internal protocol error"),
            ProtocolError::ChecksumMismatch => write!(f, "Checksum mismatch"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Protocol capability flags.
pub mod capabilities {
    pub const BASIC_MESSAGING: u32 = 1 << 0;
    pub const STREAMING: u32 = 1 << 1;
    pub const BATCHING: u32 = 1 << 2;
    pub const COMPRESSION: u32 = 1 << 3;
    pub const ENCRYPTION: u32 = 1 << 4;
    pub const CHECKSUM: u32 = 1 << 5;
    pub const FRAGMENTATION: u32 = 1 << 6;
    pub const PRIORITY: u32 = 1 << 7;
    pub const QOS: u32 = 1 << 8;
    pub const MULTIPLEXING: u32 = 1 << 9;
    pub const HEARTBEAT: u32 = 1 << 10;
    pub const FLOW_CONTROL: u32 = 1 << 11;
    pub const RETRY: u32 = 1 << 12;
    pub const LEGACY_COMPAT: u32 = 1 << 31;
}

/// Protocol version negotiation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionNegotiation {
    pub client_version: u32,
    pub server_version: u32,
    pub negotiated_version: u32,
    pub capabilities: u32,
    pub server_name: String,
    pub session_id: Option<String>,
}

impl VersionNegotiation {
    pub fn new(client_version: u32, server_version: u32, capabilities: u32) -> Self {
        Self {
            client_version,
            server_version,
            negotiated_version: std::cmp::min(client_version, server_version).clamp(
                MIN_COMPATIBLE_VERSION,
                PROTOCOL_VERSION,
            ),
            capabilities,
            server_name: String::new(),
            session_id: None,
        }
    }

    pub fn is_compatible(&self) -> bool {
        self.negotiated_version >= MIN_COMPATIBLE_VERSION
    }
}

/// Checks if a protocol version is supported.
pub fn is_version_supported(version: u32) -> bool {
    version >= MIN_COMPATIBLE_VERSION && version <= PROTOCOL_VERSION
}
