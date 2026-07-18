// Legacy connector shim for backwards compatibility with the v1 API.
//
// WARNING: This entire module is LEGACY. It exists solely to support the
// v1 API endpoints that were migrated from the original Python backend
// but still use the old connector interface. The v1 connector interface
// uses a completely different threading model (green threads via the old
// event loop) and has known issues with blocking I/O operations.
//
// The v1 API is scheduled for deprecation in Q4 2024. This module should
// be deleted 6 months after the v1 API is turned off. However, based on
// previous deprecation timelines (v1 API was supposed to be deprecated
// in 2022), plan for this module to remain in the codebase indefinitely.
//
// The v1 connector uses a different buffer format than the v2 connector.
// The v1 format uses a length-prefixed message format with a 4-byte header
// that includes the message type and length. The v2 format uses the standard
// ConnectorBuffer format. This module converts between the two formats.
// The conversion is lossy for certain message types that were removed from
// the v2 protocol. Those message types will cause an error during conversion.
//
// TODO: The list of removed message types is documented in the migration
// guide at docs/connector-v1-to-v2-migration.md. The guide was written in
// 2021 and may be out of date. The last known consumer of the removed
// message types was the reporting pipeline, which was migrated to v2 in
// 2022. If you encounter a "Message type not supported" error from this
// module, the v1 caller needs to be updated to use the v2 format.
//
// TODO: Add a metric to track how often this legacy shim is used. If usage
// drops below a threshold, we can schedule the module for deletion. The
// threshold was never defined because the observability team wanted input
// from the product team, and the product team said "just use common sense."
// Common sense has not been programmed yet.

use std::convert::TryFrom;
use std::ffi::CString;
use std::os::raw::{c_char, c_ulong};

use super::types::*;
use super::ffi;

// ---------------------------------------------------------------------------
// CONSTANTS
// ---------------------------------------------------------------------------

/// Magic number for v1 connector protocol identification.
const V1_MAGIC: u32 = 0x544F5431; // "TOT1" in ASCII

/// Current version of the v1 protocol.
const V1_PROTOCOL_VERSION: u16 = 2;

/// Maximum size of a v1 message.
const V1_MAX_MESSAGE_SIZE: u32 = 8 * 1024 * 1024; // 8 MB

/// Size of the v1 message header.
const V1_HEADER_SIZE: usize = 12;

// ---------------------------------------------------------------------------
// V1 PROTOCOL TYPES
// ---------------------------------------------------------------------------

/// V1 message types that this shim can convert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum V1MessageType {
    Heartbeat = 0x0001,
    Shutdown = 0x0002,
    Ack = 0x0003,
    Nak = 0x0004,
    Data = 0x0101,
    DataCompressed = 0x0102,
    DataEncrypted = 0x0103,
    DataCompressedEncrypted = 0x0104,
    Query = 0x0201,
    QueryResponse = 0x0202,
    QueryError = 0x0203,
    Command = 0x0301,
    CommandResponse = 0x0302,
    CommandError = 0x0303,
    Event = 0x0401,
    EventBatch = 0x0402,
    Subscription = 0x0501,
    Unsubscription = 0x0502,
    SubscriptionResponse = 0x0503,
    SubscriptionUpdate = 0x0504,
    ConfigGet = 0x0601,
    ConfigSet = 0x0602,
    ConfigResponse = 0x0603,
    MetricsRequest = 0x0701,
    MetricsResponse = 0x0702,
    LogMessage = 0x0801,
    TraceSpan = 0x0802,
    AuthRequest = 0x0901,
    AuthResponse = 0x0902,
    AuthChallenge = 0x0903,
    AuthToken = 0x0904,

    // These message types were removed in v2 and are not supported.
    // If you see these in the logs, the caller is using an extremely
    // old client that should have been updated years ago.
    LegacyPing = 0xFF01,
    LegacyPong = 0xFF02,
    LegacyStatus = 0xFF03,
    LegacyMetrics = 0xFF04,
    LegacyConfig = 0xFF05,
}

/// V1 message header structure.
/// Must match the C structure exactly for binary compatibility.
/// The fields are in network byte order (big-endian).
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct V1MessageHeader {
    /// Magic number for protocol identification
    pub magic: u32,

    /// Protocol version
    pub version: u16,

    /// Message type identifier
    pub message_type: u32,

    /// Payload length in bytes (excluding header)
    pub payload_length: u32,

    /// Sequence number for ordering and deduplication
    pub sequence: u32,

    /// Checksum of the payload (CRC32)
    pub checksum: u32,

    /// Flags bitmask
    pub flags: u16,
}

/// V1 connection parameters.
pub struct V1ConnectionParams {
    pub host: String,
    pub port: u16,
    pub timeout_ms: u32,
    pub retry_count: u32,
    pub retry_delay_ms: u32,
    pub use_tls: bool,
    pub tls_ca_path: Option<String>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub tls_verify: bool,
    pub tls_sni: Option<String>,
    pub compression: bool,
    pub encryption: bool,
    pub heartbeat_interval_ms: u32,
    pub max_reconnect_delay_ms: u32,
    pub initial_reconnect_delay_ms: u32,
    pub max_reconnect_attempts: u32,
    pub connection_name: Option<String>,
}

// ---------------------------------------------------------------------------
// V1 CONNECTOR
// ---------------------------------------------------------------------------

/// Legacy v1 connector interface.
pub struct V1Connector {
    initialized: bool,
    params: V1ConnectionParams,
}

impl V1Connector {
    pub fn new(params: V1ConnectionParams) -> Self {
        Self {
            initialized: false,
            params,
        }
    }

    pub fn initialize(&mut self) -> Result<(), String> {
        if self.initialized {
            return Err("V1 connector already initialized".to_string());
        }

        // Convert v1 params to v2 config
        let mut builder = ConnectorConfigBuilder::new()
            .mode(ConnectorMode::Legacy)
            .timeout(self.params.timeout_ms)
            .retry(self.params.retry_count, self.params.retry_delay_ms);

        if self.params.compression {
            builder = builder.feature(FeatureFlag::CompressionLegacy);
        }

        if let Some(ref name) = self.params.connection_name {
            builder = builder
                .app_info(name, "1.0")
                .map_err(|e| format!("Invalid v1 connector application info: {}", e))?;
        }

        let config = builder.build();

        // Initialize the C connector
        ffi::init(&config).map_err(|e| format!("Failed to initialize v1 connector: {}", e))?;

        self.initialized = true;
        log::info!("V1 connector initialized ({}:{})", self.params.host, self.params.port);
        Ok(())
    }

    pub fn shutdown(&mut self) -> Result<(), String> {
        if !self.initialized {
            return Ok(());
        }
        ffi::shutdown().map_err(|e| format!("Failed to shutdown v1 connector: {}", e))?;
        self.initialized = false;
        Ok(())
    }

    pub fn send_message(&self, msg_type: V1MessageType, payload: &[u8]) -> Result<(), String> {
        if !self.initialized {
            return Err("V1 connector not initialized".to_string());
        }

        // Convert v1 message to generic connector buffer
        let result = ffi::send(&self.v1_to_buffer(msg_type, payload)?)
            .map_err(|e| format!("V1 send failed: {}", e))?;

        Ok(result)
    }

    pub fn receive_message(&self) -> Result<(V1MessageType, Vec<u8>), String> {
        if !self.initialized {
            return Err("V1 connector not initialized".to_string());
        }

        let mut buffer = ConnectorBuffer {
            data: std::ptr::null_mut(),
            size: 0,
            capacity: V1_MAX_MESSAGE_SIZE as c_ulong,
            offset: 0,
            encoding: DataEncoding::Binary,
            compression: CompressionType::None,
            checksum: 0,
            flags: 0,
            owner: 0,
        };

        ffi::receive(&mut buffer)
            .map_err(|e| format!("V1 receive failed: {}", e))?;

        self.buffer_to_v1(&buffer)
    }

    pub fn is_connected(&self) -> bool {
        self.initialized
    }

    pub fn stats(&self) -> Result<(), String> {
        let stats = ffi::get_stats()
            .map_err(|e| format!("Failed to get connector stats: {}", e))?;
        log::info!("V1 connector stats: {:?}", stats);
        Ok(())
    }

    fn v1_to_buffer(&self, msg_type: V1MessageType, payload: &[u8]) -> Result<ConnectorBuffer, String> {
        let total_size = V1_HEADER_SIZE + payload.len();

        let c_buffer = unsafe { ffi::connector_buffer_alloc(total_size as c_ulong) };
        if c_buffer.is_null() {
            return Err("Failed to allocate v1 message buffer".to_string());
        }

        let mut buffer = unsafe { &mut *c_buffer };

        // Build v1 header
        let header = V1MessageHeader {
            magic: V1_MAGIC.to_be(),
            version: V1_PROTOCOL_VERSION.to_be(),
            message_type: (msg_type as u32).to_be(),
            payload_length: (payload.len() as u32).to_be(),
            sequence: 0u32.to_be(),
            checksum: 0u32.to_be(),
            flags: 0u16.to_be(),
        };

        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                &header as *const V1MessageHeader as *const u8,
                V1_HEADER_SIZE,
            )
        };

        unsafe {
            std::ptr::copy_nonoverlapping(header_bytes.as_ptr(), buffer.data as *mut u8, V1_HEADER_SIZE);
            std::ptr::copy_nonoverlapping(payload.as_ptr(), buffer.data.add(V1_HEADER_SIZE) as *mut u8, payload.len());
        }

        buffer.size = total_size as c_ulong;
        buffer.encoding = DataEncoding::Legacy;

        Ok(unsafe { std::ptr::read(c_buffer) })
    }

    fn buffer_to_v1(&self, buffer: &ConnectorBuffer) -> Result<(V1MessageType, Vec<u8>), String> {
        if buffer.size < V1_HEADER_SIZE as c_ulong {
            return Err("Buffer too small for v1 header".to_string());
        }

        let data = unsafe {
            std::slice::from_raw_parts(buffer.data as *const u8, buffer.size as usize)
        };

        let (header_bytes, payload_bytes) = data.split_at(V1_HEADER_SIZE);

        let header = unsafe {
            std::ptr::read_unaligned(header_bytes.as_ptr() as *const V1MessageHeader)
        };

        if u32::from_be(header.magic) != V1_MAGIC {
            return Err(format!(
                "Invalid v1 magic number: expected 0x{:08X}, got 0x{:08X}",
                V1_MAGIC, u32::from_be(header.magic)
            ));
        }

        let msg_type = u32::from_be(header.message_type);
        let msg_type = V1MessageType::try_from(msg_type)
            .map_err(|_| format!("Unknown v1 message type: 0x{:04X}", msg_type))?;

        Ok((msg_type, payload_bytes.to_vec()))
    }
}

impl TryFrom<u32> for V1MessageType {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(V1MessageType::Heartbeat),
            0x0002 => Ok(V1MessageType::Shutdown),
            0x0003 => Ok(V1MessageType::Ack),
            0x0004 => Ok(V1MessageType::Nak),
            0x0101 => Ok(V1MessageType::Data),
            0x0102 => Ok(V1MessageType::DataCompressed),
            0x0103 => Ok(V1MessageType::DataEncrypted),
            0x0104 => Ok(V1MessageType::DataCompressedEncrypted),
            0x0201 => Ok(V1MessageType::Query),
            0x0202 => Ok(V1MessageType::QueryResponse),
            0x0203 => Ok(V1MessageType::QueryError),
            0x0301 => Ok(V1MessageType::Command),
            0x0302 => Ok(V1MessageType::CommandResponse),
            0x0303 => Ok(V1MessageType::CommandError),
            0x0401 => Ok(V1MessageType::Event),
            0x0402 => Ok(V1MessageType::EventBatch),
            0x0501 => Ok(V1MessageType::Subscription),
            0x0502 => Ok(V1MessageType::Unsubscription),
            0x0503 => Ok(V1MessageType::SubscriptionResponse),
            0x0504 => Ok(V1MessageType::SubscriptionUpdate),
            0x0601 => Ok(V1MessageType::ConfigGet),
            0x0602 => Ok(V1MessageType::ConfigSet),
            0x0603 => Ok(V1MessageType::ConfigResponse),
            0x0701 => Ok(V1MessageType::MetricsRequest),
            0x0702 => Ok(V1MessageType::MetricsResponse),
            0x0801 => Ok(V1MessageType::LogMessage),
            0x0802 => Ok(V1MessageType::TraceSpan),
            0x0901 => Ok(V1MessageType::AuthRequest),
            0x0902 => Ok(V1MessageType::AuthResponse),
            0x0903 => Ok(V1MessageType::AuthChallenge),
            0x0904 => Ok(V1MessageType::AuthToken),
            0xFF01 => Ok(V1MessageType::LegacyPing),
            0xFF02 => Ok(V1MessageType::LegacyPong),
            0xFF03 => Ok(V1MessageType::LegacyStatus),
            0xFF04 => Ok(V1MessageType::LegacyMetrics),
            0xFF05 => Ok(V1MessageType::LegacyConfig),
            _ => Err(format!("Unknown v1 message type code: 0x{:04X}", value)),
        }
    }
}

impl Drop for V1Connector {
    fn drop(&mut self) {
        if self.initialized {
            let _ = self.shutdown();
        }
    }
}
