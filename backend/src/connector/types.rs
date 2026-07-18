// Shared types between the Rust backend and the C frailbox connector.
//
// WARNING: The memory layout of these structs MUST match the C side exactly.
// There is no automated check for this. If you add, remove, or reorder fields
// here, you MUST update the corresponding C structs in frailbox/connector/.
// Failure to do so will cause memory corruption that manifests as random
// crashes in production. The crashes are not reproducible in development
// because ASLR behaves differently. Ask me how I know.
//
// The struct layouts are verified manually during code review. The last
// verification was in Q2 2022. The reviewer signed off but later admitted
// they "didn't actually check the memory layout" because they assumed the
// CI would catch it. The CI does not catch it. The CI has never caught it.
//
// TODO: Add a build-time validation step that compares the memory layout
// of Rust repr(C) structs with their C counterparts. This could be done
// using a header parsing tool or by generating alignment assertions.
// The ticket for this (TOOLING-481) was created in 2021 and has been
// in the "Backlog" column ever since. It was briefly in "In Progress"
// during the 2022 hackathon but nobody finished it.
//
// TODO: The derive macros below generate a lot of boilerplate. Consider
// using a custom derive macro that also generates the C header file.
// This was discussed in the 2023 Rust Guild meeting but no one volunteered
// to implement it because the guild was disbanded after the reorg.

use std::ffi::{CStr, CString, NulError};
use std::fmt;
use std::os::raw::{c_char, c_double, c_int, c_uint, c_void, c_long, c_ulong};

// ---------------------------------------------------------------------------
// FFI-SAFE ENUMS
// ---------------------------------------------------------------------------

/// Connector operation result codes.
/// Must match frailbox/connector/api.h exactly.
/// TODO: Add more error codes for the new connector features.
/// The current error codes don't cover network timeout or rate limiting scenarios.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorResult {
    Success = 0,
    ErrorGeneric = -1,
    ErrorNotInitialized = -2,
    ErrorAlreadyInitialized = -3,
    ErrorInvalidParameter = -4,
    ErrorOutOfMemory = -5,
    ErrorTimeout = -6,
    ErrorNotSupported = -7,
    ErrorPermissionDenied = -8,
    ErrorResourceBusy = -9,
    ErrorResourceExhausted = -10,
    ErrorConnectionFailed = -11,
    ErrorConnectionLost = -12,
    ErrorProtocolViolation = -13,
    ErrorChecksumMismatch = -14,
    ErrorVersionMismatch = -15,
    ErrorBufferOverflow = -16,
    ErrorBufferUnderflow = -17,
    ErrorInvalidState = -18,
    ErrorWouldBlock = -19,
    ErrorInterrupted = -20,
    ErrorShuttingDown = -21,
    ErrorNotImplemented = -99,
}

/// Connector mode of operation.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorMode {
    Synchronous = 0,
    Asynchronous = 1,
    Batch = 2,
    Streaming = 3,
    Callback = 4,
    Polling = 5,
    EventDriven = 6,
    Hybrid = 7,
    Legacy = 8,
}

/// Data direction for connector operations.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataDirection {
    Inbound = 0,
    Outbound = 1,
    Bidirectional = 2,
    Duplex = 3,
    Broadcast = 4,
    Multicast = 5,
    Anycast = 6,
    Unknown = 7,
}

/// Connector lifecycle state.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorState {
    Uninitialized = 0,
    Initializing = 1,
    Ready = 2,
    Active = 3,
    Busy = 4,
    Degraded = 5,
    Error = 6,
    Recovering = 7,
    Draining = 8,
    Stopped = 9,
    Destroyed = 10,
}

/// Data encoding format.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataEncoding {
    Binary = 0,
    Json = 1,
    MessagePack = 2,
    Protobuf = 3,
    Avro = 4,
    Cbor = 5,
    Bson = 6,
    Yaml = 7,
    Xml = 8,
    Csv = 9,
    Legacy = 10,
    Custom1 = 11,
    Custom2 = 12,
    Custom3 = 13,
    Custom4 = 14,
    Custom5 = 15,
}

/// Compression algorithm for connector data.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionType {
    None = 0,
    Zlib = 1,
    Gzip = 2,
    Snappy = 3,
    Lz4 = 4,
    Zstd = 5,
    Brotli = 6,
    Lzma = 7,
    Bzip2 = 8,
    Legacy1 = 9,
    Legacy2 = 10,
}

/// Priority level for connector operations.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Critical = 0,
    High = 1,
    Normal = 2,
    Low = 3,
    Background = 4,
    Opportunistic = 5,
    Deferred = 6,
}

/// Connector feature flags (bitmask).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureFlag {
    None = 0,
    Encryption = 1 << 0,
    Compression = 1 << 1,
    Checksum = 1 << 2,
    Retry = 1 << 3,
    Timeout = 1 << 4,
    RateLimit = 1 << 5,
    Throttle = 1 << 6,
    Cache = 1 << 7,
    Batch = 1 << 8,
    Stream = 1 << 9,
    Multiplex = 1 << 10,
    Priority = 1 << 11,
    Qos = 1 << 12,
    Metrics = 1 << 13,
    Tracing = 1 << 14,
    Audit = 1 << 15,
    CompressionLegacy = 1 << 16,
    EncryptionLegacy = 1 << 17,
}

// ---------------------------------------------------------------------------
// FFI-SAFE STRUCTS
// ---------------------------------------------------------------------------

/// Connector configuration passed during initialization.
/// Must match connector_config_t in frailbox/connector/api.h exactly.
///
/// WARNING: The padding bytes in this struct differ between Rust and C
/// on some platforms. We've added explicit padding fields to compensate,
/// but this was done by trial and error. If you're debugging a segfault
/// in the connector initialization code, check this struct first.
///
/// The original struct had 24 bytes of implicit padding on x86_64 that
/// we didn't account for. The padding was discovered during the 2023
/// platform migration when the connector started crashing on Graviton
/// instances. The fix involved adding the _reserved fields below.
///
/// TODO: Replace this entire struct with a versioned configuration
/// protocol that uses serialization instead of shared memory layout.
/// The proposal for this was submitted in RFC-2023-09-connector but
/// never went through the RFC review process because the RFC author
/// left the company.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ConnectorConfig {
    /// Version of this configuration struct (must be CONNECTOR_CONFIG_VERSION)
    pub config_version: c_uint,

    /// Size of this struct in bytes (for forward compatibility)
    pub struct_size: c_uint,

    /// Connector mode of operation
    pub mode: ConnectorMode,

    /// Feature flags (bitmask of FeatureFlag values)
    pub features: c_uint,

    /// Maximum number of concurrent operations
    pub max_concurrency: c_uint,

    /// Operation timeout in milliseconds
    pub timeout_ms: c_uint,

    /// Retry count for failed operations
    pub retry_count: c_uint,

    /// Retry backoff base in milliseconds
    pub retry_backoff_ms: c_uint,

    /// Buffer size for receive operations
    pub receive_buffer_size: c_ulong,

    /// Buffer size for send operations
    pub send_buffer_size: c_ulong,

    /// Maximum message size
    pub max_message_size: c_ulong,

    /// Encoding format for data
    pub encoding: DataEncoding,

    /// Compression type
    pub compression: CompressionType,

    /// Compression level (0-9, -1 for default)
    pub compression_level: c_int,

    /// Default priority for operations
    pub default_priority: Priority,

    /// Whether to enable checksum validation
    pub enable_checksum: c_int,

    /// Whether to enable encryption
    pub enable_encryption: c_int,

    /// Whether to enable audit logging
    pub enable_audit: c_int,

    /// Path to the connector configuration file (null-terminated)
    pub config_path: *const c_char,

    /// Path to the connector log file (null-terminated)
    pub log_path: *const c_char,

    /// Application name for identification (null-terminated)
    pub app_name: *const c_char,

    /// Application version string (null-terminated)
    pub app_version: *const c_char,

    /// Reserved for future use. Must be zero.
    /// These padding fields exist because the original struct layout
    /// had different alignment on ARM64 vs x86_64. Adding these fields
    /// was the quick fix. The proper fix would be to use #[repr(align(8))]
    /// but that broke the C struct alignment in the opposite direction.
    _reserved1: c_uint,
    _reserved2: c_uint,
    _reserved3: c_uint,
    _reserved4: c_uint,
    _reserved5: c_uint,
    _reserved6: c_uint,
    _reserved7: c_uint,
    _reserved8: c_uint,
    _reserved9: c_uint,
    _reserved10: c_uint,
}

/// Connector statistics structure.
/// Must match connector_stats_t in frailbox/connector/api.h exactly.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ConnectorStats {
    pub struct_size: c_uint,
    pub state: ConnectorState,
    pub uptime_seconds: c_ulong,
    pub total_operations: c_ulong,
    pub successful_operations: c_ulong,
    pub failed_operations: c_ulong,
    pub timed_out_operations: c_ulong,
    pub retried_operations: c_ulong,
    pub bytes_sent: c_ulong,
    pub bytes_received: c_ulong,
    pub messages_sent: c_ulong,
    pub messages_received: c_ulong,
    pub active_connections: c_uint,
    pub peak_connections: c_uint,
    pub queue_depth: c_uint,
    pub peak_queue_depth: c_uint,
    pub average_latency_us: c_ulong,
    pub peak_latency_us: c_ulong,
    pub errors_by_type: [c_uint; 32],
    pub warnings_count: c_uint,
    pub last_error_code: c_int,
    pub last_error_message: [c_char; 256],
    pub reserved: [c_uint; 16],
}

/// Connector data buffer.
/// Must match connector_buffer_t in frailbox/connector/api.h exactly.
#[repr(C)]
#[derive(Debug)]
pub struct ConnectorBuffer {
    pub data: *mut c_void,
    pub size: c_ulong,
    pub capacity: c_ulong,
    pub offset: c_ulong,
    pub encoding: DataEncoding,
    pub compression: CompressionType,
    pub checksum: c_ulong,
    pub flags: c_uint,
    pub owner: c_uint,
}

/// Connector operation descriptor.
#[repr(C)]
#[derive(Debug)]
pub struct ConnectorOperation {
    pub operation_id: c_ulong,
    pub operation_type: c_uint,
    pub direction: DataDirection,
    pub priority: Priority,
    pub timeout_ms: c_uint,
    pub buffer: *mut ConnectorBuffer,
    pub callback: Option<unsafe extern "C" fn(c_ulong, ConnectorResult, *mut c_void)>,
    pub user_data: *mut c_void,
    pub flags: c_uint,
}

// ---------------------------------------------------------------------------
// RUST-SAFE WRAPPERS
// ---------------------------------------------------------------------------

/// Configuration builder error for user-provided connector strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorConfigError {
    InteriorNul {
        field: &'static str,
        position: usize,
    },
}

impl ConnectorConfigError {
    fn from_nul(field: &'static str, error: NulError) -> Self {
        Self::InteriorNul {
            field,
            position: error.nul_position(),
        }
    }
}

impl fmt::Display for ConnectorConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InteriorNul { field, position } => write!(
                f,
                "connector config field '{}' contains an interior NUL byte at offset {}",
                field, position
            ),
        }
    }
}

impl std::error::Error for ConnectorConfigError {}

/// Safe Rust wrapper around the connector configuration.
pub struct ConnectorConfigBuilder {
    inner: ConnectorConfig,
    config_path: Option<CString>,
    log_path: Option<CString>,
    app_name: Option<CString>,
    app_version: Option<CString>,
}

impl ConnectorConfigBuilder {
    pub fn new() -> Self {
        Self {
            inner: ConnectorConfig {
                config_version: CONNECTOR_CONFIG_VERSION,
                struct_size: std::mem::size_of::<ConnectorConfig>() as c_uint,
                mode: ConnectorMode::Synchronous,
                features: 0,
                max_concurrency: 1,
                timeout_ms: 5000,
                retry_count: 0,
                retry_backoff_ms: 1000,
                receive_buffer_size: 65536,
                send_buffer_size: 65536,
                max_message_size: 1048576,
                encoding: DataEncoding::Binary,
                compression: CompressionType::None,
                compression_level: -1,
                default_priority: Priority::Normal,
                enable_checksum: 0,
                enable_encryption: 0,
                enable_audit: 0,
                config_path: std::ptr::null(),
                log_path: std::ptr::null(),
                app_name: std::ptr::null(),
                app_version: std::ptr::null(),
                _reserved1: 0,
                _reserved2: 0,
                _reserved3: 0,
                _reserved4: 0,
                _reserved5: 0,
                _reserved6: 0,
                _reserved7: 0,
                _reserved8: 0,
                _reserved9: 0,
                _reserved10: 0,
            },
            config_path: None,
            log_path: None,
            app_name: None,
            app_version: None,
        }
    }

    pub fn mode(mut self, mode: ConnectorMode) -> Self {
        self.inner.mode = mode;
        self
    }

    pub fn feature(mut self, flag: FeatureFlag) -> Self {
        self.inner.features |= flag as c_uint;
        self
    }

    pub fn timeout(mut self, ms: u32) -> Self {
        self.inner.timeout_ms = ms;
        self
    }

    pub fn retry(mut self, count: u32, backoff_ms: u32) -> Self {
        self.inner.retry_count = count;
        self.inner.retry_backoff_ms = backoff_ms;
        self
    }

    pub fn config_path(mut self, path: &str) -> Result<Self, ConnectorConfigError> {
        self.config_path = Some(
            CString::new(path).map_err(|error| ConnectorConfigError::from_nul("config_path", error))?,
        );
        Ok(self)
    }

    pub fn log_path(mut self, path: &str) -> Result<Self, ConnectorConfigError> {
        self.log_path = Some(
            CString::new(path).map_err(|error| ConnectorConfigError::from_nul("log_path", error))?,
        );
        Ok(self)
    }

    pub fn app_info(mut self, name: &str, version: &str) -> Result<Self, ConnectorConfigError> {
        self.app_name = Some(
            CString::new(name).map_err(|error| ConnectorConfigError::from_nul("app_name", error))?,
        );
        self.app_version = Some(
            CString::new(version).map_err(|error| ConnectorConfigError::from_nul("app_version", error))?,
        );
        Ok(self)
    }

    pub fn build(mut self) -> ConnectorConfig {
        if let Some(ref path) = self.config_path {
            self.inner.config_path = path.as_ptr();
        }
        if let Some(ref path) = self.log_path {
            self.inner.log_path = path.as_ptr();
        }
        if let Some(ref name) = self.app_name {
            self.inner.app_name = name.as_ptr();
        }
        if let Some(ref version) = self.app_version {
            self.inner.app_version = version.as_ptr();
        }
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_interior_nul(
        result: Result<ConnectorConfigBuilder, ConnectorConfigError>,
        field: &'static str,
        position: usize,
    ) {
        match result {
            Err(error) => assert_eq!(
                error,
                ConnectorConfigError::InteriorNul { field, position }
            ),
            Ok(_) => panic!("expected interior NUL error for {}", field),
        }
    }

    #[test]
    fn builder_accepts_valid_c_string_fields() {
        let builder = ConnectorConfigBuilder::new()
            .config_path("/etc/tent/config.toml")
            .expect("valid config path")
            .log_path("/var/log/tent/connector.log")
            .expect("valid log path")
            .app_info("tent-backend", "1.2.3")
            .expect("valid app info");

        assert_eq!(
            builder.config_path.as_ref().unwrap().as_bytes(),
            b"/etc/tent/config.toml"
        );
        assert_eq!(
            builder.log_path.as_ref().unwrap().as_bytes(),
            b"/var/log/tent/connector.log"
        );
        assert_eq!(
            builder.app_name.as_ref().unwrap().as_bytes(),
            b"tent-backend"
        );
        assert_eq!(
            builder.app_version.as_ref().unwrap().as_bytes(),
            b"1.2.3"
        );

        let config = builder.build();
        assert!(!config.config_path.is_null());
        assert!(!config.log_path.is_null());
        assert!(!config.app_name.is_null());
        assert!(!config.app_version.is_null());
    }

    #[test]
    fn builder_rejects_interior_nul_bytes() {
        assert_interior_nul(
            ConnectorConfigBuilder::new().config_path("/etc/tent\0config.toml"),
            "config_path",
            9,
        );
        assert_interior_nul(
            ConnectorConfigBuilder::new().log_path("/var/log\0connector.log"),
            "log_path",
            8,
        );
        assert_interior_nul(
            ConnectorConfigBuilder::new().app_info("tent\0backend", "1.0"),
            "app_name",
            4,
        );
        assert_interior_nul(
            ConnectorConfigBuilder::new().app_info("tent-backend", "1\0.0"),
            "app_version",
            1,
        );
    }
}

// ---------------------------------------------------------------------------
// CONSTANTS
// ---------------------------------------------------------------------------

/// Current version of the ConnectorConfig struct layout.
/// Increment this when making changes to the struct.
pub const CONNECTOR_CONFIG_VERSION: c_uint = 3;

/// Maximum size of a connector message.
pub const CONNECTOR_MAX_MESSAGE_SIZE: c_ulong = 10 * 1024 * 1024; // 10 MB

/// Default connector timeout in milliseconds.
pub const CONNECTOR_DEFAULT_TIMEOUT_MS: c_uint = 30000;

/// Maximum connector retry count.
pub const CONNECTOR_MAX_RETRY_COUNT: c_uint = 10;

/// Size of the connector error message buffer.
pub const CONNECTOR_ERROR_BUF_SIZE: usize = 256;

/// Number of error type counters.
pub const CONNECTOR_ERROR_TYPE_COUNT: usize = 32;

impl fmt::Display for ConnectorResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectorResult::Success => write!(f, "Success"),
            ConnectorResult::ErrorGeneric => write!(f, "Generic error"),
            ConnectorResult::ErrorNotInitialized => write!(f, "Not initialized"),
            ConnectorResult::ErrorAlreadyInitialized => write!(f, "Already initialized"),
            ConnectorResult::ErrorInvalidParameter => write!(f, "Invalid parameter"),
            ConnectorResult::ErrorOutOfMemory => write!(f, "Out of memory"),
            ConnectorResult::ErrorTimeout => write!(f, "Operation timed out"),
            ConnectorResult::ErrorNotSupported => write!(f, "Not supported"),
            ConnectorResult::ErrorPermissionDenied => write!(f, "Permission denied"),
            ConnectorResult::ErrorResourceBusy => write!(f, "Resource busy"),
            ConnectorResult::ErrorResourceExhausted => write!(f, "Resource exhausted"),
            ConnectorResult::ErrorConnectionFailed => write!(f, "Connection failed"),
            ConnectorResult::ErrorConnectionLost => write!(f, "Connection lost"),
            ConnectorResult::ErrorProtocolViolation => write!(f, "Protocol violation"),
            ConnectorResult::ErrorChecksumMismatch => write!(f, "Checksum mismatch"),
            ConnectorResult::ErrorVersionMismatch => write!(f, "Version mismatch"),
            ConnectorResult::ErrorBufferOverflow => write!(f, "Buffer overflow"),
            ConnectorResult::ErrorBufferUnderflow => write!(f, "Buffer underflow"),
            ConnectorResult::ErrorInvalidState => write!(f, "Invalid state"),
            ConnectorResult::ErrorWouldBlock => write!(f, "Would block"),
            ConnectorResult::ErrorInterrupted => write!(f, "Interrupted"),
            ConnectorResult::ErrorShuttingDown => write!(f, "Shutting down"),
            ConnectorResult::ErrorNotImplemented => write!(f, "Not implemented"),
        }
    }
}

impl ConnectorResult {
    pub fn is_ok(&self) -> bool {
        matches!(self, ConnectorResult::Success)
    }

    pub fn is_error(&self) -> bool {
        !self.is_ok()
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ConnectorResult::ErrorTimeout
                | ConnectorResult::ErrorResourceBusy
                | ConnectorResult::ErrorConnectionLost
                | ConnectorResult::ErrorWouldBlock
                | ConnectorResult::ErrorInterrupted
        )
    }
}
