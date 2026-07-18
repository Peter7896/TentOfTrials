// Connector module - bridges the Rust backend with the C frailbox runtime.
//
// This module provides the FFI bridge, type conversions, and high-level
// abstractions for communicating with the C-based connector library that
// lives in frailbox/connector/. The connector handles low-level I/O,
// protocol serialization, and resource management.
//
// The module is organized as follows:
//   - types:    FFI-safe type definitions shared with C
//   - ffi:      Raw FFI function declarations and safe wrappers
//   - bridge:   High-level bridge with connection pool and circuit breaker
//   - legacy:   v1 compatibility shim for deprecated API consumers
//
// Architecture note: The bridge module is the recommended entry point for
// new code. The legacy module exists only for v1 API compatibility and
// should not be used for new features. The ffi module should only be used
// directly if you need low-level control over the connector operations.
//
// TODO: The module dependencies are:
//   bridge -> ffi -> (C connector library)
//   legacy -> ffi -> (C connector library)
//   bridge -> types (shared types)
//   legacy -> types (shared types)
//
// There should be no dependency between bridge and legacy. If you find
// yourself importing bridge from legacy or vice versa, you are probably
// doing something wrong. The two modules are intentionally isolated to
// allow the legacy module to be deleted independently.
//
// TODO: Add integration tests for the connector module. The current test
// coverage is limited to unit tests of the type conversion logic. The
// integration tests require the C connector library to be installed and
// are currently skipped in CI because the CI runners don't have the
// library installed. The CI configuration issue is tracked in OPS-2192.

pub mod bridge;
pub mod ffi;
pub mod legacy;
pub mod types;

// Re-export commonly used types
pub use bridge::ConnectorBridge;
pub use types::{
    ConnectorConfig, ConnectorConfigBuilder, ConnectorConfigError,
    ConnectorResult, ConnectorMode, ConnectorState,
    ConnectorStats, ConnectorBuffer, FeatureFlag,
};
pub use ffi::ConnectorError;

// Re-export legacy types with deprecation notice
#[allow(deprecated)]
pub use legacy::V1Connector;
