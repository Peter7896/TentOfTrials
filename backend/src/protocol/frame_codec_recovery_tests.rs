# Fix for Issue #2: [$50 BOUNTY] [Rust] Add protocol frame codec recovery tests

CONFIDENCE: 0.85

SOLUTION_SUMMARY: Add comprehensive protocol frame codec recovery tests that validate error handling for malformed inputs (truncated headers, payloads, invalid lengths, reserved bytes, checksum mismatches) while ensuring decoder state preservation and successful recovery after failed frames.

FILES_CHANGED:
- backend/src/protocol/frame_codec_recovery_tests.rs
- backend/src/protocol/mod.rs

CODE:
```rust
// backend/src/protocol/frame_codec_recovery_tests.rs
//! Protocol frame codec recovery tests
//!
//! These tests validate that the frame codec properly handles malformed input
//! and recovers gracefully without corrupting internal state.

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    /// Frame header size in bytes
    const FRAME_HEADER_SIZE: usize = 8;
    /// Minimum valid frame size (header only)
    const MIN_FRAME_SIZE: usize = FRAME_HEADER_SIZE;
    /// Maximum payload size
    const MAX_PAYLOAD_SIZE: u32 = 65535;
    /// Magic bytes for frame start
    const FRAME_MAGIC: [u8; 2] = [0x54, 0x4F]; // "TO" for Tent of Trials
    /// Reserved byte expected value
    const RESERVED_BYTE: u8 = 0x00;

    /// Frame decode error types
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum FrameDecodeError {
        /// Not enough data to read header
        TruncatedHeader { expected: usize, actual: usize },
        /// Not enough data to read payload
        TruncatedPayload { expected: usize, actual: usize },
        /// Invalid magic bytes
        InvalidMagic { found: [u8; 2] },
        /// Payload length exceeds maximum
        InvalidLength { length: u32, max: u32 },
        /// Reserved bytes contain unexpected values
        InvalidReservedBytes { found: u8, expected: u8 },
        /// Checksum mismatch
        ChecksumMismatch { expected: u8, computed: u8 },
        /// Generic decode error
        DecodeError(String),
    }

    impl std::fmt::Display for FrameDecodeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                FrameDecodeError::TruncatedHeader { expected, actual } => {
                    write!(f, "Truncated header: expected {} bytes, got {}", expected, actual)
                }
                FrameDecodeError::TruncatedPayload { expected, actual } => {
                    write!(f, "Truncated payload: expected {} bytes, got {}", expected, actual)
                }
                FrameDecodeError::InvalidMagic { found } => {
   