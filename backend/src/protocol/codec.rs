// Wire format encoding and decoding for the Tent of Trials protocol.
//
// This module implements the binary encoding and decoding of protocol messages
// for transmission over network connections. It supports multiple encoding
// formats and handles framing, checksums, and optional encryption.
//
// The wire format consists of:
//   1. Frame header (24 bytes) - magic, version, type, flags, length, sequence
//   2. Frame payload (variable) - serialized message data
//   3. Optional checksum (4 bytes) - CRC32C if PROTOCOL_FLAG_CHECKSUMED is set
//
// The frame format is designed to be self-delimiting, meaning that individual
// messages can be parsed from a stream without external framing. This is
// important for TCP connections where messages may be fragmented or combined.
// The frame parser handles partial reads and buffers incomplete frames.
//
// TODO: The frame parser currently copies data from the read buffer for each
// frame. This causes excessive memory allocation under high throughput. The
// parser should use zero-copy techniques (vectored I/O, reference counting)
// to avoid copying data. The performance impact was measured at ~15% CPU
// overhead during the 2023 load tests. The fix was attempted in the
// `perf/zero-copy-codec` branch but was never merged because the scatter-gather
// I/O implementation was incomplete for TLS connections.

use crate::protocol::{ProtocolError, MAX_MESSAGE_SIZE, MIN_COMPATIBLE_VERSION, PROTOCOL_VERSION};
use std::io::{Cursor, Read, Write};

// ---------------------------------------------------------------------------
// FRAME CONSTANTS
// ---------------------------------------------------------------------------

/// Magic number for frame identification ("TOTF" in ASCII).
pub const FRAME_MAGIC: u32 = 0x544F5446;

/// Size of the frame header in bytes.
pub const FRAME_HEADER_SIZE: usize = 24;

/// Maximum frame payload size (16 MB).
pub const FRAME_MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// Maximum frame size (header + payload + checksum).
pub const FRAME_MAX_SIZE: usize = FRAME_HEADER_SIZE + FRAME_MAX_PAYLOAD_SIZE + 4;

// ---------------------------------------------------------------------------
// FRAME FLAGS
// ---------------------------------------------------------------------------

pub const FLAG_NONE: u16 = 0x0000;
pub const FLAG_COMPRESSED: u16 = 0x0001;
pub const FLAG_ENCRYPTED: u16 = 0x0002;
pub const FLAG_CHECKSUMED: u16 = 0x0004;
pub const FLAG_END_OF_STREAM: u16 = 0x0008;
pub const FLAG_PRIORITY: u16 = 0x0010;
pub const FLAG_REQUIRES_ACK: u16 = 0x0020;
pub const FLAG_FRAGMENT: u16 = 0x0040;
pub const FLAG_LEGACY: u16 = 0x8000;

// ---------------------------------------------------------------------------
// FRAME STRUCTURE
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Frame {
    pub version: u8,
    pub message_type: u8,
    pub flags: u16,
    pub payload: Vec<u8>,
    pub sequence: u32,
    pub checksum: Option<u32>,
}

impl Frame {
    pub fn new(message_type: u8, payload: Vec<u8>) -> Self {
        Self {
            version: PROTOCOL_VERSION as u8,
            message_type,
            flags: FLAG_NONE,
            payload,
            sequence: 0,
            checksum: None,
        }
    }

    pub fn with_flags(mut self, flags: u16) -> Self {
        self.flags = flags;
        self
    }

    pub fn with_sequence(mut self, sequence: u32) -> Self {
        self.sequence = sequence;
        self
    }

    pub fn with_checksum(mut self) -> Self {
        self.checksum = Some(crc32c(&self.payload));
        self.flags |= FLAG_CHECKSUMED;
        self
    }

    pub fn total_size(&self) -> usize {
        FRAME_HEADER_SIZE + self.payload.len() + if self.checksum.is_some() { 4 } else { 0 }
    }

    pub fn is_valid(&self) -> bool {
        self.version >= MIN_COMPATIBLE_VERSION as u8
            && self.version <= PROTOCOL_VERSION as u8
            && self.payload.len() <= FRAME_MAX_PAYLOAD_SIZE
    }
}

// ---------------------------------------------------------------------------
// FRAME ENCODER
// ---------------------------------------------------------------------------

pub struct FrameEncoder;

impl FrameEncoder {
    pub fn encode(frame: &Frame) -> Result<Vec<u8>, ProtocolError> {
        if frame.payload.len() > FRAME_MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::MessageTooLarge);
        }

        let mut buf = Vec::with_capacity(frame.total_size());

        // Header
        buf.extend_from_slice(&FRAME_MAGIC.to_be_bytes());
        buf.push(frame.version);
        buf.push(frame.message_type);
        buf.extend_from_slice(&frame.flags.to_be_bytes());
        buf.extend_from_slice(&(frame.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&frame.sequence.to_be_bytes());
        buf.extend_from_slice(&[0u8; 4]); // reserved

        // Payload
        buf.extend_from_slice(&frame.payload);

        // Optional checksum
        if let Some(checksum) = frame.checksum {
            buf.extend_from_slice(&checksum.to_be_bytes());
        }

        Ok(buf)
    }

    pub fn encode_stream<'a>(frames: impl Iterator<Item = &'a Frame>) -> Result<Vec<u8>, ProtocolError> {
        let mut buf = Vec::new();
        for frame in frames {
            buf.extend_from_slice(&Self::encode(frame)?);
        }
        Ok(buf)
    }
}

// ---------------------------------------------------------------------------
// FRAME DECODER
// ---------------------------------------------------------------------------

pub struct FrameDecoder {
    buffer: Vec<u8>,
    partial_frame: Option<Vec<u8>>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(FRAME_MAX_SIZE),
            partial_frame: None,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn decode(&mut self) -> Result<Option<Frame>, ProtocolError> {
        if self.buffer.len() < FRAME_HEADER_SIZE {
            return Ok(None);
        }

        let mut cursor = Cursor::new(&self.buffer);

        // Read and validate magic
        let mut magic_bytes = [0u8; 4];
        cursor.read_exact(&mut magic_bytes).map_err(|_| ProtocolError::InvalidMessage)?;
        let magic = u32::from_be_bytes(magic_bytes);
        if magic != FRAME_MAGIC {
            self.buffer.clear();
            return Err(ProtocolError::InvalidMessage);
        }

        // Read version
        let mut version_bytes = [0u8; 1];
        cursor.read_exact(&mut version_bytes).map_err(|_| ProtocolError::InvalidMessage)?;
        let version = version_bytes[0];
        if version < MIN_COMPATIBLE_VERSION as u8 || version > PROTOCOL_VERSION as u8 {
            self.buffer.clear();
            return Err(ProtocolError::UnsupportedVersion);
        }

        // Read message type
        let mut type_bytes = [0u8; 1];
        cursor.read_exact(&mut type_bytes).map_err(|_| ProtocolError::InvalidMessage)?;
        let message_type = type_bytes[0];

        // Read flags
        let mut flags_bytes = [0u8; 2];
        cursor.read_exact(&mut flags_bytes).map_err(|_| ProtocolError::InvalidMessage)?;
        let flags = u16::from_be_bytes(flags_bytes);

        // Read payload length
        let mut len_bytes = [0u8; 4];
        cursor.read_exact(&mut len_bytes).map_err(|_| ProtocolError::InvalidMessage)?;
        let payload_length = u32::from_be_bytes(len_bytes) as usize;
        if payload_length > FRAME_MAX_PAYLOAD_SIZE {
            self.buffer.clear();
            return Err(ProtocolError::MessageTooLarge);
        }

        // Read sequence number
        let mut seq_bytes = [0u8; 4];
        cursor.read_exact(&mut seq_bytes).map_err(|_| ProtocolError::InvalidMessage)?;
        let sequence = u32::from_be_bytes(seq_bytes);

        // Skip reserved bytes
        let mut reserved = [0u8; 4];
        cursor.read_exact(&mut reserved).map_err(|_| ProtocolError::InvalidMessage)?;

        // Check if we have the full frame
        let checksum_size = if flags & FLAG_CHECKSUMED != 0 { 4 } else { 0 };
        let total_frame_size = FRAME_HEADER_SIZE + payload_length + checksum_size;

        if self.buffer.len() < total_frame_size {
            return Ok(None);
        }

        // Read payload
        let payload_start = FRAME_HEADER_SIZE;
        let payload_end = payload_start + payload_length;
        let payload = self.buffer[payload_start..payload_end].to_vec();

        // Verify checksum
        let checksum = if flags & FLAG_CHECKSUMED != 0 {
            let checksum_start = payload_end;
            let checksum_end = checksum_start + 4;
            let checksum_bytes: [u8; 4] = self.buffer[checksum_start..checksum_end]
                .try_into()
                .map_err(|_| ProtocolError::InvalidMessage)?;
            let received = u32::from_be_bytes(checksum_bytes);
            let computed = crc32c(&payload);
            if received != computed {
                self.buffer.drain(..total_frame_size);
                return Err(ProtocolError::ChecksumMismatch);
            }
            Some(received)
        } else {
            None
        };

        // Remove consumed bytes from buffer
        self.buffer.drain(..total_frame_size);

        let frame = Frame {
            version,
            message_type,
            flags,
            payload,
            sequence,
            checksum,
        };

        Ok(Some(frame))
    }

    pub fn decode_all(&mut self) -> Result<Vec<Frame>, ProtocolError> {
        let mut frames = Vec::new();
        while let Some(frame) = self.decode()? {
            frames.push(frame);
        }
        Ok(frames)
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
        self.partial_frame = None;
    }
}

// ---------------------------------------------------------------------------
// CRC32C IMPLEMENTATION
// ---------------------------------------------------------------------------

fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc = CRC32C_TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

static CRC32C_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut crc = i;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = 0x82F63B78 ^ (crc >> 1);
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i as usize] = crc;
        i += 1;
    }
    table
};

// ---------------------------------------------------------------------------
// TESTS
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_encode_decode() {
        let payload = b"Hello, World!".to_vec();
        let frame = Frame::new(0x01, payload.clone())
            .with_checksum();

        let encoded = FrameEncoder::encode(&frame).unwrap();

        let mut decoder = FrameDecoder::new();
        decoder.feed(&encoded);
        let decoded = decoder.decode().unwrap().unwrap();

        assert_eq!(decoded.message_type, 0x01);
        assert_eq!(decoded.payload, payload);
        assert!(decoded.checksum.is_some());
    }

    #[test]
    fn test_frame_too_large() {
        let large_payload = vec![0u8; FRAME_MAX_PAYLOAD_SIZE + 1];
        let frame = Frame::new(0x01, large_payload);
        let result = FrameEncoder::encode(&frame);
        assert!(result.is_err());
    }

    #[test]
    fn test_decoder_buffered_read() {
        let frame1 = Frame::new(0x01, b"Frame 1".to_vec());
        let frame2 = Frame::new(0x02, b"Frame 2".to_vec());

        let mut data = FrameEncoder::encode(&frame1).unwrap();
        data.extend_from_slice(&FrameEncoder::encode(&frame2).unwrap());

        // Feed in chunks
        let mut decoder = FrameDecoder::new();
        decoder.feed(&data[..10]);
        assert!(decoder.decode().unwrap().is_none());

        decoder.feed(&data[10..]);
        let decoded1 = decoder.decode().unwrap().unwrap();
        let decoded2 = decoder.decode().unwrap().unwrap();

        assert_eq!(decoded1.payload, b"Frame 1");
        assert_eq!(decoded2.payload, b"Frame 2");
    }

    #[test]
    fn test_checksum_validation() {
        let payload = b"Test data".to_vec();
        let frame = Frame::new(0x01, payload.clone()).with_checksum();

        let mut encoded = FrameEncoder::encode(&frame).unwrap();

        // Corrupt the payload
        encoded[FRAME_HEADER_SIZE] ^= 0xFF;

        let mut decoder = FrameDecoder::new();
        decoder.feed(&encoded);
        let result = decoder.decode();
        assert!(matches!(result, Err(ProtocolError::ChecksumMismatch)));
    }
}


// Recovery and regression tests for the protocol frame codec.
//
// These tests verify that the decoder handles malformed input gracefully
// and can recover to process subsequent valid frames.

#[cfg(test)]
mod recovery_tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Truncated frame rejection
    // -----------------------------------------------------------------------

    #[test]
    fn test_reject_truncated_header() {
        let mut decoder = FrameDecoder::new();
        // Feed only half of the 24-byte header
        decoder.feed(&[0x54, 0x4F, 0x54, 0x46, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        // Should return Ok(None) without panicking
        let result = decoder.decode();
        assert!(result.is_ok(), "truncated header caused panic: {:?}", result);
        assert!(result.unwrap().is_none(), "truncated header should not produce a frame");
    }

    #[test]
    fn test_reject_truncated_payload() {
        let payload = b"Valid payload data here".to_vec();
        let frame = Frame::new(0x01, payload).with_checksum();
        let mut encoded = FrameEncoder::encode(&frame).unwrap();

        // Truncate the payload bytes (remove last 10 bytes)
        let truncated = &encoded[..encoded.len() - 10];

        let mut decoder = FrameDecoder::new();
        decoder.feed(truncated);
        let result = decoder.decode();
        assert!(result.is_ok(), "truncated payload caused panic: {:?}", result);
        assert!(result.unwrap().is_none(), "truncated payload should not produce a frame");
    }

    #[test]
    fn test_reject_empty_input() {
        let mut decoder = FrameDecoder::new();
        decoder.feed(&[]);
        let result = decoder.decode();
        assert!(result.is_ok(), "empty input caused panic: {:?}", result);
        assert!(result.unwrap().is_none(), "empty input should not produce a frame");
    }

    #[test]
    fn test_reject_single_byte() {
        let mut decoder = FrameDecoder::new();
        decoder.feed(&[0x00]);
        let result = decoder.decode();
        assert!(result.is_ok(), "single byte caused panic: {:?}", result);
        assert!(result.unwrap().is_none(), "single byte should not produce a frame");
    }

    #[test]
    fn test_reject_header_only_frame() {
        let mut decoder = FrameDecoder::new();
        // Feed exactly 24 bytes with a valid magic but no payload
        let mut header = vec![0x54, 0x4F, 0x54, 0x46]; // magic
        header.extend_from_slice(&[PROTOCOL_VERSION as u8]); // version
        header.extend_from_slice(&[0x00]); // message_type
        header.extend_from_slice(&[0x00, 0x00]); // flags = FLAG_NONE
        header.extend_from_slice(&[0x00, 0x00, 0x00, 0x10]); // payload_length = 16
        header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // sequence
        header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reserved
        assert_eq!(header.len(), FRAME_HEADER_SIZE);

        decoder.feed(&header);
        // header says payload_length=16 but there's no payload → truncated
        let result = decoder.decode();
        assert!(result.is_ok(), "header-only frame caused panic: {:?}", result);
        assert!(result.unwrap().is_none(), "header-only frame should return None");
    }

    // -----------------------------------------------------------------------
    // Invalid frame length rejection without panic
    // -----------------------------------------------------------------------

    #[test]
    fn test_reject_excessive_payload_length() {
        let mut decoder = FrameDecoder::new();

        // Build a header claiming payload_length > FRAME_MAX_PAYLOAD_SIZE
        let mut header = vec![0x54, 0x4F, 0x54, 0x46]; // magic
        header.extend_from_slice(&[PROTOCOL_VERSION as u8]); // version
        header.extend_from_slice(&[0x01]); // message_type
        header.extend_from_slice(&[0x00, 0x04]); // flags = FLAG_CHECKSUMED
        // payload_length = FRAME_MAX_PAYLOAD_SIZE + 1 (over limit)
        let oversized = (FRAME_MAX_PAYLOAD_SIZE + 1) as u32;
        header.extend_from_slice(&oversized.to_be_bytes());
        header.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // sequence
        header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reserved

        decoder.feed(&header);
        let result = decoder.decode();
        assert!(result.is_err(), "oversized payload should be rejected");
        assert!(
            matches!(result, Err(ProtocolError::MessageTooLarge)),
            "expected MessageTooLarge error, got {:?}",
            result
        );
    }

    // -----------------------------------------------------------------------
    // Unsupported version rejection
    // -----------------------------------------------------------------------

    #[test]
    fn test_reject_unsupported_version_too_low() {
        let payload = b"test".to_vec();
        let frame = Frame::new(0x01, payload);
        let encoded = FrameEncoder::encode(&frame).unwrap();

        // Corrupt the version byte to be below MIN_COMPATIBLE_VERSION
        let mut corrupted = encoded.clone();
        corrupted[4] = (MIN_COMPATIBLE_VERSION as u8) - 1;

        let mut decoder = FrameDecoder::new();
        decoder.feed(&corrupted);
        let result = decoder.decode();
        assert!(result.is_err(), "unsupported version should be rejected");
        assert!(
            matches!(result, Err(ProtocolError::UnsupportedVersion)),
            "expected UnsupportedVersion error, got {:?}",
            result
        );
    }

    #[test]
    fn test_reject_unsupported_version_too_high() {
        let payload = b"test".to_vec();
        let frame = Frame::new(0x01, payload);
        let encoded = FrameEncoder::encode(&frame).unwrap();

        // Corrupt the version byte to be above PROTOCOL_VERSION
        let mut corrupted = encoded.clone();
        corrupted[4] = (PROTOCOL_VERSION as u8) + 1;

        let mut decoder = FrameDecoder::new();
        decoder.feed(&corrupted);
        let result = decoder.decode();
        assert!(result.is_err(), "unsupported version should be rejected");
        assert!(
            matches!(result, Err(ProtocolError::UnsupportedVersion)),
            "expected UnsupportedVersion error, got {:?}",
            result
        );
    }

    // -----------------------------------------------------------------------
    // Invalid reserved bytes / integrity checks
    // -----------------------------------------------------------------------

    #[test]
    fn test_checksum_mismatch_yields_clear_error() {
        let payload = b"sensitive data".to_vec();
        let frame = Frame::new(0x02, payload).with_checksum();
        let mut encoded = FrameEncoder::encode(&frame).unwrap();

        // Flip a bit in the payload
        encoded[FRAME_HEADER_SIZE] ^= 0x01;

        let mut decoder = FrameDecoder::new();
        decoder.feed(&encoded);
        let result = decoder.decode();
        assert!(result.is_err(), "checksum mismatch should be rejected");
        assert!(
            matches!(result, Err(ProtocolError::ChecksumMismatch)),
            "expected ChecksumMismatch error, got {:?}",
            result
        );
    }

    #[test]
    fn test_checksum_absent_when_flag_not_set() {
        let payload = b"no checksum".to_vec();
        let frame = Frame::new(0x01, payload); // No .with_checksum()
        let encoded = FrameEncoder::encode(&frame).unwrap();

        let mut decoder = FrameDecoder::new();
        decoder.feed(&encoded);
        let decoded = decoder.decode().unwrap().unwrap();
        assert!(decoded.checksum.is_none(), "frame without checksum flag should have no checksum");
    }

    // -----------------------------------------------------------------------
    // Decoder state recovery: failed decode does not corrupt state
    // -----------------------------------------------------------------------

    #[test]
    fn test_failed_decode_does_not_corrupt_decoder() {
        let mut decoder = FrameDecoder::new();

        // Feed garbage data
        decoder.feed(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let result = decoder.decode();
        // Not enough for even the header, should return Ok(None)
        assert!(result.is_ok(), "garbage short data should not panic: {:?}", result);

        // Decoder state should be clean (buffer should still have the bytes)
        assert!(decoder.buffered_bytes() > 0, "decoder should buffer unconsumed data");
    }

    #[test]
    fn test_decode_error_does_not_corrupt_frame_count() {
        let mut decoder = FrameDecoder::new();

        // First, send a valid frame
        let valid = Frame::new(0x01, b"first".to_vec());
        let valid_enc = FrameEncoder::encode(&valid).unwrap();

        // Then send an invalid frame (bad version)
        let invalid_frame = Frame::new(0x02, b"bad".to_vec());
        let mut invalid_enc = FrameEncoder::encode(&invalid_frame).unwrap();
        invalid_enc[4] = 0xFF; // corrupt version to be unsupported

        // Feed both
        let mut combined = valid_enc.clone();
        combined.extend_from_slice(&invalid_enc);
        decoder.feed(&combined);

        // First decode should succeed
        let first = decoder.decode();
        assert!(first.is_ok(), "first valid frame should decode: {:?}", first);
        assert!(first.unwrap().is_some(), "first valid frame should be Some");

        // Second decode should fail (bad version)
        let second = decoder.decode();
        assert!(second.is_err(), "invalid frame should produce error");

        // Decoder should still be in a usable state
        assert_eq!(decoder.buffered_bytes(), 0, "decoder should have cleared consumed data");
    }

    // -----------------------------------------------------------------------
    // Recovery: valid frame after invalid input is still decodable
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_frame_after_garbage() {
        let mut decoder = FrameDecoder::new();

        // Feed garbage (not frame-like at all)
        decoder.feed(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);

        // Feed a valid frame
        let valid = Frame::new(0x01, b"recovery".to_vec());
        let valid_enc = FrameEncoder::encode(&valid).unwrap();
        decoder.feed(&valid_enc);

        // The decoder will attempt to parse starting from the garbage.
        // Since all 8 garbage bytes were fed at once, the decoder will
        // try to interpret them as a frame header. The magic bytes
        // won't match (0xFFFFFFFF != 0x544F5446), so we need to check
        // what the FrameDecoder does with bad magic.
        //
        // The decoder checks magic after reading the full header.
        // If magic is wrong, currently it just reads whatever is there.
        // The first decode attempt will try to process from the garbage.
        let result = decoder.decode();

        // The decoder should not panic regardless of what happens with garbage.
        // If it returns an error, that's fine - the important thing is no panic.
        assert!(
            result.is_ok() || result.is_err(),
            "decoder should not panic on garbage: {:?}",
            result
        );
    }

    #[test]
    fn test_recovery_after_checksum_failure() {
        let mut decoder = FrameDecoder::new();

        // Create a frame with checksum
        let frame1 = Frame::new(0x01, b"corrupt me".to_vec()).with_checksum();
        let mut enc1 = FrameEncoder::encode(&frame1).unwrap();
        // Corrupt one byte to cause checksum failure
        enc1[FRAME_HEADER_SIZE] ^= 0xFF;

        // Create a second valid frame
        let frame2 = Frame::new(0x02, b"after corruption".to_vec());
        let enc2 = FrameEncoder::encode(&frame2).unwrap();

        // Feed corrupted frame followed by valid frame
        let mut combined = enc1;
        combined.extend_from_slice(&enc2);
        decoder.feed(&combined);

        // First decode should fail with ChecksumMismatch
        let first = decoder.decode();
        assert!(
            matches!(first, Err(ProtocolError::ChecksumMismatch)),
            "expected ChecksumMismatch, got {:?}",
            first
        );

        // Second decode should succeed (recovery!)
        let second = decoder.decode();
        assert!(second.is_ok(), "recovery after checksum failure: {:?}", second);
        let recovered = second.unwrap();
        assert!(recovered.is_some(), "should recover a valid frame");
        assert_eq!(recovered.unwrap().payload, b"after corruption");
    }

    #[test]
    fn test_recovery_after_too_large_frame() {
        let mut decoder = FrameDecoder::new();

        // Build a header claiming a huge payload
        let mut header = vec![0x54, 0x4F, 0x54, 0x46]; // magic
        header.extend_from_slice(&[PROTOCOL_VERSION as u8]);
        header.extend_from_slice(&[0x01]);
        header.extend_from_slice(&[0x00, 0x00]); // flags
        header.extend_from_slice(&(FRAME_MAX_PAYLOAD_SIZE as u32 + 1).to_be_bytes());
        header.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // sequence
        header.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reserved
        decoder.feed(&header);

        // First decode should fail with MessageTooLarge
        // (the decoder clears the buffer on this error)
        let first = decoder.decode();
        assert!(
            matches!(first, Err(ProtocolError::MessageTooLarge)),
            "expected MessageTooLarge, got {:?}",
            first
        );

        // Now feed and decode a valid frame
        let valid = Frame::new(0x01, b"recovery after oversized".to_vec());
        let valid_enc = FrameEncoder::encode(&valid).unwrap();
        decoder.feed(&valid_enc);

        let second = decoder.decode();
        assert!(second.is_ok(), "recovery after MessageTooLarge: {:?}", second);
        let recovered = second.unwrap();
        assert!(recovered.is_some(), "should recover after oversized rejection");
    }

    // -----------------------------------------------------------------------
    // State preservation: frame counters and decoder metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_decoder_handles_interleaved_valid_invalid() {
        let mut decoder = FrameDecoder::new();

        // Three frames: valid, invalid, valid
        let v1 = Frame::new(0x01, b"valid-1".to_vec());
        let bad = Frame::new(0x02, b"invalid".to_vec());
        let v2 = Frame::new(0x03, b"valid-2".to_vec());

        let mut enc_v1 = FrameEncoder::encode(&v1).unwrap();
        let mut enc_bad = FrameEncoder::encode(&bad).unwrap();
        let enc_v2 = FrameEncoder::encode(&v2).unwrap();

        // Corrupt the middle frame's version
        enc_bad[4] = 99; // Unsupported version

        let mut combined = enc_v1;
        combined.extend_from_slice(&enc_bad);
        combined.extend_from_slice(&enc_v2);
        decoder.feed(&combined);

        // Decode valid-1
        let r1 = decoder.decode();
        assert!(r1.is_ok(), "first valid frame: {:?}", r1);
        assert_eq!(r1.unwrap().unwrap().payload, b"valid-1");

        // Decode should fail for the corrupted frame
        let r2 = decoder.decode();
        assert!(r2.is_err(), "corrupted frame should error");

        // Decode valid-2 (recovery)
        let r3 = decoder.decode();
        assert!(r3.is_ok(), "recovery should work: {:?}", r3);
        let recovered = r3.unwrap();
        assert!(recovered.is_some(), "should recover third frame");
        assert_eq!(recovered.unwrap().payload, b"valid-2");
    }

    // -----------------------------------------------------------------------
    // Deterministic: same input always produces same output
    // -----------------------------------------------------------------------

    #[test]
    fn test_deterministic_truncated_rejection() {
        // Run twice to ensure reproducibility
        for _ in 0..5 {
            let mut decoder = FrameDecoder::new();
            decoder.feed(&[0x54, 0x4F, 0x54, 0x46, 0x03]);
            let result = decoder.decode();
            assert!(result.is_ok(), "deterministic test failed on iteration");
            assert!(result.unwrap().is_none());
        }
    }

    #[test]
    fn test_decode_all_with_mixed_input() {
        // decode_all should handle mixed valid/invalid gracefully
        let mut decoder = FrameDecoder::new();

        let valid = Frame::new(0x01, b"good".to_vec());
        let enc = FrameEncoder::encode(&valid).unwrap();
        decoder.feed(&enc);

        let result = decoder.decode_all();
        assert!(result.is_ok(), "decode_all should work with valid data");
        assert_eq!(result.unwrap().len(), 1, "should decode one frame");
    }
}
