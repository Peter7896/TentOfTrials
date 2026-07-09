// Wire format encoding and decoding for the Tent of Trials protocol.
//
// This module implements the binary encoding and decoding of protocol messages
// for transmission over network connections. It supports multiple encoding
// formats and handles framing, checksums, and optional encryption.
//
// The wire format consists of:
//   1. Frame header (20 bytes) - magic, version, type, flags, length, sequence
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
pub const FRAME_HEADER_SIZE: usize = 20;

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

    fn discard_through_next_magic(&mut self, start_at: usize) {
        let next_magic = self.buffer[start_at..]
            .windows(4)
            .position(|window| window == FRAME_MAGIC.to_be_bytes())
            .map(|position| start_at + position);

        match next_magic {
            Some(index) => {
                self.buffer.drain(..index);
            }
            None => {
                self.buffer.clear();
            }
        }
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
            self.discard_through_next_magic(1);
            return Err(ProtocolError::InvalidMessage);
        }

        // Read version
        let mut version_bytes = [0u8; 1];
        cursor.read_exact(&mut version_bytes).map_err(|_| ProtocolError::InvalidMessage)?;
        let version = version_bytes[0];
        if version < MIN_COMPATIBLE_VERSION as u8 || version > PROTOCOL_VERSION as u8 {
            self.discard_through_next_magic(4);
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
            self.discard_through_next_magic(FRAME_HEADER_SIZE);
            return Err(ProtocolError::MessageTooLarge);
        }

        // Read sequence number
        let mut seq_bytes = [0u8; 4];
        cursor.read_exact(&mut seq_bytes).map_err(|_| ProtocolError::InvalidMessage)?;
        let sequence = u32::from_be_bytes(seq_bytes);

        // Skip reserved bytes
        let mut reserved = [0u8; 4];
        cursor.read_exact(&mut reserved).map_err(|_| ProtocolError::InvalidMessage)?;
        if reserved != [0u8; 4] {
            self.discard_through_next_magic(FRAME_HEADER_SIZE);
            return Err(ProtocolError::InvalidMessage);
        }

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

    #[test]
    fn test_decoder_rejects_truncated_header_without_panicking() {
        let mut decoder = FrameDecoder::new();
        decoder.feed(&FRAME_MAGIC.to_be_bytes()[..2]);

        assert!(decoder.decode().unwrap().is_none());
        assert_eq!(decoder.buffered_bytes(), 2);
    }

    #[test]
    fn test_decoder_rejects_truncated_payload_and_recovers_when_completed() {
        let frame = Frame::new(0x01, b"complete me".to_vec());
        let encoded = FrameEncoder::encode(&frame).unwrap();
        let split_at = FRAME_HEADER_SIZE + 3;

        let mut decoder = FrameDecoder::new();
        decoder.feed(&encoded[..split_at]);
        assert!(decoder.decode().unwrap().is_none());
        assert_eq!(decoder.buffered_bytes(), split_at);

        decoder.feed(&encoded[split_at..]);
        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(decoded.payload, b"complete me");
        assert_eq!(decoder.buffered_bytes(), 0);
    }

    #[test]
    fn test_decoder_rejects_invalid_reserved_bytes_and_recovers() {
        let invalid = Frame::new(0x01, b"bad reserved".to_vec());
        let mut invalid_encoded = FrameEncoder::encode(&invalid).unwrap();
        invalid_encoded[FRAME_HEADER_SIZE - 1] = 0x01;

        let valid = Frame::new(0x02, b"valid after reserved".to_vec());
        let valid_encoded = FrameEncoder::encode(&valid).unwrap();
        invalid_encoded.extend_from_slice(&valid_encoded);

        let mut decoder = FrameDecoder::new();
        decoder.feed(&invalid_encoded);

        assert!(matches!(decoder.decode(), Err(ProtocolError::InvalidMessage)));
        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(decoded.message_type, 0x02);
        assert_eq!(decoded.payload, b"valid after reserved");
    }

    #[test]
    fn test_decoder_rejects_checksum_mismatch_and_recovers() {
        let invalid = Frame::new(0x01, b"bad checksum".to_vec()).with_checksum();
        let mut invalid_encoded = FrameEncoder::encode(&invalid).unwrap();
        invalid_encoded[FRAME_HEADER_SIZE] ^= 0xFF;

        let valid = Frame::new(0x02, b"valid after checksum".to_vec());
        let valid_encoded = FrameEncoder::encode(&valid).unwrap();
        invalid_encoded.extend_from_slice(&valid_encoded);

        let mut decoder = FrameDecoder::new();
        decoder.feed(&invalid_encoded);

        assert!(matches!(decoder.decode(), Err(ProtocolError::ChecksumMismatch)));
        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(decoded.message_type, 0x02);
        assert_eq!(decoded.payload, b"valid after checksum");
    }

    #[test]
    fn test_decoder_rejects_invalid_magic_and_recovers() {
        let valid = Frame::new(0x02, b"valid after junk".to_vec());
        let valid_encoded = FrameEncoder::encode(&valid).unwrap();

        let mut stream = b"not-a-frame".to_vec();
        stream.extend_from_slice(&valid_encoded);

        let mut decoder = FrameDecoder::new();
        decoder.feed(&stream);

        assert!(matches!(decoder.decode(), Err(ProtocolError::InvalidMessage)));
        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(decoded.message_type, 0x02);
        assert_eq!(decoded.payload, b"valid after junk");
    }

    #[test]
    fn test_decoder_rejects_oversized_length_and_recovers() {
        let mut invalid = Vec::new();
        invalid.extend_from_slice(&FRAME_MAGIC.to_be_bytes());
        invalid.push(PROTOCOL_VERSION as u8);
        invalid.push(0x01);
        invalid.extend_from_slice(&FLAG_NONE.to_be_bytes());
        invalid.extend_from_slice(&((FRAME_MAX_PAYLOAD_SIZE as u32) + 1).to_be_bytes());
        invalid.extend_from_slice(&1u32.to_be_bytes());
        invalid.extend_from_slice(&[0u8; 4]);

        let valid = Frame::new(0x02, b"valid after oversized".to_vec());
        let valid_encoded = FrameEncoder::encode(&valid).unwrap();
        invalid.extend_from_slice(&valid_encoded);

        let mut decoder = FrameDecoder::new();
        decoder.feed(&invalid);

        assert!(matches!(decoder.decode(), Err(ProtocolError::MessageTooLarge)));
        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(decoded.message_type, 0x02);
        assert_eq!(decoded.payload, b"valid after oversized");
    }
}
