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

use crate::protocol::{ProtocolError, MIN_COMPATIBLE_VERSION, PROTOCOL_VERSION};
use std::io::{Cursor, Read};

// ---------------------------------------------------------------------------
// FRAME CONSTANTS
// ---------------------------------------------------------------------------

/// Magic number for frame identification ("TOTF" in ASCII).
pub const FRAME_MAGIC: u32 = 0x544F5446;

/// Size of the frame header in bytes.
pub const FRAME_HEADER_SIZE: usize = 24;

/// Size of the reserved header field in bytes.
const FRAME_RESERVED_SIZE: usize = 8;

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
        buf.extend_from_slice(&[0u8; FRAME_RESERVED_SIZE]); // reserved

        // Payload
        buf.extend_from_slice(&frame.payload);

        // Optional checksum
        if let Some(checksum) = frame.checksum {
            buf.extend_from_slice(&checksum.to_be_bytes());
        }

        Ok(buf)
    }

    pub fn encode_stream<'a>(
        frames: impl Iterator<Item = &'a Frame>,
    ) -> Result<Vec<u8>, ProtocolError> {
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
    accepted_frames: u64,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(FRAME_MAX_SIZE),
            partial_frame: None,
            accepted_frames: 0,
        }
    }

    pub fn accepted_frames(&self) -> u64 {
        self.accepted_frames
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn discard_until_next_magic(&mut self) {
        let magic = FRAME_MAGIC.to_be_bytes();
        if let Some(pos) = self
            .buffer
            .windows(magic.len())
            .enumerate()
            .skip(1)
            .find_map(|(idx, window)| (window == magic).then_some(idx))
        {
            self.buffer.drain(..pos);
        } else {
            self.buffer.clear();
        }
    }

    pub fn decode(&mut self) -> Result<Option<Frame>, ProtocolError> {
        if self.buffer.len() < FRAME_HEADER_SIZE {
            return Ok(None);
        }

        let mut cursor = Cursor::new(&self.buffer);

        // Read and validate magic
        let mut magic_bytes = [0u8; 4];
        cursor
            .read_exact(&mut magic_bytes)
            .map_err(|_| ProtocolError::InvalidMessage)?;
        let magic = u32::from_be_bytes(magic_bytes);
        if magic != FRAME_MAGIC {
            self.discard_until_next_magic();
            return Err(ProtocolError::InvalidMessage);
        }

        // Read version
        let mut version_bytes = [0u8; 1];
        cursor
            .read_exact(&mut version_bytes)
            .map_err(|_| ProtocolError::InvalidMessage)?;
        let version = version_bytes[0];
        if version < MIN_COMPATIBLE_VERSION as u8 || version > PROTOCOL_VERSION as u8 {
            self.discard_until_next_magic();
            return Err(ProtocolError::UnsupportedVersion);
        }

        // Read message type
        let mut type_bytes = [0u8; 1];
        cursor
            .read_exact(&mut type_bytes)
            .map_err(|_| ProtocolError::InvalidMessage)?;
        let message_type = type_bytes[0];

        // Read flags
        let mut flags_bytes = [0u8; 2];
        cursor
            .read_exact(&mut flags_bytes)
            .map_err(|_| ProtocolError::InvalidMessage)?;
        let flags = u16::from_be_bytes(flags_bytes);

        // Read payload length
        let mut len_bytes = [0u8; 4];
        cursor
            .read_exact(&mut len_bytes)
            .map_err(|_| ProtocolError::InvalidMessage)?;
        let payload_length = u32::from_be_bytes(len_bytes) as usize;
        if payload_length > FRAME_MAX_PAYLOAD_SIZE {
            self.discard_until_next_magic();
            return Err(ProtocolError::MessageTooLarge);
        }

        // Read sequence number
        let mut seq_bytes = [0u8; 4];
        cursor
            .read_exact(&mut seq_bytes)
            .map_err(|_| ProtocolError::InvalidMessage)?;
        let sequence = u32::from_be_bytes(seq_bytes);

        // Skip reserved bytes
        let mut reserved = [0u8; FRAME_RESERVED_SIZE];
        cursor
            .read_exact(&mut reserved)
            .map_err(|_| ProtocolError::InvalidMessage)?;

        // Check if we have the full frame
        let checksum_size = if flags & FLAG_CHECKSUMED != 0 { 4 } else { 0 };
        let total_frame_size = FRAME_HEADER_SIZE + payload_length + checksum_size;

        if reserved != [0u8; FRAME_RESERVED_SIZE] {
            if self.buffer.len() >= total_frame_size {
                self.buffer.drain(..total_frame_size);
            } else {
                self.buffer.clear();
            }
            return Err(ProtocolError::InvalidMessage);
        }

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
        self.accepted_frames += 1;

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
        let frame = Frame::new(0x01, payload.clone()).with_checksum();

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
    fn test_truncated_header_and_payload_do_not_decode_or_corrupt_buffer() {
        let frame = Frame::new(0x01, b"payload".to_vec()).with_checksum();
        let encoded = FrameEncoder::encode(&frame).unwrap();

        for cut in [0, 1, FRAME_HEADER_SIZE - 1] {
            let mut decoder = FrameDecoder::new();
            decoder.feed(&encoded[..cut]);

            assert!(decoder.decode().unwrap().is_none());
            assert_eq!(decoder.buffered_bytes(), cut);
        }

        let payload_cut = FRAME_HEADER_SIZE + frame.payload.len() - 1;
        let mut decoder = FrameDecoder::new();
        decoder.feed(&encoded[..payload_cut]);

        assert!(decoder.decode().unwrap().is_none());
        assert_eq!(decoder.buffered_bytes(), payload_cut);
    }

    #[test]
    fn test_invalid_payload_length_is_rejected_without_panic() {
        let mut encoded = FrameEncoder::encode(&Frame::new(0x01, Vec::new())).unwrap();
        encoded[8..12].copy_from_slice(&((FRAME_MAX_PAYLOAD_SIZE as u32) + 1).to_be_bytes());

        let mut decoder = FrameDecoder::new();
        decoder.feed(&encoded);

        assert!(matches!(
            decoder.decode(),
            Err(ProtocolError::MessageTooLarge)
        ));
        assert_eq!(decoder.buffered_bytes(), 0);

        let valid = Frame::new(0x02, b"valid after invalid length".to_vec()).with_sequence(7);
        let valid_encoded = FrameEncoder::encode(&valid).unwrap();
        decoder.feed(&valid_encoded);

        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(decoded.sequence, 7);
        assert_eq!(decoded.payload, b"valid after invalid length");
        assert_eq!(decoder.buffered_bytes(), 0);
    }

    #[test]
    fn test_invalid_reserved_bytes_are_rejected_and_next_frame_decodes() {
        let mut invalid = FrameEncoder::encode(&Frame::new(0x01, Vec::new())).unwrap();
        invalid[16] = 0x80;

        let valid = Frame::new(0x02, b"after reserved".to_vec()).with_sequence(42);
        let valid_encoded = FrameEncoder::encode(&valid).unwrap();

        let mut decoder = FrameDecoder::new();
        decoder.feed(&invalid);
        decoder.feed(&valid_encoded);

        assert!(matches!(
            decoder.decode(),
            Err(ProtocolError::InvalidMessage)
        ));
        assert_eq!(decoder.buffered_bytes(), valid_encoded.len());

        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(decoded.message_type, 0x02);
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.payload, b"after reserved");
        assert_eq!(decoder.buffered_bytes(), 0);
    }

    #[test]
    fn test_checksum_mismatch_preserves_following_valid_frame() {
        let mut invalid =
            FrameEncoder::encode(&Frame::new(0x01, b"bad checksum".to_vec()).with_checksum())
                .unwrap();
        invalid[FRAME_HEADER_SIZE] ^= 0x01;

        let valid = Frame::new(0x03, b"after checksum".to_vec()).with_sequence(99);
        let valid_encoded = FrameEncoder::encode(&valid).unwrap();

        let mut decoder = FrameDecoder::new();
        decoder.feed(&invalid);
        decoder.feed(&valid_encoded);

        assert!(matches!(
            decoder.decode(),
            Err(ProtocolError::ChecksumMismatch)
        ));
        assert_eq!(decoder.buffered_bytes(), valid_encoded.len());

        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(decoded.message_type, 0x03);
        assert_eq!(decoded.sequence, 99);
        assert_eq!(decoded.payload, b"after checksum");
        assert_eq!(decoder.buffered_bytes(), 0);
    }
}
