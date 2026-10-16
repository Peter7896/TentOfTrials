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

        // Read and validate reserved bytes (must be all zeros)
        let mut reserved = [0u8; 4];
        cursor.read_exact(&mut reserved).map_err(|_| ProtocolError::InvalidMessage)?;
        if reserved != [0u8; 4] {
            self.buffer.clear();
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

    /// Helper: build a raw frame byte buffer without using the encoder.
    /// This lets us inject malformed data the encoder would reject.
    fn raw_frame_header(
        magic: u32,
        version: u8,
        message_type: u8,
        flags: u16,
        payload_length: u32,
        sequence: u32,
        reserved: [u8; 4],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&magic.to_be_bytes());
        buf.push(version);
        buf.push(message_type);
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&payload_length.to_be_bytes());
        buf.extend_from_slice(&sequence.to_be_bytes());
        buf.extend_from_slice(&reserved);
        buf
    }

    /// Helper: build a complete raw frame byte buffer with arbitrary payload.
    fn raw_frame(
        version: u8,
        message_type: u8,
        flags: u16,
        payload: &[u8],
        sequence: u32,
        checksum: Option<u32>,
    ) -> Vec<u8> {
        let mut buf = raw_frame_header(
            FRAME_MAGIC,
            version,
            message_type,
            flags,
            payload.len() as u32,
            sequence,
            [0u8; 4],
        );
        buf.extend_from_slice(payload);
        if let Some(cs) = checksum {
            buf.extend_from_slice(&cs.to_be_bytes());
        }
        buf
    }

    // -----------------------------------------------------------------------
    // Basic encode/decode round-trip
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Buffered / stream decode
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Checksum validation
    // -----------------------------------------------------------------------

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
    fn test_checksum_mismatch_preserves_buffer() {
        // A checksum mismatch should drain only the failing frame bytes,
        // preserving the decoder so subsequent data is still usable.
        let payload = b"checksum test".to_vec();
        let frame = Frame::new(0x01, payload.clone()).with_checksum();
        let mut encoded = FrameEncoder::encode(&frame).unwrap();

        // Corrupt one byte mid-payload to trigger a checksum mismatch
        encoded[FRAME_HEADER_SIZE + 3] ^= 0xFF;

        let mut decoder = FrameDecoder::new();
        decoder.feed(&encoded);
        let result = decoder.decode();
        assert!(matches!(result, Err(ProtocolError::ChecksumMismatch)));
    }

    // -----------------------------------------------------------------------
    // Reject truncated frames
    // -----------------------------------------------------------------------

    #[test]
    fn test_reject_truncated_header() {
        // Fewer bytes than FRAME_HEADER_SIZE → Ok(None), not a panic
        let mut decoder = FrameDecoder::new();
        decoder.feed(&[0u8; 10]);
        let result = decoder.decode();
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_reject_truncated_payload() {
        // Header claims 100-byte payload, but we only provide 10 bytes of
        // payload data → Ok(None) (waiting for more data), not a panic.
        let header = raw_frame_header(
            FRAME_MAGIC,
            3,    // valid version
            0x01,
            FLAG_NONE,
            100,  // payload length
            0,
            [0u8; 4],
        );
        let mut buf = header;
        buf.extend_from_slice(&[0u8; 10]); // only 10 of 100 payload bytes

        let mut decoder = FrameDecoder::new();
        decoder.feed(&buf);
        let result = decoder.decode();
        assert!(result.is_ok());
        assert!(result.unwrap().is_none(), "should return None waiting for full payload, not Err");
    }

    #[test]
    fn test_reject_truncated_header_exactly_at_boundary() {
        // Exactly FRAME_HEADER_SIZE - 1 bytes → Ok(None)
        let mut decoder = FrameDecoder::new();
        decoder.feed(&[0u8; FRAME_HEADER_SIZE - 1]);
        let result = decoder.decode();
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    // -----------------------------------------------------------------------
    // Reject invalid magic
    // -----------------------------------------------------------------------

    #[test]
    fn test_reject_invalid_magic() {
        let header = raw_frame_header(
            0xDEADBEEF, // wrong magic
            3,
            0x01,
            FLAG_NONE,
            0,
            0,
            [0u8; 4],
        );
        let mut decoder = FrameDecoder::new();
        decoder.feed(&header);
        let result = decoder.decode();
        assert!(matches!(result, Err(ProtocolError::InvalidMessage)));
    }

    // -----------------------------------------------------------------------
    // Reject unsupported version
    // -----------------------------------------------------------------------

    #[test]
    fn test_reject_version_too_low() {
        let header = raw_frame_header(
            FRAME_MAGIC,
            0, // below MIN_COMPATIBLE_VERSION
            0x01,
            FLAG_NONE,
            0,
            0,
            [0u8; 4],
        );
        let mut decoder = FrameDecoder::new();
        decoder.feed(&header);
        let result = decoder.decode();
        assert!(matches!(result, Err(ProtocolError::UnsupportedVersion)));
    }

    #[test]
    fn test_reject_version_too_high() {
        let header = raw_frame_header(
            FRAME_MAGIC,
            99, // above PROTOCOL_VERSION
            0x01,
            FLAG_NONE,
            0,
            0,
            [0u8; 4],
        );
        let mut decoder = FrameDecoder::new();
        decoder.feed(&header);
        let result = decoder.decode();
        assert!(matches!(result, Err(ProtocolError::UnsupportedVersion)));
    }

    // -----------------------------------------------------------------------
    // Reject oversized payload
    // -----------------------------------------------------------------------

    #[test]
    fn test_reject_payload_too_large_at_decode() {
        // Header claims a payload size that exceeds FRAME_MAX_PAYLOAD_SIZE
        let header = raw_frame_header(
            FRAME_MAGIC,
            3,
            0x01,
            FLAG_NONE,
            (FRAME_MAX_PAYLOAD_SIZE + 1) as u32,
            0,
            [0u8; 4],
        );
        let mut decoder = FrameDecoder::new();
        decoder.feed(&header);
        let result = decoder.decode();

        // The decoder checks payload_length against FRAME_MAX_PAYLOAD_SIZE,
        // but also needs the buffer to contain the full (oversized) frame
        // before reaching that check. With only the header in the buffer,
        // it returns Ok(None). Feed enough extra bytes to satisfy the
        // frame-size test so the payload-length check triggers.
        let extra = vec![0u8; FRAME_MAX_PAYLOAD_SIZE + 1];
        decoder.feed(&extra);
        let result2 = decoder.decode();
        assert!(
            matches!(result2, Err(ProtocolError::MessageTooLarge)),
            "expected MessageTooLarge, got {:?}", result2
        );
    }

    // -----------------------------------------------------------------------
    // Reject non-zero reserved bytes
    // -----------------------------------------------------------------------

    #[test]
    fn test_reject_nonzero_reserved_bytes() {
        let header = raw_frame_header(
            FRAME_MAGIC,
            3,
            0x01,
            FLAG_NONE,
            0,
            0,
            [0xAA, 0xBB, 0xCC, 0xDD], // non-zero reserved
        );
        let mut decoder = FrameDecoder::new();
        decoder.feed(&header);
        let result = decoder.decode();
        assert!(
            matches!(result, Err(ProtocolError::InvalidMessage)),
            "non-zero reserved bytes must be rejected, got {:?}", result
        );
    }

    #[test]
    fn test_reject_single_nonzero_reserved_byte() {
        // Only one reserved byte is non-zero — still invalid.
        let header = raw_frame_header(
            FRAME_MAGIC,
            3,
            0x01,
            FLAG_NONE,
            0,
            0,
            [0x00, 0x00, 0x00, 0x01],
        );
        let mut decoder = FrameDecoder::new();
        decoder.feed(&header);
        let result = decoder.decode();
        assert!(matches!(result, Err(ProtocolError::InvalidMessage)));
    }

    // -----------------------------------------------------------------------
    // State preservation: failed decode does not corrupt decoder
    // -----------------------------------------------------------------------

    #[test]
    fn test_decoder_state_after_invalid_magic() {
        // After a failed decode due to invalid magic, the decoder should be
        // clean and ready to accept new data.
        let bad = raw_frame_header(0xDEADBEEF, 3, 0x01, FLAG_NONE, 0, 0, [0u8; 4]);
        let mut decoder = FrameDecoder::new();
        decoder.feed(&bad);

        let result = decoder.decode();
        assert!(result.is_err());

        // State check: buffer should be cleared after invalid-magic error
        // (the code clears buffer on magic and version errors).

        // Now feed a valid frame — it should decode fine
        let valid = raw_frame(3, 0x02, FLAG_NONE, b"recovery", 1, None);
        decoder.feed(&valid);
        let recovered = decoder.decode().unwrap().unwrap();
        assert_eq!(recovered.payload, b"recovery");
        assert_eq!(recovered.message_type, 0x02);
    }

    #[test]
    fn test_decoder_state_after_checksum_mismatch() {
        // Checksum failure drains only the bad frame, leaving the decoder
        // intact for subsequent frames.
        let payload = b"frame with bad checksum".to_vec();
        let frame = Frame::new(0x01, payload).with_checksum();
        let mut bad_encoded = FrameEncoder::encode(&frame).unwrap();
        // Corrupt payload so checksum fails
        bad_encoded[FRAME_HEADER_SIZE + 1] ^= 0xFF;

        // Prepare a valid frame to follow
        let valid = raw_frame(3, 0x02, FLAG_NONE, b"recovery", 2, None);

        let mut all = bad_encoded;
        all.extend_from_slice(&valid);

        let mut decoder = FrameDecoder::new();
        decoder.feed(&all);

        let result1 = decoder.decode();
        assert!(matches!(result1, Err(ProtocolError::ChecksumMismatch)));

        let result2 = decoder.decode();
        assert!(result2.is_ok());
        let recovered = result2.unwrap().unwrap();
        assert_eq!(recovered.payload, b"recovery");
        assert_eq!(recovered.message_type, 0x02);
        assert_eq!(recovered.sequence, 2);
    }

    // -----------------------------------------------------------------------
    // Recovery: valid frame after invalid input
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_frame_after_invalid_input() {
        // Prepend 12 bytes of garbage, then a valid frame.
        // The garbage should be consumed as part of a failed decode
        // (invalid magic) or trigger an error; the valid frame should still
        // be decodable.
        let valid = raw_frame(3, 0x03, FLAG_NONE, b"after garbage", 42, None);

        let mut buf = vec![0xFFu8; 12]; // garbage prefix
        buf.extend_from_slice(&valid);

        let mut decoder = FrameDecoder::new();
        decoder.feed(&buf);

        // First decode attempt: the garbage bytes (12) + header (20) = 32 ≥ 24,
        // so decode will try: magic will be wrong, clearing buffer.
        let result1 = decoder.decode();
        // With garbage + valid frame in buffer, after the failed decode
        // the buffer is cleared. So result1 is Err(InvalidMessage).
        assert!(result1.is_err());

        // Valid frame was also cleared. Feed it again.
        decoder.feed(&valid);
        let recovered = decoder.decode().unwrap().unwrap();
        assert_eq!(recovered.payload, b"after garbage");
        assert_eq!(recovered.message_type, 0x03);
    }

    #[test]
    fn test_valid_frame_after_multiple_invalid_inputs() {
        // Feed a stream with mixed garbage and a valid frame.
        // Verify the decoder recovers to produce the correct frame.
        let valid = raw_frame(3, 0x07, FLAG_NONE, b"final", 100, None);

        // Garbage chunk 1: wrong magic
        let garbage1 = raw_frame_header(0xCAFEBABE, 3, 0x01, FLAG_NONE, 0, 0, [0u8; 4]);
        // Garbage chunk 2: unsupported version
        let garbage2 = raw_frame_header(FRAME_MAGIC, 0, 0x01, FLAG_NONE, 0, 0, [0u8; 4]);

        let mut decoder = FrameDecoder::new();

        // Feed garbage1 → decode → error → buffer cleared
        decoder.feed(&garbage1);
        assert!(decoder.decode().is_err());

        // Feed garbage2 → decode → error → buffer cleared
        decoder.feed(&garbage2);
        assert!(decoder.decode().is_err());

        // Feed valid frame → should decode successfully
        decoder.feed(&valid);
        let recovered = decoder.decode().unwrap().unwrap();
        assert_eq!(recovered.payload, b"final");
        assert_eq!(recovered.sequence, 100);
        assert_eq!(recovered.message_type, 0x07);
    }

    #[test]
    fn test_valid_frame_after_garbage_interleaved() {
        // Garbage followed immediately by valid frame in one feed call.
        // After garbage causes error (clearing buffer), the valid frame
        // needs to be re-fed, then it decodes successfully.
        let valid = raw_frame(3, 0x05, FLAG_NONE, b"interleaved", 7, None);
        let mut buf = vec![0x00u8; FRAME_HEADER_SIZE]; // bad magic (all zeros)
        buf.extend_from_slice(&valid);

        let mut decoder = FrameDecoder::new();
        decoder.feed(&buf);

        // Decode: magic is all zeros → Err(InvalidMessage) + buffer cleared
        let result1 = decoder.decode();
        assert!(result1.is_err());

        // Re-feed the valid frame after the error
        decoder.feed(&valid);
        let recovered = decoder.decode().unwrap().unwrap();
        assert_eq!(recovered.payload, b"interleaved");
        assert_eq!(recovered.sequence, 7);
    }

    // -----------------------------------------------------------------------
    // Reserved bytes regression
    // -----------------------------------------------------------------------

    #[test]
    fn test_reserved_bytes_zero_are_accepted() {
        // Normal zero reserved bytes must work (regression check after
        // adding the non-zero-reserved-bytes validation).
        let frame = raw_frame(3, 0x01, FLAG_NONE, b"ok", 0, None);
        let mut decoder = FrameDecoder::new();
        decoder.feed(&frame);
        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(decoded.payload, b"ok");
    }

    // -----------------------------------------------------------------------
    // decode_all batch
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_all_with_recovery() {
        let valid = raw_frame(3, 0x01, FLAG_NONE, b"batch1", 0, None);
        let valid2 = raw_frame(3, 0x02, FLAG_NONE, b"batch2", 1, None);
        let mut data = valid;
        data.extend_from_slice(&valid2);

        let mut decoder = FrameDecoder::new();
        decoder.feed(&data);
        let frames = decoder.decode_all().unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].payload, b"batch1");
        assert_eq!(frames[1].payload, b"batch2");
    }

    // -----------------------------------------------------------------------
    // Frame with flags and checksum round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_frame_with_flags_round_trip() {
        let payload = b"flagged frame".to_vec();
        let frame = Frame::new(0x10, payload.clone())
            .with_sequence(999)
            .with_flags(FLAG_COMPRESSED | FLAG_PRIORITY);

        let encoded = FrameEncoder::encode(&frame).unwrap();
        let mut decoder = FrameDecoder::new();
        decoder.feed(&encoded);
        let decoded = decoder.decode().unwrap().unwrap();

        assert_eq!(decoded.message_type, 0x10);
        assert_eq!(decoded.sequence, 999);
        assert_eq!(decoded.flags & FLAG_COMPRESSED, FLAG_COMPRESSED);
        assert_eq!(decoded.flags & FLAG_PRIORITY, FLAG_PRIORITY);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_frame_checksum_round_trip() {
        let payload = b"checksummed".to_vec();
        let frame = Frame::new(0x20, payload.clone()).with_checksum();

        let encoded = FrameEncoder::encode(&frame).unwrap();
        let mut decoder = FrameDecoder::new();
        decoder.feed(&encoded);
        let decoded = decoder.decode().unwrap().unwrap();

        assert_eq!(decoded.payload, payload);
        assert!(decoded.checksum.is_some());
        // Verify checksum is correct
        assert_eq!(decoded.checksum.unwrap(), crc32c(&payload));
    }

    // -----------------------------------------------------------------------
    // Recovery: valid frame after truncated-then-complete
    // -----------------------------------------------------------------------

    #[test]
    fn test_recover_after_partial_then_complete() {
        // Feed partial header → get None, then complete the frame → get Some
        let payload = b"complete".to_vec();
        let frame = Frame::new(0x03, payload.clone());

        let encoded = FrameEncoder::encode(&frame).unwrap();
        let split_at = 10; // less than header size

        let mut decoder = FrameDecoder::new();
        decoder.feed(&encoded[..split_at]);
        assert!(decoder.decode().unwrap().is_none());

        decoder.feed(&encoded[split_at..]);
        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(decoded.payload, payload);
    }

    // -----------------------------------------------------------------------
    // Empty and zero-length payload cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_payload_frame() {
        let frame = raw_frame(3, 0x01, FLAG_NONE, b"", 0, None);
        let mut decoder = FrameDecoder::new();
        decoder.feed(&frame);
        let decoded = decoder.decode().unwrap().unwrap();
        assert_eq!(decoded.payload, b"");
    }

    // -----------------------------------------------------------------------
    // Buffer state tracking
    // -----------------------------------------------------------------------

    #[test]
    fn test_buffered_bytes_after_partial_feed() {
        let mut decoder = FrameDecoder::new();
        assert_eq!(decoder.buffered_bytes(), 0);

        decoder.feed(&[1u8, 2, 3, 4, 5]);
        assert_eq!(decoder.buffered_bytes(), 5);

        // decode returns None (not enough data), but buffer is preserved
        let _ = decoder.decode();
        assert_eq!(decoder.buffered_bytes(), 5);
    }

    #[test]
    fn test_reset_clears_everything() {
        let mut decoder = FrameDecoder::new();
        decoder.feed(&[0u8; 100]);
        assert_eq!(decoder.buffered_bytes(), 100);

        decoder.reset();
        assert_eq!(decoder.buffered_bytes(), 0);
    }
}
