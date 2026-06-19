use super::codec::{
    Frame, FrameDecoder, FrameEncoder, FRAME_HEADER_SIZE, FRAME_MAX_PAYLOAD_SIZE,
};
use super::ProtocolError;

// ---------------------------------------------------------------------------
// Test helpers for deterministic malformed-frame fixtures
// ---------------------------------------------------------------------------

fn encode_valid_frame(message_type: u8, payload: &[u8], with_checksum: bool) -> Vec<u8> {
    let mut frame = Frame::new(message_type, payload.to_vec());
    if with_checksum {
        frame = frame.with_checksum();
    }
    FrameEncoder::encode(&frame).expect("valid frame should encode")
}

fn set_payload_length(encoded: &mut [u8], length: u32) {
    encoded[8..12].copy_from_slice(&length.to_be_bytes());
}

fn set_reserved_nonzero(encoded: &mut [u8]) {
    let reserved_start = FRAME_HEADER_SIZE - 8;
    encoded[reserved_start] = 0x01;
}

fn corrupt_checksum(encoded: &mut [u8]) {
    if encoded.len() >= FRAME_HEADER_SIZE + 4 {
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;
    }
}

fn assert_decode_err(result: Result<Option<Frame>, ProtocolError>, expected: ProtocolError) {
    match result {
        Err(err) => assert_eq!(err, expected, "unexpected protocol error"),
        Ok(Some(_)) => panic!("expected decode error, got frame"),
        Ok(None) => panic!("expected decode error, got incomplete frame"),
    }
}

// ---------------------------------------------------------------------------
// Truncated and oversize input
// ---------------------------------------------------------------------------

#[test]
fn truncated_header_returns_none_without_panic() {
    let valid = encode_valid_frame(0x01, b"payload", false);
    let mut decoder = FrameDecoder::new();

    decoder.feed(&valid[..FRAME_HEADER_SIZE - 1]);
    let result = decoder.decode();

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
    assert_eq!(decoder.accepted_frames(), 0);
    assert_eq!(decoder.buffered_bytes(), FRAME_HEADER_SIZE - 1);
}

#[test]
fn truncated_payload_returns_none_without_panic() {
    let valid = encode_valid_frame(0x02, b"hello", false);
    let mut decoder = FrameDecoder::new();

    decoder.feed(&valid[..FRAME_HEADER_SIZE + 2]);
    let result = decoder.decode();

    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
    assert_eq!(decoder.accepted_frames(), 0);
    assert_eq!(decoder.buffered_bytes(), FRAME_HEADER_SIZE + 2);
}

#[test]
fn truncated_payload_completes_after_additional_feed() {
    let valid = encode_valid_frame(0x03, b"complete-me", false);
    let split = FRAME_HEADER_SIZE + 4;
    let mut decoder = FrameDecoder::new();

    decoder.feed(&valid[..split]);
    assert!(decoder.decode().unwrap().is_none());

    decoder.feed(&valid[split..]);
    let frame = decoder.decode().unwrap().expect("frame should decode");
    assert_eq!(frame.payload, b"complete-me");
    assert_eq!(decoder.accepted_frames(), 1);
}

#[test]
fn invalid_frame_length_rejects_oversize_payload() {
    let mut encoded = encode_valid_frame(0x04, b"tiny", false);
    set_payload_length(&mut encoded, (FRAME_MAX_PAYLOAD_SIZE + 1) as u32);

    let mut decoder = FrameDecoder::new();
    decoder.feed(&encoded);

    assert_decode_err(decoder.decode(), ProtocolError::MessageTooLarge);
    assert_eq!(decoder.accepted_frames(), 0);
    assert_eq!(decoder.buffered_bytes(), 0);
}

// ---------------------------------------------------------------------------
// Reserved bytes and checksum integrity
// ---------------------------------------------------------------------------

#[test]
fn invalid_reserved_bytes_return_clear_error() {
    let mut encoded = encode_valid_frame(0x05, b"reserved-check", false);
    set_reserved_nonzero(&mut encoded);

    let mut decoder = FrameDecoder::new();
    decoder.feed(&encoded);

    assert_decode_err(decoder.decode(), ProtocolError::InvalidMessage);
    assert_eq!(decoder.accepted_frames(), 0);
    assert_eq!(decoder.buffered_bytes(), 0);
}

#[test]
fn checksum_mismatch_returns_clear_error() {
    let mut encoded = encode_valid_frame(0x06, b"checksum-me", true);
    corrupt_checksum(&mut encoded);

    let mut decoder = FrameDecoder::new();
    decoder.feed(&encoded);

    assert_decode_err(decoder.decode(), ProtocolError::ChecksumMismatch);
    assert_eq!(decoder.accepted_frames(), 0);
    assert_eq!(decoder.buffered_bytes(), 0);
}

// ---------------------------------------------------------------------------
// Decoder state preservation and recovery
// ---------------------------------------------------------------------------

#[test]
fn valid_frame_after_checksum_failure_decodes_successfully() {
    let mut bad = encode_valid_frame(0x09, b"bad", true);
    corrupt_checksum(&mut bad);
    let good = encode_valid_frame(0x0A, b"good", false);

    let mut stream = bad;
    stream.extend_from_slice(&good);

    let mut decoder = FrameDecoder::new();
    decoder.feed(&stream);

    assert_decode_err(decoder.decode(), ProtocolError::ChecksumMismatch);
    assert_eq!(decoder.accepted_frames(), 0);

    let recovered = decoder.decode().unwrap().expect("valid trailing frame");
    assert_eq!(recovered.message_type, 0x0A);
    assert_eq!(recovered.payload, b"good");
    assert_eq!(decoder.accepted_frames(), 1);
    assert_eq!(decoder.buffered_bytes(), 0);
}

#[test]
fn valid_frame_after_invalid_reserved_decodes_successfully() {
    let mut bad = encode_valid_frame(0x0B, b"bad-reserved", false);
    set_reserved_nonzero(&mut bad);
    let good = encode_valid_frame(0x0C, b"good-reserved", false);

    let mut stream = bad;
    stream.extend_from_slice(&good);

    let mut decoder = FrameDecoder::new();
    decoder.feed(&stream);

    assert_decode_err(decoder.decode(), ProtocolError::InvalidMessage);
    assert_eq!(decoder.accepted_frames(), 0);

    let recovered = decoder.decode().unwrap().expect("valid trailing frame");
    assert_eq!(recovered.message_type, 0x0C);
    assert_eq!(recovered.payload, b"good-reserved");
    assert_eq!(decoder.accepted_frames(), 1);
}
