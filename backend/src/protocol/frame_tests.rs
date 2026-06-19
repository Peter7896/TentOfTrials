use super::codec::{
    Frame, FrameDecoder, FrameEncoder, FRAME_HEADER_SIZE, FRAME_MAGIC, FRAME_MAX_PAYLOAD_SIZE,
};
use super::{ProtocolError, PROTOCOL_VERSION};

fn encoded_frame(message_type: u8, payload: &[u8], checksum: bool) -> Vec<u8> {
    let mut frame = Frame::new(message_type, payload.to_vec());
    if checksum {
        frame = frame.with_checksum();
    }
    FrameEncoder::encode(&frame).expect("test frame should encode")
}

fn set_payload_length(encoded: &mut [u8], length: u32) {
    encoded[8..12].copy_from_slice(&length.to_be_bytes());
}

fn set_reserved_nonzero(encoded: &mut [u8]) {
    encoded[16] = 0x80;
}

fn corrupt_checksum(encoded: &mut [u8]) {
    let last = encoded.len() - 1;
    encoded[last] ^= 0x01;
}

fn assert_error(result: Result<Option<Frame>, ProtocolError>, expected: ProtocolError) {
    match result {
        Err(actual) => assert_eq!(actual, expected),
        Ok(None) => panic!("expected {expected:?}, got incomplete frame"),
        Ok(Some(frame)) => panic!("expected {expected:?}, got frame {frame:?}"),
    }
}

#[test]
fn encoded_header_size_matches_decoder_contract() {
    let payload = b"size-check";
    let encoded = encoded_frame(0x01, payload, false);

    assert_eq!(encoded.len(), FRAME_HEADER_SIZE + payload.len());
    assert_eq!(&encoded[..4], &FRAME_MAGIC.to_be_bytes());
}

#[test]
fn truncated_header_returns_none_without_panic() {
    let encoded = encoded_frame(0x02, b"payload", false);
    let mut decoder = FrameDecoder::new();

    decoder.feed(&encoded[..FRAME_HEADER_SIZE - 1]);

    assert!(decoder.decode().unwrap().is_none());
    assert_eq!(decoder.buffered_bytes(), FRAME_HEADER_SIZE - 1);
    assert_eq!(decoder.accepted_frames(), 0);
}

#[test]
fn truncated_payload_returns_none_without_panic() {
    let encoded = encoded_frame(0x03, b"payload", false);
    let mut decoder = FrameDecoder::new();

    decoder.feed(&encoded[..FRAME_HEADER_SIZE + 3]);

    assert!(decoder.decode().unwrap().is_none());
    assert_eq!(decoder.buffered_bytes(), FRAME_HEADER_SIZE + 3);
    assert_eq!(decoder.accepted_frames(), 0);
}

#[test]
fn truncated_payload_completes_after_more_bytes_arrive() {
    let encoded = encoded_frame(0x04, b"complete me", false);
    let split = FRAME_HEADER_SIZE + 4;
    let mut decoder = FrameDecoder::new();

    decoder.feed(&encoded[..split]);
    assert!(decoder.decode().unwrap().is_none());

    decoder.feed(&encoded[split..]);
    let decoded = decoder.decode().unwrap().unwrap();

    assert_eq!(decoded.message_type, 0x04);
    assert_eq!(decoded.payload, b"complete me");
    assert_eq!(decoder.accepted_frames(), 1);
    assert_eq!(decoder.buffered_bytes(), 0);
}

#[test]
fn invalid_magic_preserves_following_valid_frame() {
    let mut invalid = encoded_frame(0x05, b"bad magic", false);
    invalid[0] ^= 0xFF;
    let valid = encoded_frame(0x06, b"after magic", false);

    let mut decoder = FrameDecoder::new();
    decoder.feed(&invalid);
    decoder.feed(&valid);

    assert_error(decoder.decode(), ProtocolError::InvalidMessage);
    assert_eq!(decoder.buffered_bytes(), valid.len());

    let decoded = decoder.decode().unwrap().unwrap();
    assert_eq!(decoded.message_type, 0x06);
    assert_eq!(decoded.payload, b"after magic");
    assert_eq!(decoder.accepted_frames(), 1);
}

#[test]
fn unsupported_version_preserves_following_valid_frame() {
    let mut invalid = encoded_frame(0x07, b"bad version", false);
    invalid[4] = (PROTOCOL_VERSION as u8).saturating_add(1);
    let valid = encoded_frame(0x08, b"after version", false);

    let mut decoder = FrameDecoder::new();
    decoder.feed(&invalid);
    decoder.feed(&valid);

    assert_error(decoder.decode(), ProtocolError::UnsupportedVersion);
    assert_eq!(decoder.buffered_bytes(), valid.len());

    let decoded = decoder.decode().unwrap().unwrap();
    assert_eq!(decoded.message_type, 0x08);
    assert_eq!(decoded.payload, b"after version");
    assert_eq!(decoder.accepted_frames(), 1);
}

#[test]
fn oversize_payload_length_preserves_following_valid_frame() {
    let mut invalid = encoded_frame(0x09, b"oversize", false);
    set_payload_length(&mut invalid, (FRAME_MAX_PAYLOAD_SIZE + 1) as u32);
    let valid = encoded_frame(0x0A, b"after oversize", false);

    let mut decoder = FrameDecoder::new();
    decoder.feed(&invalid);
    decoder.feed(&valid);

    assert_error(decoder.decode(), ProtocolError::MessageTooLarge);
    assert_eq!(decoder.buffered_bytes(), valid.len());

    let decoded = decoder.decode().unwrap().unwrap();
    assert_eq!(decoded.message_type, 0x0A);
    assert_eq!(decoded.payload, b"after oversize");
    assert_eq!(decoder.accepted_frames(), 1);
}

#[test]
fn nonzero_reserved_bytes_are_rejected() {
    let mut invalid = encoded_frame(0x0B, b"reserved", false);
    set_reserved_nonzero(&mut invalid);

    let mut decoder = FrameDecoder::new();
    decoder.feed(&invalid);

    assert_error(decoder.decode(), ProtocolError::InvalidMessage);
    assert_eq!(decoder.buffered_bytes(), 0);
    assert_eq!(decoder.accepted_frames(), 0);
}

#[test]
fn valid_frame_after_invalid_reserved_bytes_decodes() {
    let mut invalid = encoded_frame(0x0C, b"reserved", false);
    set_reserved_nonzero(&mut invalid);
    let valid = encoded_frame(0x0D, b"after reserved", false);

    let mut decoder = FrameDecoder::new();
    decoder.feed(&invalid);
    decoder.feed(&valid);

    assert_error(decoder.decode(), ProtocolError::InvalidMessage);
    assert_eq!(decoder.buffered_bytes(), valid.len());

    let decoded = decoder.decode().unwrap().unwrap();
    assert_eq!(decoded.message_type, 0x0D);
    assert_eq!(decoded.payload, b"after reserved");
    assert_eq!(decoder.accepted_frames(), 1);
}

#[test]
fn checksum_mismatch_preserves_following_valid_frame() {
    let mut invalid = encoded_frame(0x0E, b"bad checksum", true);
    corrupt_checksum(&mut invalid);
    let valid = encoded_frame(0x0F, b"after checksum", false);

    let mut decoder = FrameDecoder::new();
    decoder.feed(&invalid);
    decoder.feed(&valid);

    assert_error(decoder.decode(), ProtocolError::ChecksumMismatch);
    assert_eq!(decoder.buffered_bytes(), valid.len());

    let decoded = decoder.decode().unwrap().unwrap();
    assert_eq!(decoded.message_type, 0x0F);
    assert_eq!(decoded.payload, b"after checksum");
    assert_eq!(decoder.accepted_frames(), 1);
}

#[test]
fn decode_all_returns_all_complete_frames_and_leaves_partial_buffered() {
    let first = encoded_frame(0x10, b"first", false);
    let second = encoded_frame(0x11, b"second", false);
    let partial = encoded_frame(0x12, b"partial", false);

    let mut decoder = FrameDecoder::new();
    decoder.feed(&first);
    decoder.feed(&second);
    decoder.feed(&partial[..FRAME_HEADER_SIZE + 2]);

    let frames = decoder.decode_all().unwrap();

    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].payload, b"first");
    assert_eq!(frames[1].payload, b"second");
    assert_eq!(decoder.accepted_frames(), 2);
    assert_eq!(decoder.buffered_bytes(), FRAME_HEADER_SIZE + 2);
}

#[test]
fn empty_payload_frame_decodes_and_increments_counter() {
    let encoded = encoded_frame(0x13, b"", false);
    let mut decoder = FrameDecoder::new();
    decoder.feed(&encoded);

    let decoded = decoder.decode().unwrap().unwrap();

    assert_eq!(decoded.message_type, 0x13);
    assert!(decoded.payload.is_empty());
    assert_eq!(decoder.accepted_frames(), 1);
    assert_eq!(decoder.buffered_bytes(), 0);
}
