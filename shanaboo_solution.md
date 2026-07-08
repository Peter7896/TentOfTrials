 ```diff
--- a/backend/src/protocol/frame.rs
+++ b/backend/src/protocol/frame.rs
@@ -0,0 +1,0 @@
+// Protocol frame codec with recovery support
+
+use bytes::{Buf, BytesMut};
+use std::fmt;
+use thiserror::Error;
+
+/// Maximum allowed frame size to prevent memory exhaustion
+pub const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024; // 16 MiB
+
+/// Protocol version
+pub const PROTOCOL_VERSION: u8 = 1;
+
+/// Frame header structure:
+/// - Magic (2 bytes): 0x54 0x4F ("TO")
+/// - Version (1 byte)
+/// - Flags (1 byte)
+/// - Reserved (2 bytes, must be 0)
+/// - Length (4 bytes, big-endian)
+/// - Checksum (4 bytes, simple XOR-based)
+pub const HEADER_SIZE: usize = 14;
+
+#[derive(Debug, Clone, PartialEq, Eq)]
+pub struct Frame {
+    pub version: u8,
+    pub flags: u8,
+    pub payload: Vec<u8>,
+}
+
+impl Frame {
+    pub fn new(payload: Vec<u8>) -> Self {
+        Self {
+            version: PROTOCOL_VERSION,
+            flags: 0,
+            payload,
+        }
+    }
+}
+
+#[derive(Error, Debug, Clone, PartialEq, Eq)]
+pub enum FrameError {
+    #[error("insufficient data: need {needed}, have {have}")]
+    InsufficientData { needed: usize, have: usize },
+    
+    #[error("invalid magic bytes: expected [0x54, 0x4F], got {0:?}")]
+    InvalidMagic([u8; 2]),
+    
+    #[error("unsupported protocol version: {0}")]
+    UnsupportedVersion(u8),
+    
+    #[error("invalid reserved bytes: expected [0x00, 0x00], got {0:?}")]
+    InvalidReserved([u8; 2]),
+    
+    #[error("frame length exceeds maximum: {length} > {max}")]
+    FrameTooLarge { length: u32, max: u32 },
+    
+    #[error("checksum mismatch: expected {expected:#04x}, computed {computed:#04x}")]
+    ChecksumMismatch { expected: u32, computed: u32 },
+    
+    #[error("truncated payload: expected {expected} bytes, have {have}")]
+    TruncatedPayload { expected: usize, have: usize },
+}
+
+/// Compute simple XOR checksum over data
+fn compute_checksum(data: &[u8]) -> u32 {
+    let mut checksum: u32 = 0;
+    for chunk in data.chunks(4) {
+        let mut word = [0u8; 4];
+        word[..chunk.len()].copy_from_slice(chunk);
+        checksum ^= u32::from_be_bytes(word);
+    }
+    checksum
+}
+
+/// Build a complete frame into a byte buffer
+pub fn encode_frame(frame: &Frame, dst: &mut BytesMut) {
+    let length = frame.payload.len() as u32;
+    let mut header = [0u8; HEADER_SIZE];
+    
+    // Magic
+    header[0] = 0x54;
+    header[1] = 0x4F;
+    // Version
+    header[2] = frame.version;
+    // Flags
+    header[3] = frame.flags;
+    // Reserved (must be 0)
+    header[4] = 0;
+    header[5] = 0;
+    // Length (big-endian)
+    header[6..10].copy_from_slice(&length.to_be_bytes());
+    
+    // Checksum over header (without checksum field) + payload
+    let checksum = compute_checksum(&header[..10]);
+    let payload_checksum = compute_checksum(&frame.payload);
+    let total_checksum = checksum ^ payload_checksum;
+    header[10..14].copy_from_slice(&total_checksum.to_be_bytes());
+    
+    dst.extend_from_slice(&header);
+    dst.extend_from_slice(&frame.payload);
+}
+
+/// Decode a frame from a byte buffer with state preservation on error
+pub struct FrameDecoder {
+    /// Number of successfully decoded frames
+    frames_decoded: u64,
+    /// Number of failed decode attempts
+    frames_failed: u64,
+    /// Whether we're currently mid-decode (for state tracking)
+    decoding: bool,
+}
+
+impl Default for FrameDecoder {
+    fn default() -> Self {
+        Self::new()
+    }
+}
+
+impl FrameDecoder {
+    pub fn new() -> Self {
+        Self {
+            frames_decoded: 0,
+            frames_failed: 0,
+            decoding: false,
+        }
+    }
+    
+    pub fn frames_decoded(&self) -> u64 {
+        self.frames_decoded
+    }
+    
+    pub fn frames_failed(&self) -> u64 {
+        self.frames_failed
+    }
+    
+    /// Attempt to decode a frame from the buffer.
+    /// On success, consumes the frame bytes and returns the frame.
+    /// On error, preserves buffer state (does not consume bytes).
+    pub fn decode(&mut self, src: &mut BytesMut) -> Result<Frame, FrameError> {
+        self.decoding = true;
+        
+        let result = self.try_decode(src);
+        
+        match &result {
+            Ok(_) => {
+                self.frames_decoded += 1;
+                self.decoding = false;
+            }
+            Err(_) => {
+                self.frames_failed += 1;
+                // Don't reset decoding flag - we're still in a valid state
+                self.decoding = false;
+            }
+        }
+        
+        result
+    }
+    
+    fn try_decode(&self, src: &mut BytesMut) -> Result<Frame, FrameError> {
+        // Check for complete header
+        if src.len() < HEADER_SIZE {
+            return Err(FrameError::InsufficientData {
+                needed: HEADER_SIZE,
+                have: src.len(),
+            });
+        }
+        
+        // Parse header without consuming yet
+        let magic = [src[0], src[1]];
+        if magic != [0x54, 0x4F] {
+            return Err(FrameError::InvalidMagic(magic));
+        }
+        
+        let version = src[2];
+        if version != PROTOCOL_VERSION {
+            return Err(FrameError::UnsupportedVersion(version));
+        }
+        
+        let flags = src[3];
+        
+        let