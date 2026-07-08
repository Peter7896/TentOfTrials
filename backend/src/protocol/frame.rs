   Heartbeat = 0x00,
   Data = 0x01,
   Control = 0x02,
   Error = 0x03,
   pub fn from_u8(value: u8) -> Option<Self> {
       match value {
           0x00 => Some(FrameType::Heartbeat),
           0x01 => Some(FrameType::Data),
           0x02 => Some(FrameType::Control),
           0x03 => Some(FrameType::Error),
           _ => None,
       }
   }