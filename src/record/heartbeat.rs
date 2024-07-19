use defmt_or_log::derive_format_or_debug;
use num_enum::TryFromPrimitive;

use crate::buffer::{EncodingBuffer, OutOfMemory, ParseBuffer};

/// Heartbeat message type.
///
/// From Section 3, RFC6520.
/// enum {
///    heartbeat_request(1),
///    heartbeat_response(2),
///    (255)
/// } HeartbeatMessageType;
#[repr(u8)]
#[derive_format_or_debug]
#[derive(Copy, Clone, PartialOrd, PartialEq, TryFromPrimitive)]
pub enum HeartbeatMessageType {
    Request = 1,
    Response = 2,
}

// TODO: Move to record module (possibly, record::heartbeat?)
/// High-level heartbeat representation
#[derive_format_or_debug]
pub struct Heartbeat<'a> {
    pub type_: HeartbeatMessageType,
    pub payload: &'a [u8],
}

impl<'a> Heartbeat<'a> {
    // struct {
    //    HeartbeatMessageType type;
    //    uint16 payload_length;
    //    opaque payload[HeartbeatMessage.payload_length];
    //    opaque padding[padding_length];
    // } HeartbeatMessage;

    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), OutOfMemory> {
        buf.push_u8(self.type_ as u8)?;
        buf.push_u16_be(self.payload.len() as u16)?;
        buf.extend_from_slice(self.payload)?;
        // From Section 4, RFC6520.
        for _ in 0..16 {
            buf.push_u8(0)?;
        }
        Ok(())
    }
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<Self> {
        let type_ = HeartbeatMessageType::try_from(buf.pop_u8()?).ok()?;
        let payload_len = buf.pop_u16_be()?;
        // From Section 4, RFC6520.
        // > The total length of a HeartbeatMessage MUST NOT exceed 2^14 or
        // > max_fragment_length when negotiated as defined in [RFC6066].
        if payload_len > (1 << 14) {
            return None;
        }
        let payload = buf.pop_slice(payload_len as usize)?;
        Some(Self { type_, payload })
    }
}
