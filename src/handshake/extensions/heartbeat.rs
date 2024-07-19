use defmt_or_log::derive_format_or_debug;
use num_enum::TryFromPrimitive;

use crate::buffer::{EncodingBuffer, OutOfMemory, ParseBuffer};

/// The heartbeat extension.
///
/// From Section 2, RFC6520.
#[derive_format_or_debug]
#[derive(Clone, PartialOrd, PartialEq)]
pub struct HeartbeatExtension {
    /// Supported heartbeat mode.
    pub mode: HeartbeatMode,
}

impl HeartbeatExtension {
    /// Encode a `heartbeat` extension.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), OutOfMemory> {
        buf.push_u8(self.mode as u8)
    }

    /// Parse a supported heartbeat.
    pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
        Some(Self {
            mode: HeartbeatMode::try_from(buf.pop_u8()?).ok()?,
        })
    }
}

/// Heartbeat mode.
///
/// From Section 2, RFC6520.
#[repr(u8)]
#[derive_format_or_debug]
#[derive(Copy, Clone, PartialOrd, PartialEq, TryFromPrimitive)]
pub enum HeartbeatMode {
    /// Peer is willing to receive HeartbeatRequests and respond with HeartbeatResponses
    PeerAllowedToSend = 1,
    /// Peer is willing only to send HeartbeatRequests
    PeerNotAllowedToSend = 2,
}
