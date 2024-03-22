use crate::{buffer::Buffer, integers::U48, DTlsError, UdpSocket};

/// Record number tracking.
pub struct RecordNumber {
    // epoch: u16, // Always 0
    sequence_number: U48,
}

impl RecordNumber {
    /// Create a new record number counter.
    pub fn new() -> Self {
        Self {
            sequence_number: U48::new(0),
        }
    }

    /// Increment the counter.
    pub fn increment(&mut self) {
        self.sequence_number += 1;
    }

    /// Get the value.
    pub fn sequence_number(&self) -> U48 {
        self.sequence_number
    }

    // Encode into a DTLS buffer.
    pub fn encode<S: UdpSocket>(&self, mut buf: Buffer) -> Result<(), DTlsError<S>> {
        // Epoch (always 0), RFC 9147 - Appendix A.1
        buf.push_u16_be(0)
            .map_err(|_| DTlsError::InsufficientSpace)?;
        //  Sequence number
        buf.push_u48_be(self.sequence_number)
            .map_err(|_| DTlsError::InsufficientSpace)
    }
}

pub struct Session {
    sequence_number: U48,
}
