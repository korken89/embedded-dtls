use rand_core::{CryptoRng, RngCore};

use crate::{
    buffer::{AllocU16Handle, Buffer},
    cipher_suites::TlsCipherSuite,
    handshake::{ClientConfig, ClientHandshake, ClientHello},
    integers::U48,
    key_schedule::KeySchedule,
    DTlsError, UdpSocket,
};

#[derive(Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Encryption {
    Enabled,
    Disabled,
}

/// Supported client records.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ClientRecord<'a, CipherSuite> {
    Handshake(ClientHandshake<'a, CipherSuite>, Encryption),
    Alert(/* Alert, */ (), Encryption),
    Heartbeat((), Encryption),
    Ack((), Encryption),
    ApplicationData(/* &'a [u8] */),
}

impl<'a, CipherSuite: TlsCipherSuite> ClientRecord<'a, CipherSuite> {
    /// Create a client hello handshake.
    pub fn client_hello<Rng>(config: &'a ClientConfig<'a>, rng: &mut Rng) -> Self
    where
        Rng: RngCore + CryptoRng,
    {
        ClientRecord::Handshake(
            ClientHandshake::ClientHello(ClientHello::new(config, rng)),
            Encryption::Disabled,
        )
    }

    /// Encode the record into a buffer.
    pub fn encode<S: UdpSocket>(
        &self,
        buf: &mut Buffer,
        key_schedule: &mut KeySchedule<CipherSuite>,
        transcript_hasher: &mut CipherSuite::Hash,
    ) -> Result<(), DTlsError<S>> {
        let header = DTlsPlaintextHeader {
            type_: self.content_type(),
            sequence_number: 0.into(),
        };

        // ------ Start record

        // Create record header.
        let content_start = buf.len();
        let (length_allocation, mut buf) = header
            .encode(&mut buf)
            .map_err(|_| DTlsError::InsufficientSpace)?;

        let mut buf = buf.forward();

        // ------ Encode payload

        match self {
            ClientRecord::Handshake(handshake, encryption) => {
                // TODO: handle encryption
                handshake
                    .encode(&mut buf, key_schedule, transcript_hasher)
                    .map_err(|_| DTlsError::InsufficientSpace)?;

                // if let Some(binders) = binders_allocation {
                //     if let &ClientRecord::Handshake(
                //         ClientHandshake::ClientHello(_),
                //         Encryption::Disabled,
                //     ) = self
                //     {
                //         // TODO: Handle binders
                //     }
                // }
            }
            ClientRecord::Alert(_, _) => todo!(),
            ClientRecord::Heartbeat(_, _) => todo!(),
            ClientRecord::Ack(_, _) => todo!(),
            ClientRecord::ApplicationData() => todo!(),
        }

        let content_length = (content_start - buf.len()) as u16;
        length_allocation.set(content_length);

        // ------ Finish record

        Ok(())
    }

    fn content_type(&self) -> ContentType {
        match self {
            ClientRecord::Handshake(_, Encryption::Disabled) => ContentType::Handshake,
            ClientRecord::Alert(_, Encryption::Disabled) => ContentType::Alert,
            ClientRecord::Heartbeat(_, Encryption::Disabled) => ContentType::Heartbeat,
            ClientRecord::Ack(_, Encryption::Disabled) => ContentType::Ack,
            // All encrypted communication is marked as `ApplicationData`.
            ClientRecord::Handshake(_, Encryption::Enabled) => ContentType::ApplicationData,
            ClientRecord::Alert(_, Encryption::Enabled) => ContentType::ApplicationData,
            ClientRecord::Heartbeat(_, Encryption::Enabled) => ContentType::ApplicationData,
            ClientRecord::Ack(_, Encryption::Enabled) => ContentType::ApplicationData,
            ClientRecord::ApplicationData() => ContentType::ApplicationData,
        }
    }
}

/// Protocol version definition.
pub type ProtocolVersion = [u8; 2];

/// Value used for protocol version in DTLS 1.3.
pub const LEGACY_DTLS_VERSION: ProtocolVersion = [254, 253];

/// DTls 1.3 plaintext header.
pub struct DTlsPlaintextHeader {
    type_: ContentType,
    sequence_number: U48,
}

impl DTlsPlaintextHeader {
    /// Encode a DTlsPlaintext header, return the allocation for the length field.
    pub fn encode(&self, buf: &mut Buffer) -> Result<(AllocU16Handle, Buffer), ()> {
        // DTlsPlaintext structure:
        //
        // type: ContentType,
        // legacy_record_version: ProtocolVersion,
        // epoch: u16, always 0
        // sequence_number: U48,
        // length: u16, // we don't know this yes, only alloc for it
        // fragment: opaque[length]

        buf.push_u8(self.type_ as u8)?;
        buf.extend_from_slice(&LEGACY_DTLS_VERSION)?;
        buf.push_u16_be(0)?;
        buf.push_u48_be(self.sequence_number)?;
        buf.alloc_u16()
    }
}

/// TLS content type. RFC 9147 - Appendix A.1
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24,
    // Tls12Cid = 25,
    Ack = 26,
}

impl ContentType {
    pub fn of(num: u8) -> Option<Self> {
        match num {
            20 => Some(Self::ChangeCipherSpec),
            21 => Some(Self::Alert),
            22 => Some(Self::Handshake),
            23 => Some(Self::ApplicationData),
            _ => None,
        }
    }
}
