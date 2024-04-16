use num_enum::TryFromPrimitive;
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::PublicKey;

use crate::{
    buffer::{AllocU16Handle, EncodingBuffer, ParseBuffer},
    cipher_suites::TlsCipherSuite,
    client_config::ClientConfig,
    handshake::{
        extensions::DtlsVersions, ClientHandshake, ClientHello, ServerHandshake, ServerHello,
    },
    integers::U48,
    key_schedule::KeySchedule,
};

#[derive(Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Encryption {
    Enabled,
    Disabled,
}

/// Holds positions of key positions in the payload data. Used for transcript hashing.
pub struct RecordPayloadPositions {
    pub start: usize,
    pub end: usize,
}

impl RecordPayloadPositions {
    pub fn into_sub_slices(self, buf: &[u8], split_at: usize) -> Option<(&[u8], &[u8])> {
        // Calculate indices
        let start = self.start.checked_sub(buf.as_ptr() as usize)?;
        let middle = split_at.checked_sub(buf.as_ptr() as usize)?;
        let end = self.end.checked_sub(buf.as_ptr() as usize)?;

        debug_assert!(start < middle);
        debug_assert!(middle < end);

        // Create the sub-slices around the middle element
        Some((buf.get(start..middle)?, buf.get(middle..end)?))
    }

    pub fn into_slice(self, buf: &[u8]) -> Option<&[u8]> {
        // Calculate indices
        let start = self.start.checked_sub(buf.as_ptr() as usize)?;
        let end = self.end.checked_sub(buf.as_ptr() as usize)?;

        debug_assert!(start < end);

        buf.get(start..end)
    }
}

/// Supported client records.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ClientRecord<'a, CipherSuite> {
    Handshake(ClientHandshake<'a, CipherSuite>),
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
        ClientRecord::Handshake(ClientHandshake::ClientHello(ClientHello::new(config, rng)))
    }

    /// Encode the record into a buffer.
    pub fn encode<'buf>(
        &self,
        buf: &'buf mut EncodingBuffer,
        key_schedule: &mut KeySchedule<<CipherSuite as TlsCipherSuite>::Hash>,
        transcript_hasher: &mut CipherSuite::Hash,
    ) -> Result<&'buf [u8], ()> {
        let header = DTlsPlaintextHeader {
            type_: self.content_type(),
            epoch: 0,
            sequence_number: 0.into(),
            length: 0, // To be encoded later.
        };

        // ------ Start record

        // Create record header.
        let length_allocation = header.encode(buf)?;

        buf.forward_start();
        let content_start = buf.len();

        // ------ Encode payload

        match self {
            // NOTE: Each record encoder needs to update the transcript hash at their end.
            ClientRecord::Handshake(handshake) => {
                handshake.encode(buf, key_schedule, transcript_hasher)?;
            }
            ClientRecord::Alert(_, _) => todo!(),
            ClientRecord::Heartbeat(_, _) => todo!(),
            ClientRecord::Ack(_, _) => todo!(),
            ClientRecord::ApplicationData() => todo!(),
        }

        let content_length = (buf.len() - content_start) as u16;
        length_allocation.set(buf, content_length);

        // ------ Finish record
        buf.reset_start();

        Ok(&*buf)
    }

    fn content_type(&self) -> ContentType {
        match self {
            ClientRecord::Handshake(_) => ContentType::Handshake,
            ClientRecord::Alert(_, Encryption::Disabled) => ContentType::Alert,
            ClientRecord::Heartbeat(_, Encryption::Disabled) => ContentType::Heartbeat,
            ClientRecord::Ack(_, Encryption::Disabled) => ContentType::Ack,
            // All encrypted communication is marked as `ApplicationData`.
            ClientRecord::Alert(_, Encryption::Enabled) => ContentType::ApplicationData,
            ClientRecord::Heartbeat(_, Encryption::Enabled) => ContentType::ApplicationData,
            ClientRecord::Ack(_, Encryption::Enabled) => ContentType::ApplicationData,
            ClientRecord::ApplicationData() => ContentType::ApplicationData,
        }
    }
}

/// Supported client records.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ServerRecord {
    Handshake(ServerHandshake),
    Alert(/* Alert, */ (), Encryption),
    Heartbeat((), Encryption),
    Ack((), Encryption),
    ApplicationData(/* &'a [u8] */),
}

impl ServerRecord {
    /// Create a client hello handshake.
    pub fn server_hello(
        legacy_session_id: Vec<u8>,
        supported_version: DtlsVersions,
        public_key: PublicKey,
        selected_cipher_suite: u16,
        selected_psk_identity: u16,
    ) -> Self {
        ServerRecord::Handshake(ServerHandshake::ServerHello(ServerHello::new(
            legacy_session_id,
            supported_version,
            public_key,
            selected_cipher_suite,
            selected_psk_identity,
        )))
    }

    /// Encode the record into a buffer. Returns (packet to send, content to hash).
    pub fn encode<'buf>(&self, buf: &'buf mut EncodingBuffer) -> Result<(&'buf [u8]), ()> {
        let header = DTlsPlaintextHeader {
            type_: self.content_type(),
            epoch: 0,
            sequence_number: 0.into(),
            length: 0, // To be encoded later.
        };

        // ------ Start record

        // Create record header.
        let length_allocation = header.encode(buf)?;

        buf.forward_start();
        let content_start = buf.len();

        // ------ Encode payload

        match self {
            // NOTE: Each record encoder needs to update the transcript hash at their end.
            ServerRecord::Handshake(handshake) => {
                handshake.encode(buf)?;
            }
            ServerRecord::Alert(_, _) => todo!(),
            ServerRecord::Heartbeat(_, _) => todo!(),
            ServerRecord::Ack(_, _) => todo!(),
            ServerRecord::ApplicationData() => todo!(),
        }

        let content_length = (buf.len() - content_start) as u16;
        length_allocation.set(buf, content_length);

        // ------ Finish record
        buf.reset_start();

        let r = &*buf;
        let start = buf.len() - content_length as usize;

        Ok(&r[start..])
    }

    fn content_type(&self) -> ContentType {
        match self {
            ServerRecord::Handshake(_) => ContentType::Handshake,
            ServerRecord::Alert(_, Encryption::Disabled) => ContentType::Alert,
            ServerRecord::Heartbeat(_, Encryption::Disabled) => ContentType::Heartbeat,
            ServerRecord::Ack(_, Encryption::Disabled) => ContentType::Ack,
            // All encrypted communication is marked as `ApplicationData`.
            ServerRecord::Alert(_, Encryption::Enabled) => ContentType::ApplicationData,
            ServerRecord::Heartbeat(_, Encryption::Enabled) => ContentType::ApplicationData,
            ServerRecord::Ack(_, Encryption::Enabled) => ContentType::ApplicationData,
            ServerRecord::ApplicationData() => ContentType::ApplicationData,
        }
    }
}

/// Protocol version definition.
pub type ProtocolVersion = [u8; 2];

/// Value used for protocol version in DTLS 1.3.
pub const LEGACY_DTLS_VERSION: ProtocolVersion = [254, 253];

/// DTls 1.3 plaintext header.
#[derive(Debug)]
pub struct DTlsPlaintextHeader {
    pub type_: ContentType,
    pub epoch: u16,
    pub sequence_number: U48,
    pub length: u16,
}

impl DTlsPlaintextHeader {
    /// Encode a DTlsPlaintext header, return the allocation for the length field.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<AllocU16Handle, ()> {
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
        buf.push_u16_be(self.epoch)?;
        buf.push_u48_be(self.sequence_number)?;
        buf.alloc_u16() // Allocate for teh length
    }

    /// Parse a plaintext header.
    pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
        let type_ = ContentType::try_from(buf.pop_u8()?).ok()?;

        if buf.pop_slice(2)? != LEGACY_DTLS_VERSION {
            return None;
        }

        let epoch = buf.pop_u16_be()?;
        let sequence_number = buf.pop_u48_be()?;
        let length = buf.pop_u16_be()?;

        Some(Self {
            type_,
            epoch,
            sequence_number,
            length,
        })
    }
}

/// TLS content type. RFC 9147 - Appendix A.1
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq, TryFromPrimitive)]
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
