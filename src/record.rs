use crate::{
    buffer::{AllocU16Handle, EncodingBuffer, ParseBuffer},
    cipher_suites::DtlsCipherSuite,
    client_config::ClientConfig,
    handshake::{
        extensions::{
            ClientExtensions, ClientSupportedVersions, DtlsVersions, KeyShareEntry, NamedGroup,
            NewServerExtensions, OfferedPsks, PskKeyExchangeMode, PskKeyExchangeModes, SelectedPsk,
            ServerSupportedVersion,
        },
        ClientHandshake, ClientHello, Finished, Random, ServerHandshake, ServerHello,
    },
    integers::U48,
    key_schedule::KeySchedule,
};
use core::ops::Range;
use digest::{Digest, OutputSizeUser};
use num_enum::TryFromPrimitive;
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::PublicKey;

#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Encryption {
    Enabled,
    Disabled,
}

#[allow(unused)]
struct NoRandom {}

impl rand::CryptoRng for NoRandom {}

impl rand::RngCore for NoRandom {
    fn next_u32(&mut self) -> u32 {
        unreachable!()
    }

    fn next_u64(&mut self) -> u64 {
        unreachable!()
    }

    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        unreachable!()
    }

    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand::Error> {
        unreachable!()
    }
}

/// Helper when something needs to encode or parse something differently.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum EncodeOrParse<E, P> {
    /// The encoding branch.
    Encode(E),
    /// The parsing branch.
    Parse(P),
}

/// A unified header.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct UnifiedHeader<'a> {
    data: &'a mut [u8],
}

/// An ACK message.
#[derive(Debug)]
pub struct Ack<'a> {
    pub record_numbers: EncodeOrParse<&'a [RecordNumber], RecordNumberIter<'a>>,
}

impl<'a> Ack<'a> {
    /// Encode an ACK.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), ()> {
        let EncodeOrParse::Encode(record_numbers) = &self.record_numbers else {
            l0g::error!("ACK: Expected encode, got parse");
            return Err(());
        };

        let size = u16::try_from(record_numbers.len() * 16).map_err(|_| ())?;
        buf.push_u16_be(size)?;

        for record_number in *record_numbers {
            record_number.encode(buf)?;
        }

        Ok(())
    }

    /// Parse an ACK.
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<Self> {
        let iter = RecordNumberIter::parse(buf)?;

        Some(Self {
            record_numbers: EncodeOrParse::Parse(iter),
        })
    }
}

/// Record number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordNumber {
    pub epoch: u64,
    pub sequence_number: u64,
}

impl RecordNumber {
    /// Encode a record number.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), ()> {
        buf.push_u64_be(self.epoch)?;
        buf.push_u64_be(self.sequence_number)
    }

    /// Parse a record number.
    pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
        let epoch = buf.pop_u64_be()?;
        let sequence_number = buf.pop_u64_be()?;

        Some(Self {
            epoch,
            sequence_number,
        })
    }
}

/// This iterator gives a `RecordNumber` for each iteration.
#[derive(Clone, Debug, PartialEq)]
pub struct RecordNumberIter<'a> {
    /// The record numbers.
    record_numbers: ParseBuffer<'a>,
}

impl<'a> Iterator for RecordNumberIter<'a> {
    type Item = RecordNumber;

    fn next(&mut self) -> Option<Self::Item> {
        RecordNumber::parse(&mut self.record_numbers)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len(), Some(self.len()))
    }
}

impl<'a> ExactSizeIterator for RecordNumberIter<'a> {}

impl<'a> RecordNumberIter<'a> {
    /// Checks if it is empty.
    pub fn is_empty(&self) -> bool {
        self.record_numbers.is_empty()
    }

    /// Returns the number of `RecordNumber` that are available.
    pub fn len(&self) -> usize {
        self.record_numbers.len() / 16
    }

    /// Parse a `RecordNumberIter`.
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<Self> {
        let record_numbers_size = buf.pop_u16_be()?;

        if record_numbers_size % 16 != 0 {
            return None;
        }

        let record_numbers = buf.pop_slice(record_numbers_size as usize)?;

        Some(Self {
            record_numbers: ParseBuffer::new(&record_numbers),
        })
    }
}

impl<'a> UnifiedHeader<'a> {
    fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }

    pub fn sequence_number_mut(&mut self) -> &mut [u8] {
        let header = self.data[0];

        if (header >> 3) & 1 != 0 {
            &mut self.data[1..3]
        } else {
            &mut self.data[1..2]
        }
    }

    pub fn full_header(&self) -> &[u8] {
        self.data
    }

    pub fn sequence_number(&self) -> CiphertextSequenceNumber {
        let header = self.data[0];

        if (header >> 3) & 1 != 0 {
            CiphertextSequenceNumber::Long(u16::from_be_bytes(self.data[1..3].try_into().unwrap()))
        } else {
            CiphertextSequenceNumber::Short(self.data[1])
        }
    }
}

/// Holds positions of key positions in the payload data. Used for transcript hashing.
#[derive(Debug)]
pub struct RecordPayloadPositions {
    pub start: usize,
    pub binders: Option<usize>,
    pub end: usize,
}

impl RecordPayloadPositions {
    fn indexes(&self, buf: &[u8]) -> Option<(usize, usize, usize)> {
        // Calculate indices
        let start = self.start.checked_sub(buf.as_ptr() as usize)?;
        let middle = self.binders?.checked_sub(buf.as_ptr() as usize)?;
        let end = self.end.checked_sub(buf.as_ptr() as usize)?;

        debug_assert!(start < middle);
        debug_assert!(middle < end);

        Some((start, middle, end))
    }

    pub fn pre_post_binders<'a>(&self, buf: &'a [u8]) -> Option<(&'a [u8], &'a [u8])> {
        let (start, middle, end) = self.indexes(buf)?;

        // Create the sub-slices around the middle element
        Some((buf.get(start..middle)?, buf.get(middle..end)?))
    }

    pub fn pre_post_binders_mut<'a>(&self, buf: &'a mut [u8]) -> Option<(&'a [u8], &'a mut [u8])> {
        let (start, middle, end) = self.indexes(buf)?;

        // Create the sub-slices around the middle element
        let buf = buf.get_mut(start..end)?;
        let (pre, post) = buf.split_at_mut(middle - start);
        Some((pre, post))
    }

    pub fn as_slice<'a>(&self, buf: &'a [u8]) -> Option<&'a [u8]> {
        let start = self.start.checked_sub(buf.as_ptr() as usize)?;
        let end = self.end.checked_sub(buf.as_ptr() as usize)?;

        buf.get(start..end)
    }
}

/// Supported client records.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ClientRecord<'a> {
    Handshake(ClientHandshake<'a>, Encryption),
    Alert(/* Alert, */ (), Encryption),
    Ack(Ack<'a>, Encryption),
    Heartbeat(()),
    ApplicationData(/* &'a [u8] */),
}

impl<'a> ClientRecord<'a> {
    /// Create a client hello handshake.
    pub async fn encode_client_hello<CipherSuite: DtlsCipherSuite, Rng: RngCore + CryptoRng>(
        buf: &mut EncodingBuffer<'_>,
        config: &'a ClientConfig<'a>,
        public_key: &PublicKey,
        rng: &mut Rng,
        key_schedule: &mut KeySchedule<CipherSuite, false>,
    ) -> Result<RecordPayloadPositions, ()>
    where
        Rng: RngCore + CryptoRng,
    {
        let identities = &[config.psk.clone()];

        let mut random = Random::default();
        rng.fill_bytes(&mut random);

        let client_hello = ClientHello {
            version: LEGACY_DTLS_VERSION,
            legacy_session_id: &[],
            cipher_suites: &(<CipherSuite as DtlsCipherSuite>::CODE_POINT as u16).to_be_bytes(),
            random: &random,
            extensions: ClientExtensions {
                psk_key_exchange_modes: Some(PskKeyExchangeModes {
                    ke_modes: PskKeyExchangeMode::PskDheKe,
                }),
                key_share: Some(KeyShareEntry {
                    group: NamedGroup::X25519,
                    opaque: public_key.as_bytes(),
                }),
                supported_versions: Some(ClientSupportedVersions {
                    version: DtlsVersions::V1_3,
                }),
                pre_shared_key: Some(OfferedPsks {
                    identities: EncodeOrParse::Encode(identities),
                    hash_size: EncodeOrParse::Encode(
                        <<CipherSuite as DtlsCipherSuite>::Hash as OutputSizeUser>::output_size(),
                    ),
                }),
            },
        };

        l0g::debug!("Sending client hello: {:02x?}", client_hello);

        ClientRecord::Handshake(
            ClientHandshake::ClientHello(client_hello),
            Encryption::Disabled,
        )
        .encode(buf, key_schedule)
        .await
    }

    /// Create a client's finished message.
    pub async fn encode_finished<CipherSuite: DtlsCipherSuite>(
        buf: &mut EncodingBuffer<'_>,
        key_schedule: &mut KeySchedule<CipherSuite, false>,
        transcript_hash: &'a [u8],
    ) -> Result<(), ()> {
        let finished = Finished {
            verify: transcript_hash,
        };

        l0g::debug!("Sending client finished: {finished:02x?}");

        ClientRecord::Handshake(
            ClientHandshake::ClientFinished(finished),
            Encryption::Enabled,
        )
        .encode(buf, key_schedule)
        .await
        .map(|_| ())
    }

    /// Create a client's ACK message.
    pub async fn encode_ack<CipherSuite: DtlsCipherSuite>(
        buf: &mut EncodingBuffer<'_>,
        key_schedule: &mut KeySchedule<CipherSuite, false>,
        record_numbers: &'a [RecordNumber],
    ) -> Result<(), ()> {
        let ack = Ack {
            record_numbers: EncodeOrParse::Encode(record_numbers),
        };

        l0g::debug!("Sending client ACK: {ack:?}");

        ClientRecord::Ack(ack, Encryption::Enabled)
            .encode(buf, key_schedule)
            .await
            .map(|_| ())
    }

    /// Encode the record into a buffer. Returns (packet to send, content to hash).
    async fn encode<'buf>(
        &self,
        buf: &'buf mut EncodingBuffer<'_>,
        cipher: &mut impl GenericCipher,
    ) -> Result<RecordPayloadPositions, ()> {
        encode_record(
            buf,
            cipher,
            self.is_encrypted(),
            self.content_type(),
            |buf| self.encode_content(buf),
        )
        .await
    }

    fn encode_content<'buf>(
        &self,
        buf: &'buf mut EncodingBuffer<'_>,
    ) -> Result<RecordPayloadPositions, ()> {
        let start = buf.current_pos_ptr();

        let binders = match self {
            // NOTE: Each record encoder needs to update the transcript hash at their end.
            ClientRecord::Handshake(handshake, _) => handshake.encode(buf)?,
            ClientRecord::Alert(_, _) => todo!(),
            ClientRecord::Heartbeat(_) => todo!(),
            ClientRecord::Ack(_, _) => todo!(),
            ClientRecord::ApplicationData() => todo!(),
        };

        let end = buf.current_pos_ptr();

        Ok(RecordPayloadPositions {
            start,
            binders,
            end,
        })
    }

    /// Parse a `ServerRecord`. The incoming `buf` will be reduced to not include what's been
    /// parsed after finishing, allowing for parse to be called multiple times.
    ///
    /// If a transcript hasher is supplied, then the hashing will be performed over the plaintext.
    pub async fn parse<Cipher>(
        buf: &mut &'a mut [u8],
        cipher: Option<&mut Cipher>,
    ) -> Option<((ClientRecord<'a>, RecordPayloadPositions), &'a [u8])>
    where
        Cipher: GenericCipher,
    {
        let r = parse_record(buf, cipher, |content_type, encryption, buf| {
            // // Perform transcript hashing.
            // if let Some(hasher) = transcript_hasher {
            //     hasher.update(buf.as_ref())
            // }

            Self::parse_content(content_type, encryption, buf)
        })
        .await;

        if let Some(out) = &r {
            l0g::trace!("Parsed {out:?}");
        }

        r
    }

    fn parse_content(
        content_type: ContentType,
        encryption: Encryption,
        buf: &mut ParseBuffer<'a>,
    ) -> Option<(Self, RecordPayloadPositions)> {
        let start = buf.current_pos_ptr();
        let (ret, binders) = match content_type {
            ContentType::Handshake => {
                let (handshake, binders_pos) = ClientHandshake::parse(buf)?;
                (ClientRecord::Handshake(handshake, encryption), binders_pos)
            }
            ContentType::Ack => {
                let ack = Ack::parse(buf)?;
                (ClientRecord::Ack(ack, encryption), None)
            }
            ContentType::Heartbeat => todo!(),
            ContentType::Alert => todo!(),
            ContentType::ApplicationData => todo!(),
            ContentType::ChangeCipherSpec => todo!(),
        };
        let end = buf.current_pos_ptr();

        Some((
            ret,
            RecordPayloadPositions {
                start,
                binders,
                end,
            },
        ))
    }

    fn is_encrypted(&self) -> bool {
        match self {
            ClientRecord::Handshake(_, Encryption::Disabled) => false,
            ClientRecord::Alert(_, Encryption::Disabled) => false,
            ClientRecord::Ack(_, Encryption::Disabled) => false,
            _ => true,
        }
    }

    fn content_type(&self) -> ContentType {
        match self {
            ClientRecord::Handshake(_, _) => ContentType::Handshake,
            ClientRecord::Alert(_, _) => ContentType::Alert,
            ClientRecord::Ack(_, _) => ContentType::Ack,
            ClientRecord::Heartbeat(_) => ContentType::Heartbeat,
            ClientRecord::ApplicationData() => ContentType::ApplicationData,
        }
    }
}

pub(crate) trait GenericHasher {
    /// Add the input buffer to the hasher.
    fn update(&mut self, data: &[u8]);
}

impl<T> GenericHasher for T
where
    T: Digest,
{
    fn update(&mut self, data: &[u8]) {
        Digest::update(self, data)
    }
}

/// No hasher marker.
pub struct NoHasher {}

impl GenericHasher for NoHasher {
    fn update(&mut self, _data: &[u8]) {}
}

pub(crate) trait GenericCipher {
    /// Encrypts a record.
    async fn encrypt_record(&mut self, args: CipherArguments) -> aead::Result<()>;

    /// Decrypts a record, returning the payload without a tag.
    async fn decrypt_record<'a>(
        &mut self,
        ciphertext_header: &DTlsCiphertextHeader,
        args: CipherArguments<'a>,
    ) -> aead::Result<&'a [u8]>;

    /// Returns the size of the AEAD tag.
    fn tag_size(&self) -> usize;

    /// Get the current write record number.
    fn write_record_number(&self) -> u64;

    /// Increment the current write record number.
    fn increment_write_record_number(&mut self);

    /// Get the current read record number.
    fn read_record_number(&self) -> u64;

    /// Get the current epoch number.
    fn epoch_number(&self) -> u64;
}

/// No cipher marker.
pub struct NoCipher {}

impl GenericCipher for NoCipher {
    async fn encrypt_record(&mut self, _args: CipherArguments<'_>) -> aead::Result<()> {
        Err(aead::Error)
    }

    async fn decrypt_record<'a>(
        &mut self,
        _ciphertext_header: &DTlsCiphertextHeader<'_>,
        _args: CipherArguments<'a>,
    ) -> aead::Result<&'a [u8]> {
        Err(aead::Error)
    }

    fn tag_size(&self) -> usize {
        0
    }

    fn write_record_number(&self) -> u64 {
        0
    }

    fn increment_write_record_number(&mut self) {}

    fn read_record_number(&self) -> u64 {
        0
    }

    fn epoch_number(&self) -> u64 {
        0
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct CipherArguments<'a> {
    /// The header of the ciphertext.
    pub unified_hdr: UnifiedHeader<'a>,
    /// The location of the payload (plaintext/ciphertext) with the tag at the end.
    pub payload_with_tag: &'a mut [u8],
}

/// Supported client records.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ServerRecord<'a> {
    Handshake(ServerHandshake<'a>, Encryption),
    Alert(/* Alert, */ (), Encryption),
    Ack(Ack<'a>, Encryption),
    Heartbeat(()),
    ApplicationData(/* &'a [u8] */),
}

impl<'a> ServerRecord<'a> {
    /// Create a client hello handshake.
    pub async fn encode_server_hello<'buf>(
        legacy_session_id: &[u8],
        supported_version: DtlsVersions,
        public_key: PublicKey,
        selected_cipher_suite: u16,
        selected_psk_identity: u16,
        key_schedule: &mut impl GenericCipher,
        transcript_hasher: &mut impl GenericHasher,
        buf: &'buf mut EncodingBuffer<'_>,
    ) -> Result<(), ()> {
        let server_hello = ServerHello {
            version: LEGACY_DTLS_VERSION,
            legacy_session_id_echo: &legacy_session_id,
            cipher_suite_index: selected_cipher_suite,
            extensions: NewServerExtensions {
                selected_supported_version: Some(ServerSupportedVersion {
                    version: supported_version,
                }),
                key_share: Some(KeyShareEntry {
                    group: NamedGroup::X25519,
                    opaque: public_key.as_bytes(),
                }),
                pre_shared_key: Some(SelectedPsk {
                    selected_identity: selected_psk_identity,
                }),
            },
        };

        l0g::debug!("Sending server hello: {server_hello:02x?}");

        ServerRecord::Handshake(
            ServerHandshake::ServerHello(server_hello),
            Encryption::Disabled,
        )
        .encode(buf, Some(transcript_hasher), key_schedule)
        .await
    }

    /// Create a server's finished message.
    pub async fn encode_finished(
        verify: &[u8],
        key_schedule: &mut impl GenericCipher,
        transcript_hasher: &mut impl GenericHasher,
        buf: &mut EncodingBuffer<'_>,
    ) -> Result<(), ()> {
        let finished = ServerRecord::Handshake(
            ServerHandshake::ServerFinished(Finished { verify }),
            Encryption::Enabled,
        );

        l0g::debug!("Sending server finished: {finished:02x?}");

        finished
            .encode(buf, Some(transcript_hasher), key_schedule)
            .await
    }

    /// Create a server's ACK message.
    pub async fn encode_ack(
        record_numbers: &[RecordNumber],
        key_schedule: &mut impl GenericCipher,
        buf: &mut EncodingBuffer<'_>,
    ) -> Result<(), ()> {
        let ack = Ack {
            record_numbers: EncodeOrParse::Encode(record_numbers),
        };

        l0g::debug!("Sending server ACK: {ack:?}");

        ServerRecord::Ack(ack, Encryption::Enabled)
            .encode::<NoHasher>(buf, None, key_schedule)
            .await
            .map(|_| ())
    }

    /// Encode the record into a buffer. Returns (packet to send, content to hash).
    pub async fn encode<'buf, Hasher: GenericHasher>(
        &self,
        buf: &'buf mut EncodingBuffer<'_>,
        transcript_hasher: Option<&mut Hasher>,
        cipher: &mut impl GenericCipher,
    ) -> Result<(), ()> {
        encode_record(
            buf,
            cipher,
            self.is_encrypted(),
            self.content_type(),
            |buf| self.encode_content(transcript_hasher, buf),
        )
        .await
    }

    fn encode_content<'buf>(
        &self,
        transcript_hasher: Option<&mut impl GenericHasher>,
        buf: &'buf mut EncodingBuffer,
    ) -> Result<(), ()> {
        let start = buf.current_pos_ptr();

        match self {
            // NOTE: Each record encoder needs to update the transcript hash at their end.
            ServerRecord::Handshake(handshake, _) => handshake.encode(buf)?,
            ServerRecord::Alert(_, _) => todo!(),
            ServerRecord::Heartbeat(_) => todo!(),
            ServerRecord::Ack(ack, _) => ack.encode(buf)?,
            ServerRecord::ApplicationData() => todo!(),
        }

        let end = buf.current_pos_ptr();

        if let Some(hasher) = transcript_hasher {
            hasher.update(
                RecordPayloadPositions {
                    start,
                    binders: None,
                    end,
                }
                .as_slice(&buf)
                .ok_or(())?,
            );
        }

        Ok(())
    }

    fn is_encrypted(&self) -> bool {
        match self {
            ServerRecord::Handshake(_, Encryption::Disabled)
            | ServerRecord::Alert(_, Encryption::Disabled)
            | ServerRecord::Ack(_, Encryption::Disabled) => false,
            _ => true,
        }
    }

    fn content_type(&self) -> ContentType {
        match self {
            ServerRecord::Handshake(_, _) => ContentType::Handshake,
            ServerRecord::Alert(_, _) => ContentType::Alert,
            ServerRecord::Ack(_, _) => ContentType::Ack,
            ServerRecord::Heartbeat(_) => ContentType::Heartbeat,
            ServerRecord::ApplicationData() => ContentType::ApplicationData,
        }
    }

    /// Parse a `ServerRecord`. The incoming `buf` will be reduced to not include what's been
    /// parsed after finishing, allowing for parse to be called multiple times.
    ///
    /// If a transcript hasher is supplied, then the hashing will be performed over the plaintext.
    pub async fn parse<Hash>(
        buf: &mut &'a mut [u8],
        transcript_hasher: Option<&mut Hash>,
        cipher: &mut impl GenericCipher,
    ) -> Option<ServerRecord<'a>>
    where
        Hash: Digest,
    {
        let r = parse_record(buf, Some(cipher), |content_type, encryption, buf| {
            // Perform transcript hashing.
            if let Some(hasher) = transcript_hasher {
                hasher.update(buf.as_ref())
            }

            Self::parse_content(content_type, encryption, buf)
        })
        .await;

        if let Some(out) = &r {
            l0g::trace!("Parsed {out:?}");
        }

        r.map(|s| s.0)
    }

    fn parse_content(
        content_type: ContentType,
        encryption: Encryption,
        buf: &mut ParseBuffer<'a>,
    ) -> Option<Self> {
        Some(match content_type {
            ContentType::Handshake => {
                let handshake = ServerHandshake::parse(buf)?;
                ServerRecord::Handshake(handshake, encryption)
            }
            ContentType::Ack => {
                let ack = Ack::parse(buf)?;
                ServerRecord::Ack(ack, encryption)
            }
            ContentType::Heartbeat => todo!(),
            ContentType::Alert => todo!(),
            ContentType::ApplicationData => todo!(),
            ContentType::ChangeCipherSpec => todo!(),
        })
    }
}

fn to_header_and_payload_with_tag(
    buf: &mut [u8],
    header_position: Range<usize>,
    plaintext_position: Range<usize>,
    tag_position: Range<usize>,
) -> (&mut [u8], &mut [u8]) {
    l0g::trace!(
        "hp: {header_position:?}, pp: {plaintext_position:?}, tp: {tag_position:?}, bl: {}",
        buf.len()
    );

    // Enforce the ordering for tests.
    if !(header_position.start <= header_position.end
        && header_position.end <= plaintext_position.start
        && plaintext_position.start <= plaintext_position.end
        && plaintext_position.end <= tag_position.start
        && tag_position.start <= tag_position.end
        && plaintext_position.end == tag_position.start
        && tag_position.end <= buf.len())
    {
        panic!(
            "The order of data in the encryption is wrong or longer than the buffer they stem from: hp: {header_position:?}, pp: {plaintext_position:?}, tp: {tag_position:?}, bl: {}", buf.len()
        );
    }

    // We want to do this, but we can't due to the borrow checker:
    // (
    //     &mut buf[sequence_number_position],
    //     &mut buf[plaintext_position.start..tag_position.end],
    // )

    let mut curr_start = 0;

    // Extract sequence number slice.
    let (_, r) = buf.split_at_mut(header_position.start);
    curr_start += header_position.start;

    let (sequence_number, r) = r.split_at_mut(header_position.end - curr_start);
    curr_start += header_position.end - curr_start;

    // Extract plaintext slice compounded with the tag slice.
    let (_, r) = r.split_at_mut(plaintext_position.start - curr_start);
    curr_start += plaintext_position.start - curr_start;

    let (plaintext_with_tag, _) = r.split_at_mut(tag_position.end - curr_start);

    (sequence_number, plaintext_with_tag)
}

/// Protocol version definition.
pub type ProtocolVersion = [u8; 2];

/// Value used for protocol version in DTLS 1.3.
pub const LEGACY_DTLS_VERSION: ProtocolVersion = [254, 253];

/// Helper to parse DTLS headers.
#[derive(Debug)]
pub enum DTlsHeader<'a> {
    Plaintext(DTlsPlaintextHeader),
    Ciphertext(DTlsCiphertextHeader<'a>),
}

impl<'a> DTlsHeader<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<Self> {
        let mut pt_buf = buf.clone(); // We need 2 parse buffers.

        if let Some(h) = DTlsCiphertextHeader::parse(buf) {
            Some(DTlsHeader::Ciphertext(h))
        } else if let Some(h) = DTlsPlaintextHeader::parse(&mut pt_buf) {
            *buf = pt_buf;
            Some(DTlsHeader::Plaintext(h))
        } else {
            None
        }
    }
}

/// DTls 1.3 plaintext header.
#[derive(Debug, PartialEq, Eq)]
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

/// DTlsCiphertext unified header.
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DTlsCiphertextHeader<'a> {
    /// The shortened 2-bit epoch number of this record.
    // TODO: Make epoc only representable as 2 bits.
    pub epoch: u8,
    /// The shortened sequence number of this record.
    pub sequence_number: CiphertextSequenceNumber,
    /// The optional length of this record. If it's not provided then the size is extracted from
    /// the datagram. If there are many records in a single datagram then the length is required.
    /// See section 4.2 in RFC9147 for details.
    pub length: Option<u16>,
    /// The optional connection ID.
    pub connection_id: Option<&'a [u8]>,
}

impl<'a> DTlsCiphertextHeader<'a> {
    //
    //  0 1 2 3 4 5 6 7
    // +-+-+-+-+-+-+-+-+
    // |0|0|1|C|S|L|E E|
    // +-+-+-+-+-+-+-+-+
    // | Connection ID |   Legend:
    // | (if any,      |
    // /  length as    /   C   - Connection ID (CID) present
    // |  negotiated)  |   S   - Sequence number length
    // +-+-+-+-+-+-+-+-+   L   - Length present
    // |  8 or 16 bit  |   E   - Epoch
    // |Sequence Number|
    // +-+-+-+-+-+-+-+-+
    // | 16 bit Length |
    // | (if present)  |
    // +-+-+-+-+-+-+-+-+
    //
    // struct {
    //     opaque unified_hdr[variable];
    //     opaque encrypted_record[length];
    // } DTLSCiphertext;

    /// Encode a DTlsCiphertext unified header, return the sequence number location in the buffer
    /// and allocation for the length field in case the length is not `None`.
    ///
    /// Follows section 4 in RFC9147.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<Option<AllocU16Handle>, ()> {
        let header = {
            let epoch = self.epoch & 0b11;
            let length = match self.length {
                Some(_) => 1 << 2,
                None => 0,
            };
            let seq_num = match self.sequence_number {
                CiphertextSequenceNumber::Short(_) => 0,
                CiphertextSequenceNumber::Long(_) => 1 << 3,
            };
            let cid = match self.connection_id {
                Some(_) => 1 << 4,
                None => 0,
            };
            0b00100000 | epoch | length | seq_num | cid
        };

        buf.push_u8(header)?;

        if let Some(cid) = self.connection_id {
            buf.extend_from_slice(cid)?;
        }

        match self.sequence_number {
            CiphertextSequenceNumber::Short(s) => buf.push_u8(s)?,
            CiphertextSequenceNumber::Long(l) => buf.push_u16_be(l)?,
        }

        if self.length.is_some() {
            Ok(Some(buf.alloc_u16()?))
        } else {
            Ok(None)
        }
    }

    /// Parse a ciphertext header.
    pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
        let header = buf.pop_u8()?;

        // Check the header bits that this is actually a ciphertext.
        if header >> 5 != 0b001 {
            l0g::error!("Not a ciphertext, header = {header:02x}");
            return None;
        }

        let epoch = header & 0b11;
        let connection_id = if (header >> 4) & 1 != 0 {
            // TODO: No support for CID for now.
            l0g::error!("Ciphertext specified CID, we don't support that");
            return None;
        } else {
            None
        };
        let sequence_number = if (header >> 3) & 1 != 0 {
            CiphertextSequenceNumber::Long(buf.pop_u16_be()?)
        } else {
            CiphertextSequenceNumber::Short(buf.pop_u8()?)
        };
        let length = if (header >> 2) & 1 != 0 {
            Some(buf.pop_u16_be()?)
        } else {
            None
        };

        Some(Self {
            epoch,
            sequence_number,
            length,
            connection_id,
        })
    }
}

// struct {
//      opaque content[DTLSPlaintext.length];
//      ContentType type;
//      uint8 zeros[length_of_padding];
// } DTLSInnerPlaintext;

/// The payload within the `encrypted_record` in a DTLSCiphertext.
#[derive(Debug)]
pub struct DtlsInnerPlaintext<'a> {
    pub content: &'a [u8], // Only filled on decode.
    pub type_: ContentType,
}

impl<'a> DtlsInnerPlaintext<'a> {
    /// Encode a DTlsInnerPlaintext.
    ///
    /// Follows section 4 in RFC9147.
    pub fn encode(
        type_: ContentType,
        buf: &mut EncodingBuffer,
        content_size: usize,
        aead_tag_size: usize,
    ) -> Result<(), ()> {
        buf.push_u8(type_ as u8)?;

        // In accordance with Section 4.2.3 in RFC9147 we need that the cipher text, including tag,
        // to have a minimum of 16 bytes length. Else we must pad the packet. Usually the tag is
        // large enough to not need any padding.
        let padding_size = 16usize.saturating_sub(aead_tag_size + content_size + 1);
        for _ in 0..padding_size {
            buf.push_u8(0)?;
        }

        Ok(())
    }

    /// Parse a DtlsInnerPlaintext.
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<Self> {
        let payload = buf.pop_rest();

        // Remove padding.
        let no_padding = Self::remove_trailing_zeros(payload);

        let (last, content) = no_padding.split_last()?;

        Some(Self {
            content,
            type_: ContentType::try_from(*last).ok()?,
        })
    }

    fn remove_trailing_zeros(slice: &[u8]) -> &[u8] {
        if let Some(last_non_zero_pos) = slice.iter().rposition(|&x| x != 0) {
            &slice[..=last_non_zero_pos]
        } else {
            &[]
        }
    }
}

/// The two types of sequence numbers supported by the DTls ciphertext unified header.
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CiphertextSequenceNumber {
    /// Short single byte sequence number.
    Short(u8),
    /// Long two byte sequence number.
    Long(u16),
}

impl CiphertextSequenceNumber {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 1 {
            Some(CiphertextSequenceNumber::Short(bytes[0]))
        } else if bytes.len() == 2 {
            Some(CiphertextSequenceNumber::Long(u16::from_be_bytes(
                bytes.try_into().unwrap(),
            )))
        } else {
            None
        }
    }
}

impl From<CiphertextSequenceNumber> for u64 {
    fn from(value: CiphertextSequenceNumber) -> Self {
        match value {
            CiphertextSequenceNumber::Short(s) => s as u64,
            CiphertextSequenceNumber::Long(l) => l as u64,
        }
    }
}

/// TLS content type. RFC 9147 - Appendix A.1
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq, Eq, TryFromPrimitive)]
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

/// Encode the record into a buffer. Returns (packet to send, content to hash).
pub async fn encode_record<'buf, Ret>(
    buf: &'buf mut EncodingBuffer<'_>,
    cipher: &mut impl GenericCipher,
    is_encrypted: bool,
    content_type: ContentType,
    encode_content: impl FnOnce(&mut EncodingBuffer) -> Result<Ret, ()>,
) -> Result<Ret, ()> {
    let epoch = cipher.epoch_number();
    let record_number = cipher.write_record_number();

    let r = if is_encrypted {
        encode_ciphertext(
            buf,
            cipher,
            content_type,
            epoch as u8,
            CiphertextSequenceNumber::Long(record_number as u16),
            encode_content,
        )
        .await?
    } else {
        encode_plaintext(
            buf,
            content_type,
            epoch as u16,
            record_number.into(), // TODO: Check if we should protect here
            encode_content,
        )?
    };

    cipher.increment_write_record_number();

    Ok(r)
}

/// Parses a record and returns the parsed content and the payload buffer that was used for parsing.
pub async fn parse_record<'a, Content>(
    buf: &mut &'a mut [u8],
    cipher: Option<&mut impl GenericCipher>,
    parse_content: impl FnOnce(ContentType, Encryption, &mut ParseBuffer<'a>) -> Option<Content>,
) -> Option<(Content, &'a [u8])>
where
    Content: 'a,
{
    let is_ciphertext = buf.first()? >> 5 == 0b001;

    if is_ciphertext {
        let cipher = cipher?;

        let (unified_hdr, payload_with_tag, header) = {
            // Find payload size.
            let pb = &mut ParseBuffer::new(buf);
            let header = DTlsCiphertextHeader::parse(pb)?;
            let header_length = buf.len() - pb.len();
            l0g::trace!(
                "ciphertext header len = {header_length}, payload length = {:?}",
                header.length
            );

            // If the length is not specified, then the payload is the full datagram.
            let payload_length = if let Some(payload_length) = header.length {
                if pb.len() < payload_length as usize {
                    return None;
                }

                payload_length as usize
            } else {
                pb.len()
            };

            // Split the buffer into what should be parsed.
            let b = core::mem::replace(buf, &mut []);
            let (to_parse, next_datagram) = b.split_at_mut(header_length + payload_length as usize);
            let _ = core::mem::replace(buf, next_datagram);

            // Split into header and payload.
            let (unified_hdr, payload) = to_parse.split_at_mut(header_length);
            (unified_hdr, payload, header)
        };

        let payload_without_tag = cipher
            .decrypt_record(
                &header,
                CipherArguments {
                    unified_hdr: UnifiedHeader::new(unified_hdr),
                    payload_with_tag,
                },
            )
            .await
            .ok()?;

        let inner_plaintext =
            DtlsInnerPlaintext::parse(&mut ParseBuffer::new(payload_without_tag))?;

        l0g::trace!("Parsed plaintext: {inner_plaintext:02x?}");

        let ret = parse_content(
            inner_plaintext.type_,
            Encryption::Enabled,
            &mut ParseBuffer::new(inner_plaintext.content),
        )?;

        Some((ret, payload_without_tag))
    } else {
        let (to_parse, header, header_length) = {
            // Find payload size.
            let pb = &mut ParseBuffer::new(buf);
            let header = DTlsPlaintextHeader::parse(pb)?;
            let header_length = buf.len() - pb.len();
            l0g::trace!(
                "plaintext header len = {header_length}, payload length = {}",
                header.length
            );

            if pb.len() < header.length as usize {
                return None;
            }

            // Split the buffer into what should be parsed.
            let b = core::mem::replace(buf, &mut []);
            let (to_parse, next_datagram) = b.split_at_mut(header_length + header.length as usize);
            let _ = core::mem::replace(buf, next_datagram);

            (to_parse, header, header_length)
        };

        // Remove the header from future parsing.
        let mut pb = ParseBuffer::new(to_parse);
        pb.pop_slice(header_length);

        let r = parse_plaintext(header, &mut pb, parse_content)?;

        Some((r, to_parse))
    }
}

/// Encode a plaintext.
fn encode_plaintext<'buf, Ret>(
    buf: &'buf mut EncodingBuffer,
    content_type: ContentType,
    epoch: u16,
    sequence_number: U48,
    encode_content: impl FnOnce(&mut EncodingBuffer) -> Result<Ret, ()>,
) -> Result<Ret, ()> {
    let header = DTlsPlaintextHeader {
        type_: content_type,
        epoch,
        sequence_number,
        length: 0, // To be encoded later.
    };
    // Create record header.
    let length_allocation = header.encode(buf)?;

    // ------ Start record

    let (r, content_length) = {
        let mut inner_buf = buf.new_from_existing();

        // ------ Encode payload
        let r = encode_content(&mut inner_buf)?;

        (r, inner_buf.len())
    };

    length_allocation.set(buf, content_length as u16);

    // ------ Finish record
    Ok(r)
}

/// Encode a ciphertext.
async fn encode_ciphertext<'buf, Ret>(
    buf: &'buf mut EncodingBuffer<'_>,
    cipher: &mut impl GenericCipher,
    content_type: ContentType,
    epoch: u8,
    sequence_number: CiphertextSequenceNumber,
    encode_content: impl FnOnce(&mut EncodingBuffer) -> Result<Ret, ()>,
) -> Result<Ret, ()> {
    let buf = &mut buf.new_from_existing();

    let header_start = buf.len();

    // Create record header.
    let length_allocation = DTlsCiphertextHeader {
        epoch,
        sequence_number,
        length: Some(0),
        connection_id: None,
    }
    .encode(buf)?;

    l0g::trace!("encoded header = {:02x?}", buf);

    // ------ Start record

    let content_start = buf.len();
    let header_position = header_start..content_start;

    // ------ Encode payload
    let r = encode_content(buf)?;

    let content_length = buf.len() - content_start;

    // Encode the tail of the DTLSInnerPlaintext.
    DtlsInnerPlaintext::encode(content_type, buf, content_length, cipher.tag_size())?;

    let innerplaintext_end = buf.len();

    // Allocate space for the AEAD tag.
    let aead_tag_allocation = buf.alloc_slice(cipher.tag_size())?;
    let tag_position = aead_tag_allocation.at();
    aead_tag_allocation.fill(buf, 0);

    // Write the ciphertext length to the header.
    let ciphertext_length = buf.len() - content_start;
    if let Some(length_allocation) = length_allocation {
        l0g::trace!("ciphertext length: {ciphertext_length}, {ciphertext_length:02x}, {length_allocation:?}");
        length_allocation.set(buf, ciphertext_length as u16);
    }

    // ------ Encrypt payload
    {
        let plaintext_position = content_start..innerplaintext_end as usize;

        // Split the buffer into the 2 slices.
        let (unified_hdr, payload_with_tag) =
            to_header_and_payload_with_tag(buf, header_position, plaintext_position, tag_position);

        let cipher_args = CipherArguments {
            unified_hdr: UnifiedHeader::new(unified_hdr),
            payload_with_tag,
        };

        cipher.encrypt_record(cipher_args).await.map_err(|_| ())?;
    }

    // ------ Finish record
    l0g::trace!("encoded record = {:02x?}", buf);

    Ok(r)
}

fn parse_plaintext<'a, Content>(
    header: DTlsPlaintextHeader,
    buf: &mut ParseBuffer<'a>,
    parse_content: impl FnOnce(ContentType, Encryption, &mut ParseBuffer<'a>) -> Option<Content>,
) -> Option<Content> {
    let record_payload = buf.pop_slice(header.length.into())?;
    let mut buf = ParseBuffer::new(record_payload);
    let ret = parse_content(header.type_, Encryption::Disabled, &mut buf)?;

    Some(ret)
}

#[cfg(test)]
mod test {
    use super::{ContentType, DTlsPlaintextHeader};
    use crate::{
        buffer::{EncodingBuffer, ParseBuffer},
        record::DTlsCiphertextHeader,
    };

    #[test]
    fn plaintext_header_rount_trip() {
        let header = DTlsPlaintextHeader {
            type_: ContentType::Handshake,
            epoch: 2,
            sequence_number: 123456.into(),
            length: 321,
        };

        let mut buf = [0; 32];
        let buf = &mut EncodingBuffer::new(&mut buf);

        let len_alloc = header.encode(buf).unwrap();
        len_alloc.set(buf, header.length);

        let recv_buf: &[u8] = &buf;

        let parse_buffer = &mut ParseBuffer::new(recv_buf);
        let parsed_header = DTlsPlaintextHeader::parse(parse_buffer).unwrap();

        assert_eq!(header, parsed_header)
    }

    #[test]
    fn ciphertext_header_rount_trip() {
        let header = DTlsCiphertextHeader {
            epoch: 2,
            sequence_number: crate::record::CiphertextSequenceNumber::Long(123),
            length: Some(321),
            connection_id: None,
        };

        let mut buf = [0; 32];
        let buf = &mut EncodingBuffer::new(&mut buf);

        let len_alloc = header.encode(buf).unwrap();
        len_alloc.unwrap().set(buf, header.length.unwrap());

        let recv_buf: &[u8] = &buf;

        let parse_buffer = &mut ParseBuffer::new(recv_buf);
        let parsed_header = DTlsCiphertextHeader::parse(parse_buffer).unwrap();

        assert_eq!(header, parsed_header)
    }
}
