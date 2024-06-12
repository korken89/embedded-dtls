//! A DTLS 1.3 PSK implementation.
//!
//! # Limitations
//!
//! - We only support that the client sends 1 PSK identity for now.
//! - Only X25519 ECDHE
//!
//! # Thanks
//!
//! Heavily inspired by [`embedded-tls`].
//! [`embedded-tls`]: https://github.com/drogue-iot/embedded-tls

#![cfg_attr(not(test), no_std)]
#![allow(async_fn_in_trait)]

use defmt_or_log::{derive_format_or_debug, FormatOrDebug};

pub(crate) mod buffer;
pub(crate) mod cipher_suites;
pub(crate) mod handshake;
pub(crate) mod integers;
pub(crate) mod key_schedule;
pub(crate) mod record;

pub mod client_config {
    use crate::handshake::extensions::Psk;
    use defmt_or_log::derive_format_or_debug;

    /// Client configuration.
    #[derive_format_or_debug]
    pub struct ClientConfig<'a> {
        /// Preshared key.
        /// TODO: Support a list of PSKs. Needs work in how to calculate binders and track all the
        /// necessary early secrets derived from the PSKs until the server selects one PSK.
        pub psk: Psk<'a>,
    }
}

pub mod server_config {
    use defmt_or_log::{derive_format_or_debug, maybe_derive_format};

    /// Pre-shared key identity.
    #[maybe_derive_format]
    #[derive(PartialEq, Eq, Hash)]
    pub struct Identity<'a>(&'a [u8]);

    impl<'a, T> From<&'a T> for Identity<'a>
    where
        T: AsRef<[u8]>,
    {
        fn from(value: &'a T) -> Self {
            Self(value.as_ref())
        }
    }

    impl<'a> Identity<'a> {
        pub(crate) fn as_slice(&self) -> &[u8] {
            self.0
        }
    }

    impl<'a> core::fmt::Debug for Identity<'a> {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            match core::str::from_utf8(self.0) {
                Ok(string) => f.write_str(string),
                Err(_) => {
                    for b in self.0 {
                        write!(f, "{:02x}", b)?;
                    }

                    Ok(())
                }
            }
        }
    }

    /// Pre-shared key value.
    #[derive_format_or_debug]
    pub struct Key<'a>(&'a [u8]);

    impl<'a, T> From<&'a T> for Key<'a>
    where
        T: AsRef<[u8]>,
    {
        fn from(value: &'a T) -> Self {
            Self(value.as_ref())
        }
    }

    impl<'a> Key<'a> {
        pub(crate) fn as_slice(&self) -> &[u8] {
            &self.0
        }
    }

    /// Server configuration.
    pub struct ServerConfig<'a, 'b> {
        /// A list of allowed pre-shared keys.
        ///
        /// The key is the identity and the value is the key.
        pub psk: &'b [(Identity<'a>, Key<'a>)],
    }
}

// The TLS cake
//
// 1. Record layer (fragmentation and such)
// 2. The payload (Handshake, ChangeCipherSpec, Alert, ApplicationData)

#[derive_format_or_debug]
#[derive(Copy, Clone)]
pub enum Error<D: Endpoint> {
    /// The backing buffer ran out of space.
    InsufficientSpace,
    /// Failed to parse a message.
    Parse,
    /// The client hello was invalid.
    InvalidClientHello,
    /// The client finished was invalid.
    InvalidClientFinished,
    /// The server hello was invalid.
    InvalidServerHello,
    /// The server finished was invalid.
    InvalidServerFinished,
    /// The server ACK was invalid.
    InvalidServerAck,
    /// An error related to sending on the socket.
    Send(D::SendError),
    /// An error related to receivnig on the socket.
    Recv(D::ReceiveError),
}

/// Datagram trait, send and receives datagrams from/to a single endpoint.
///
/// This means on `std` that it cannot be implemented directly on a socket, but probably a
/// sender/receiver pair which splits the incoming packets based on IP or similar.
///
/// The debug implementation should indicate the identifier for this endpoint.
pub trait Endpoint: FormatOrDebug {
    /// Error type for sending.
    type SendError: FormatOrDebug;
    /// Error type for receiving.
    type ReceiveError: FormatOrDebug;

    /// Send a complete datagram.
    async fn send(&self, buf: &[u8]) -> Result<(), Self::SendError>;
    /// Receive a complete datagram.
    async fn recv<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], Self::ReceiveError>;
}

// Lives in no_std land.
pub mod client {
    use crate::{
        buffer::EncodingBuffer,
        cipher_suites::DtlsCipherSuite,
        client_config::ClientConfig,
        handshake::ServerHandshake,
        key_schedule::KeySchedule,
        record::{ClientRecord, EncodeOrParse, GenericKeySchedule, ServerRecord},
        Endpoint, Error,
    };
    use defmt_or_log::{debug, error, info, trace, FormatOrDebug};
    use digest::Digest;
    use rand_core::{CryptoRng, RngCore};
    use x25519_dalek::{EphemeralSecret, PublicKey};

    // TODO: How to select between server and client? Typestate, flag or two separate structs?
    /// A DTLS 1.3 connection.
    pub struct ClientConnection<Socket, CipherSuite>
    where
        CipherSuite: DtlsCipherSuite,
    {
        /// Sender/receiver of data.
        socket: Socket,
        /// Cipher and keys for client->server and server->client communication.
        key_schedule: KeySchedule<CipherSuite, false>,
    }

    impl<Socket, CipherSuite> ClientConnection<Socket, CipherSuite>
    where
        Socket: Endpoint,
        CipherSuite: DtlsCipherSuite + FormatOrDebug,
    {
        /// Open a DTLS 1.3 client connection.
        /// This returns an active connection after handshake is completed.
        ///
        /// NOTE: This does not do timeout, it's up to the caller to give up.
        pub async fn open_client<Rng>(
            rng: &mut Rng,
            buf: &mut [u8],
            socket: Socket,
            cipher: <CipherSuite as DtlsCipherSuite>::Cipher, // TODO: Should this be &mut ?
            config: &ClientConfig<'_>,
        ) -> Result<Self, Error<Socket>>
        where
            Rng: RngCore + CryptoRng,
        {
            info!("Starting handshake for client connection {:?}", socket);

            let mut key_schedule = KeySchedule::new_client(cipher);
            let mut transcript_hasher = <CipherSuite::Hash as Digest>::new();

            // Initialize key-schedule for generating binders.
            key_schedule.initialize_early_secret(Some(config.psk.clone()));

            // Generate our ephemeral key for key exchange.
            let secret_key = EphemeralSecret::random_from_rng(&mut *rng);
            let our_public_key = PublicKey::from(&secret_key);

            // Send ClientHello.
            {
                let mut ser_buf = EncodingBuffer::new(buf);
                let positions = ClientRecord::encode_client_hello::<CipherSuite, _>(
                    &mut ser_buf,
                    config,
                    &our_public_key,
                    rng,
                    &mut key_schedule,
                )
                .await
                .map_err(|_| Error::InsufficientSpace)?;

                // Write binders.
                if let Some((up_to_binders, binders)) = positions.pre_post_binders_mut(&mut ser_buf)
                {
                    transcript_hasher.update(up_to_binders);
                    let binder_entry =
                        key_schedule.create_binder(&transcript_hasher.clone().finalize());

                    let mut binders_enc = EncodingBuffer::new(binders);
                    binders_enc.push_u8(binder_entry.len() as u8).unwrap();
                    binders_enc.extend_from_slice(&binder_entry).unwrap();

                    transcript_hasher.update(&binders_enc);
                } else {
                    // TODO: As we only support PSK right now, we don't really exercise this path.
                    let buf = positions.as_slice(&ser_buf).expect("UNREACHABLE");
                    transcript_hasher.update(buf);
                }

                trace!(
                    "Client transcript after client hello: {:?}",
                    transcript_hasher.clone().finalize()
                );

                socket.send(&ser_buf).await.map_err(|e| Error::Send(e))?;
            }

            // Wait for response (ServerHello and Finished).
            {
                let mut resp = socket.recv(buf).await.map_err(|e| Error::Recv(e))?;
                trace!("Got datagram!");

                // Parse and validate ServerHello.
                // let mut parse_buffer = ParseBufferMut::new(resp);

                let shared_secret = {
                    let server_hello =
                        if let ServerRecord::Handshake(ServerHandshake::ServerHello(hello), _) =
                            ServerRecord::parse(
                                &mut resp,
                                Some(&mut transcript_hasher),
                                &mut key_schedule,
                            )
                            .await
                            .ok_or(Error::InvalidServerHello)?
                        {
                            hello
                        } else {
                            return Err(Error::InvalidServerHello);
                        };

                    trace!(
                        "Client transcript after server hello: {:?}",
                        transcript_hasher.clone().finalize()
                    );

                    // Update key schedule to Handshake Secret using public keys.
                    let their_public_key = server_hello
                        .validate()
                        .map_err(|_| Error::InvalidServerHello)?;

                    secret_key.diffie_hellman(&their_public_key)
                };

                key_schedule.initialize_handshake_secret(
                    shared_secret.as_bytes(),
                    &transcript_hasher.clone().finalize(),
                );

                // Check if we got more datagrams, we're expecting a finished.
                let expected_verify =
                    key_schedule.create_verify_data(&transcript_hasher.clone().finalize(), true);
                let finished = {
                    let mut buf = if resp.is_empty() {
                        // Wait for finished.
                        socket.recv(buf).await.map_err(|e| Error::Recv(e))?
                    } else {
                        resp
                    };

                    if let ServerRecord::Handshake(ServerHandshake::ServerFinished(fin), _) =
                        ServerRecord::parse::<CipherSuite::Hash>(
                            &mut buf,
                            Some(&mut transcript_hasher),
                            &mut key_schedule,
                        )
                        .await
                        .ok_or(Error::InvalidServerFinished)?
                    {
                        fin
                    } else {
                        return Err(Error::InvalidServerFinished);
                    }
                };

                if expected_verify.as_ref() != finished.verify {
                    error!("Server finished does not match transcript");
                    return Err(Error::InvalidServerFinished);
                }

                debug!("Server finished MATCHES expected transcript");
            }

            // Send finished.
            {
                let ser_buf = &mut EncodingBuffer::new(buf);

                let verify =
                    key_schedule.create_verify_data(&transcript_hasher.clone().finalize(), false);

                // Add the Finished message to this datagram.
                ClientRecord::encode_finished(ser_buf, &mut key_schedule, &verify)
                    .await
                    .map_err(|_| Error::InsufficientSpace)?;

                socket.send(&ser_buf).await.map_err(|e| Error::Send(e))?;
            }

            // Update key schedule to Master Secret.
            key_schedule.initialize_master_secret(&transcript_hasher.clone().finalize());

            // Wait for server ACK.
            {
                let mut ack = socket.recv(buf).await.map_err(|e| Error::Recv(e))?;

                let ack = if let ServerRecord::Ack(ack, _) =
                    ServerRecord::parse::<CipherSuite::Hash>(&mut ack, None, &mut key_schedule)
                        .await
                        .ok_or(Error::InvalidServerFinished)?
                {
                    ack
                } else {
                    return Err(Error::InvalidServerFinished);
                };

                debug!("Got server ACK");
                trace!("{:?}", ack);
                let EncodeOrParse::Parse(record_numbers) = ack.record_numbers else {
                    panic!("ACK: Expected parse, got encode");
                };

                if record_numbers.is_empty() {
                    error!("There was no record number in the handshake ACK");
                    return Err(Error::InvalidServerAck);
                }

                for record_number in record_numbers {
                    if record_number.epoch != key_schedule.epoch_number() {
                        return Err(Error::InvalidServerAck);
                    }

                    // TODO: Should we check sequence number?
                }
            }

            info!("New client connection created for {:?}", socket);

            Ok(ClientConnection {
                socket,
                key_schedule,
            })
        }
    }
}

// Lives in std land.
pub mod server {
    use crate::{
        buffer::EncodingBuffer,
        cipher_suites::{ChaCha20Poly1305Cipher, DtlsEcdhePskWithChacha20Poly1305Sha256},
        handshake::{
            extensions::{DtlsVersions, Psk},
            ClientHandshake,
        },
        key_schedule::KeySchedule,
        record::{
            CipherArguments, ClientRecord, DTlsCiphertextHeader, GenericKeySchedule,
            GenericTranscript, NoKeySchedule, RecordNumber, ServerRecord,
        },
        server_config::{Identity, Key, ServerConfig},
        Endpoint, Error,
    };
    use defmt_or_log::{debug, error, info, trace};
    use digest::Digest;
    use heapless::Vec as HVec;
    use rand_core::{CryptoRng, RngCore};
    use sha2::Sha256;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    /// The maximum hash size the server supports. If we start using larger hashes, update this
    /// constant.
    const MAX_HASH_SIZE: usize = 32;

    // TODO: How to select between server and client? Typestate, flag or two separate structs?
    /// A DTLS 1.3 connection.
    pub struct ServerConnection<Socket> {
        /// Sender/receiver of data.
        socket: Socket,
        /// Keys for client->server and server->client. Also called "key schedule".
        key_schedule: ServerKeySchedule,
    }

    impl<Socket> ServerConnection<Socket>
    where
        Socket: Endpoint,
    {
        /// Open a DTLS 1.3 server connection.
        /// This returns an active connection after handshake is completed.
        ///
        /// NOTE: This does not do timeout, it's up to the caller to give up.
        pub async fn open_server<Rng>(
            socket: Socket,
            server_config: &ServerConfig<'_, '_>,
            rng: &mut Rng,
            buf: &mut [u8],
        ) -> Result<Self, Error<Socket>>
        where
            Rng: RngCore + CryptoRng,
        {
            // TODO: If any part fails with error, make sure to send the correct ALERT.
            info!("Starting handshake for server connection {:?}", socket);

            let mut resp = socket.recv(buf).await.map_err(|e| Error::Recv(e))?;
            trace!("Got datagram!");

            let (client_hello, positions, buffer_that_was_parsed) = {
                let record = ClientRecord::parse::<NoKeySchedule>(&mut resp, None)
                    .await
                    .ok_or(Error::InvalidClientHello)?;

                if let (
                    (ClientRecord::Handshake(ClientHandshake::ClientHello(hello), _), pos),
                    buf,
                ) = record
                {
                    (hello, pos, buf)
                } else {
                    return Err(Error::InvalidClientHello);
                }
            };

            // Find the first supported cipher suite.
            let (mut key_schedule, selected_cipher_suite) = {
                let mut r = None;
                for (index, cipher_suite) in client_hello
                    .cipher_suites
                    .chunks_exact(2)
                    .map(|chunk| u16::from_be_bytes(chunk.try_into().unwrap()))
                    .enumerate()
                {
                    // Check so we can support this cipher suite.
                    if let Some(key_schedule) =
                        ServerKeySchedule::try_from_cipher_suite(cipher_suite)
                    {
                        r = Some((key_schedule, index));
                    }
                }

                // TODO: This should generate an alert.
                r.ok_or(Error::InvalidClientHello)?
            };

            // At this point we know the selected cipher suite, and hence also the hash function.
            // Now we can generate transcript hashes for binders and the message in total.
            let mut transcript_hasher = key_schedule.new_transcript_hasher();
            {
                let binders_transcript_hash = {
                    let (up_to_binders, binders_and_rest) = positions
                        .pre_post_binders(buffer_that_was_parsed)
                        .ok_or(Error::InvalidClientHello)?;

                    transcript_hasher.update(up_to_binders);
                    let binders_transcript_hash = transcript_hasher.clone().finalize();
                    transcript_hasher.update(binders_and_rest);
                    binders_transcript_hash
                };

                trace!(
                    "Server transcript after client hello: {:?}",
                    transcript_hasher.clone().finalize()
                );

                let their_public_key = client_hello
                    .validate_and_initialize_keyschedule(
                        &mut key_schedule,
                        server_config,
                        &binders_transcript_hash,
                    )
                    .map_err(|_| Error::InvalidClientHello)?;

                // Perform ECDHE -> Handshake Secret with Key Schedule
                // TODO: For now we assume X25519.
                let secret = EphemeralSecret::random();
                let our_public_key = PublicKey::from(&secret);
                let shared_secret = secret.diffie_hellman(&their_public_key);

                // Send server hello.
                let legacy_session_id: HVec<u8, 32> =
                    HVec::from_slice(client_hello.legacy_session_id)
                        .map_err(|_| Error::InsufficientSpace)?;

                // TODO: Can we move this up somehow?
                if !resp.is_empty() {
                    error!("More data after client hello");
                    return Err(Error::InvalidClientHello);
                }

                // TODO: We hardcode the selected PSK as the first one for now.
                let mut enc_buf = EncodingBuffer::new(buf);
                ServerRecord::encode_server_hello(
                    &legacy_session_id,
                    DtlsVersions::V1_3,
                    our_public_key,
                    selected_cipher_suite as u16,
                    0,
                    rng,
                    &mut key_schedule,
                    &mut transcript_hasher,
                    &mut enc_buf,
                )
                .await
                .map_err(|_| Error::InsufficientSpace)?;

                trace!(
                    "Server transcript after server hello: {:?}",
                    transcript_hasher.clone().finalize()
                );

                key_schedule.initialize_handshake_secret(
                    shared_secret.as_bytes(),
                    &transcript_hasher.clone().finalize(),
                );

                // Add the Finished message to this datagram.
                let verify =
                    key_schedule.create_verify_data(&transcript_hasher.clone().finalize(), true);
                ServerRecord::encode_finished(
                    &verify,
                    &mut key_schedule,
                    &mut transcript_hasher,
                    &mut enc_buf,
                )
                .await
                .map_err(|_| Error::InsufficientSpace)?;

                socket.send(&enc_buf).await.map_err(|e| Error::Send(e))?;
            }

            // Finished from client
            {
                let mut resp = socket.recv(buf).await.map_err(|e| Error::Recv(e))?;

                // Check if we got more datagrams, we're expecting a finished.
                let expected_verify =
                    key_schedule.create_verify_data(&transcript_hasher.clone().finalize(), false);

                let finished = {
                    if let (
                        (ClientRecord::Handshake(ClientHandshake::ClientFinished(fin), _), _),
                        _,
                    ) = ClientRecord::parse(&mut resp, Some(&mut key_schedule))
                        .await
                        .ok_or(Error::InvalidClientFinished)?
                    {
                        fin
                    } else {
                        return Err(Error::InvalidClientFinished);
                    }
                };

                if expected_verify != finished.verify {
                    error!("Client finished does not match transcript");
                    return Err(Error::InvalidServerFinished);
                }

                debug!("Client finished MATCHES expected transcript");
            }

            // Update key schedule to Master Secret.
            key_schedule.initialize_master_secret(&transcript_hasher.clone().finalize());

            // Send ACK.
            {
                let mut enc_buf = EncodingBuffer::new(buf);
                let sequence_number = key_schedule.read_record_number();
                let epoch = key_schedule.epoch_number();

                ServerRecord::encode_ack(
                    &[RecordNumber {
                        epoch,
                        sequence_number,
                    }],
                    &mut key_schedule,
                    &mut enc_buf,
                )
                .await
                .map_err(|_| Error::InsufficientSpace)?;

                socket.send(&enc_buf).await.map_err(|e| Error::Send(e))?;
            }

            // Handshake complete!
            info!("New server connection created for {:?}", socket);

            Ok(ServerConnection {
                socket,
                key_schedule,
            })
        }
    }

    pub enum ServerKeySchedule {
        /// Key schedule for the Chacha20Poly1305 cipher suite.
        Chacha20Poly1305Sha256(KeySchedule<DtlsEcdhePskWithChacha20Poly1305Sha256, true>),
    }

    impl ServerKeySchedule {
        pub fn is_uninitialized(&self) -> bool {
            match self {
                ServerKeySchedule::Chacha20Poly1305Sha256(v) => v.is_uninitialized(),
            }
        }

        pub fn new_transcript_hasher(&self) -> TranscriptHasher {
            match self {
                ServerKeySchedule::Chacha20Poly1305Sha256(_) => {
                    TranscriptHasher::Sha256(Sha256::default())
                }
            }
        }

        pub fn try_from_cipher_suite(cipher_suites: u16) -> Option<Self> {
            Some(match cipher_suites {
                // TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
                0xCCAC => ServerKeySchedule::Chacha20Poly1305Sha256(KeySchedule::new_server(
                    ChaCha20Poly1305Cipher::default(),
                )),
                _ => {
                    trace!("Detected unsupported cipher suite {:?}", cipher_suites);
                    return None;
                }
            })
        }

        pub fn initialize_early_secret(&mut self, psk: Option<(&Identity, &Key)>) {
            match self {
                ServerKeySchedule::Chacha20Poly1305Sha256(key_schedule) => key_schedule
                    .initialize_early_secret(psk.map(|p| Psk {
                        identity: p.0.as_slice(),
                        key: p.1.as_slice(),
                    })),
            }
        }

        pub fn create_binder(&self, transcript_hash: &[u8]) -> HVec<u8, MAX_HASH_SIZE> {
            match self {
                ServerKeySchedule::Chacha20Poly1305Sha256(key_schedule) => {
                    HVec::from_slice(key_schedule.create_binder(transcript_hash).as_slice())
                        .unwrap()
                }
            }
        }

        pub fn create_verify_data(
            &self,
            transcript_hash: &[u8],
            use_server_key: bool,
        ) -> HVec<u8, MAX_HASH_SIZE> {
            match self {
                ServerKeySchedule::Chacha20Poly1305Sha256(key_schedule) => HVec::from_slice(
                    key_schedule
                        .create_verify_data(transcript_hash, use_server_key)
                        .as_slice(),
                )
                .unwrap(),
            }
        }

        pub fn initialize_handshake_secret(&mut self, ecdhe: &[u8], transcript: &[u8]) {
            match self {
                ServerKeySchedule::Chacha20Poly1305Sha256(key_schedule) => {
                    key_schedule.initialize_handshake_secret(ecdhe, transcript);
                }
            }
        }

        fn initialize_master_secret(&mut self, transcript: &[u8]) {
            match self {
                ServerKeySchedule::Chacha20Poly1305Sha256(key_schedule) => {
                    key_schedule.initialize_master_secret(transcript);
                }
            }
        }
    }

    // All server ciphers must implement `GenericCipher`.
    impl GenericKeySchedule for ServerKeySchedule {
        async fn encrypt_record(&mut self, args: CipherArguments<'_>) -> aead::Result<()> {
            match self {
                ServerKeySchedule::Chacha20Poly1305Sha256(cipher) => {
                    cipher.encrypt_record(args).await
                }
            }
        }

        async fn decrypt_record<'a>(
            &mut self,
            ciphertext_header: &DTlsCiphertextHeader<'_>,
            args: CipherArguments<'a>,
        ) -> aead::Result<&'a [u8]> {
            match self {
                ServerKeySchedule::Chacha20Poly1305Sha256(cipher) => {
                    cipher.decrypt_record(ciphertext_header, args).await
                }
            }
        }

        fn tag_size(&self) -> usize {
            match self {
                ServerKeySchedule::Chacha20Poly1305Sha256(cipher) => cipher.tag_size(),
            }
        }

        fn write_record_number(&self) -> u64 {
            match self {
                ServerKeySchedule::Chacha20Poly1305Sha256(cipher) => cipher.write_record_number(),
            }
        }

        fn increment_write_record_number(&mut self) {
            match self {
                ServerKeySchedule::Chacha20Poly1305Sha256(cipher) => {
                    cipher.increment_write_record_number()
                }
            }
        }

        fn read_record_number(&self) -> u64 {
            match self {
                ServerKeySchedule::Chacha20Poly1305Sha256(cipher) => cipher.read_record_number(),
            }
        }

        fn epoch_number(&self) -> u64 {
            match self {
                ServerKeySchedule::Chacha20Poly1305Sha256(cipher) => cipher.epoch_number(),
            }
        }
    }

    /// This is used to get the transcript hashes, it stems from the
    #[derive(Clone, Debug)]
    pub enum TranscriptHasher {
        Sha256(Sha256),
    }

    impl GenericTranscript for TranscriptHasher {
        fn update(&mut self, data: &[u8]) {
            self.update(data);
        }
    }

    impl TranscriptHasher {
        pub fn update(&mut self, data: impl AsRef<[u8]>) {
            match self {
                TranscriptHasher::Sha256(h) => Digest::update(h, data),
            }
        }

        pub fn finalize(self) -> HVec<u8, MAX_HASH_SIZE> {
            match self {
                TranscriptHasher::Sha256(h) => HVec::from_slice(h.finalize().as_slice()).unwrap(),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;
    use crate::{
        cipher_suites::{ChaCha20Poly1305Cipher, DtlsEcdhePskWithChacha20Poly1305Sha256},
        client::ClientConnection,
        client_config::ClientConfig,
        handshake::extensions::Psk,
        server::ServerConnection,
        server_config::ServerConfig,
    };
    use defmt_or_log::trace;
    use rand::{rngs::StdRng, SeedableRng};
    use tokio::sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    };

    struct ChannelSocket {
        who: &'static str,
        rx: Mutex<Receiver<Vec<u8>>>,
        tx: Sender<Vec<u8>>,
    }

    impl core::fmt::Debug for ChannelSocket {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Socket {{ who: {} }}", self.who)
        }
    }

    impl Endpoint for ChannelSocket {
        type SendError = ();
        type ReceiveError = ();

        async fn send(&self, buf: &[u8]) -> Result<(), Self::SendError> {
            let r = self.tx.send(buf.into()).await;
            trace!(
                "{} send ({}) (r = {r:?}): {:02x?}",
                self.who,
                buf.len(),
                buf
            );

            r.map_err(|_| ())
        }

        async fn recv<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], Self::ReceiveError> {
            let r = self.rx.lock().await.recv().await.ok_or(())?;

            buf[..r.len()].copy_from_slice(&r);

            Ok(&mut buf[..r.len()])
        }
    }

    fn make_server_client_channel() -> (ChannelSocket, ChannelSocket) {
        let (s1, r1) = channel(10);
        let (s2, r2) = channel(10);

        (
            ChannelSocket {
                who: "server",
                rx: Mutex::new(r1),
                tx: s2,
            },
            ChannelSocket {
                who: "client",
                rx: Mutex::new(r2),
                tx: s1,
            },
        )
    }

    #[tokio::test]
    async fn open_connection() {
        simple_logger::SimpleLogger::new().env().init().unwrap();

        let (server_socket, client_socket) = make_server_client_channel();

        // Client
        let c = tokio::spawn(async move {
            let client_buf = &mut [0; 1024];
            let mut rng: StdRng = SeedableRng::from_entropy();
            let client_config = ClientConfig {
                psk: Psk {
                    identity: b"hello world",
                    key: b"11111234567890qwertyuiopasdfghjklzxc",
                },
            };

            let cipher = ChaCha20Poly1305Cipher::default();
            let mut client_connection =
                ClientConnection::<_, DtlsEcdhePskWithChacha20Poly1305Sha256>::open_client(
                    &mut rng,
                    client_buf,
                    client_socket,
                    cipher,
                    &client_config,
                )
                .await
                .unwrap();

            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        // Server
        let s = tokio::spawn(async move {
            let psk = [(
                server_config::Identity::from(b"hello world"),
                server_config::Key::from(b"11111234567890qwertyuiopasdfghjklzxc"),
            )];

            let server_config = ServerConfig { psk: &psk };

            let buf = &mut vec![0; 16 * 1024];
            let rng = &mut rand::rngs::OsRng;

            let mut server_connection =
                ServerConnection::open_server(server_socket, &server_config, rng, buf)
                    .await
                    .unwrap();

            // server_connection.send(b"hello").await;

            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        c.await.unwrap();
        s.await.unwrap();
    }
}
