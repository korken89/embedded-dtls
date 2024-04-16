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

// #![cfg_attr(not(test), no_std)]
#![allow(async_fn_in_trait)]

pub(crate) mod buffer;
pub(crate) mod cipher_suites;
pub(crate) mod handshake;
pub(crate) mod integers;
pub(crate) mod key_schedule;
pub(crate) mod record;

pub mod client_config {
    use crate::handshake::extensions::Psk;

    /// Client configuration.
    pub struct ClientConfig<'a> {
        /// Preshared key.
        /// TODO: Support a list of PSKs. Needs work in how to calculate binders and track all the
        /// necessary early secrets derived from the PSKs until the server selects one PSK.
        pub psk: Psk<'a>,
    }
}

pub mod server_config {
    use std::collections::HashMap;

    use zeroize::Zeroizing;

    /// Pre-shared key identity.
    #[derive(PartialEq, Eq, Hash)]
    pub struct Identity(Vec<u8>);

    impl<T> From<T> for Identity
    where
        T: AsRef<[u8]>,
    {
        fn from(value: T) -> Self {
            Self(Vec::from(value.as_ref()))
        }
    }

    impl Identity {
        pub(crate) fn as_slice(&self) -> &[u8] {
            &self.0
        }
    }

    impl core::fmt::Debug for Identity {
        fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
            match std::str::from_utf8(&self.0) {
                Ok(string) => f.write_str(string),
                Err(_) => f.write_str(
                    &self
                        .0
                        .iter()
                        .map(|byte| format!("{:02x}", byte))
                        .collect::<Vec<String>>()
                        .join(" "),
                ),
            }
        }
    }

    /// Pre-shared key value.
    pub struct Key(Zeroizing<Vec<u8>>);

    impl<T> From<T> for Key
    where
        T: AsRef<[u8]>,
    {
        fn from(value: T) -> Self {
            Self(Vec::from(value.as_ref()).into())
        }
    }

    impl Key {
        pub(crate) fn as_slice(&self) -> &[u8] {
            &self.0
        }
    }

    /// Server configuration.
    pub struct ServerConfig {
        /// A list of allowed pre-shared keys.
        ///
        /// The key is the identity and the value is the key.
        pub psk: HashMap<Identity, Key>,
    }
}

// The TLS cake
//
// 1. Record layer (fragmentation and such)
// 2. The payload (Handshake, ChangeCipherSpec, Alert, ApplicationData)

#[derive(Debug, Copy, Clone)]
pub enum Error<D: Datagram> {
    /// The backing buffer ran out of space.
    InsufficientSpace,
    /// Failed to parse a message.
    Parse,
    /// The client hello was invalid.
    InvalidClientHello,
    /// The server hello was invalid.
    InvalidServerHello,
    /// An error related to sending on the socket.
    Send(D::SendError),
    /// An error related to receivnig on the socket.
    Recv(D::ReceiveError),
}

// TODO: Make this not hard-implemented.
impl<D> defmt::Format for Error<D>
where
    D: Datagram,
    <D as Datagram>::SendError: defmt::Format,
    <D as Datagram>::ReceiveError: defmt::Format,
{
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(fmt, "{}", self);
    }
}

/// Datagram trait, send and receives datagrams from/to a single endpoint.
///
/// This means on `std` that it cannot be implemented directly on a socket, but probably a
/// sender/receiver pair which splits the incoming packets based on IP or similar.
pub trait Datagram {
    /// Error type for sending.
    type SendError;
    /// Error type for receiving.
    type ReceiveError;

    /// Send a complete datagram.
    async fn send(&self, buf: &[u8]) -> Result<(), Self::SendError>;
    /// Receive a complete datagram.
    async fn recv<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], Self::ReceiveError>;
}

// Lives in no_std land.
pub mod client {
    use crate::{
        buffer::{EncodingBuffer, ParseBuffer},
        cipher_suites::TlsCipherSuite,
        client_config::ClientConfig,
        key_schedule::KeySchedule,
        record::ClientRecord,
        Datagram, Error,
    };
    use digest::Digest;
    use rand_core::{CryptoRng, RngCore};

    // TODO: How to select between server and client? Typestate, flag or two separate structs?
    /// A DTLS 1.3 connection.
    pub struct ClientConnection<Socket, CipherSuite: TlsCipherSuite> {
        /// Sender/receiver of data.
        socket: Socket,
        /// TODO: Keys for client->server and server->client. Also called "key schedule".
        key_schedule: KeySchedule<<CipherSuite as TlsCipherSuite>::Hash>,
    }

    impl<Socket, CipherSuite> ClientConnection<Socket, CipherSuite>
    where
        Socket: Datagram,
        CipherSuite: TlsCipherSuite + core::fmt::Debug,
    {
        /// Open a DTLS 1.3 client connection.
        /// This returns an active connection after handshake is completed.
        ///
        /// NOTE: This does not do timeout, it's up to the caller to give up.
        pub async fn open_client<Rng>(
            rng: &mut Rng,
            buf: &mut [u8],
            socket: Socket,
            config: &ClientConfig<'_>,
        ) -> Result<Self, Error<Socket>>
        where
            Rng: RngCore + CryptoRng,
        {
            let mut ser_buf = EncodingBuffer::new(buf);
            let mut key_schedule = KeySchedule::new();
            let mut transcript_hasher = <CipherSuite::Hash as Digest>::new();

            // TODO: In the future, implement support for more than 1 PSK.
            key_schedule.initialize_early_secret(Some(config.psk.clone()));
            let hello = ClientRecord::<'_, CipherSuite>::client_hello(config, rng);
            let send_buf = hello
                .encode(&mut ser_buf, &mut key_schedule, &mut transcript_hasher)
                .map_err(|_| Error::InsufficientSpace)?;

            l0g::debug!("Sending client hello: {:02x?}", hello);
            socket.send(send_buf).await.map_err(|e| Error::Send(e))?;

            // Wait for response.
            let resp = socket.recv(buf).await.map_err(|e| Error::Recv(e))?;
            l0g::trace!("Got datagram!");

            let (server_hello, positions) =
                parse::parse_server_hello(resp).ok_or(Error::InvalidServerHello)?;
            let to_hash = positions
                .into_slice(resp)
                .ok_or(Error::InvalidServerHello)?;
            transcript_hasher.update(to_hash);

            Ok(ClientConnection {
                socket,
                key_schedule,
            })
        }
    }

    mod parse {
        use crate::{
            buffer::ParseBuffer,
            handshake::{
                extensions::{
                    ExtensionType, KeyShareEntry, ParseExtension, ParseServerExtensions,
                    SelectedPsk, ServerSupportedVersion,
                },
                HandshakeHeader, HandshakeType,
            },
            record::{ContentType, DTlsPlaintextHeader, ProtocolVersion, RecordPayloadPositions},
        };

        pub fn parse_server_hello(buf: &[u8]) -> Option<(ServerHello, RecordPayloadPositions)> {
            let mut buf = ParseBuffer::new(buf);

            let record = ServerRecord::parse(&mut buf)?;

            if !buf.pop_rest().is_empty() {
                return None;
            }
            if let (ServerRecord::Handshake(ServerHandshake::ServerHello(hello)), pos) = record {
                return Some((hello, pos));
            }

            None
        }

        pub enum ServerRecord<'a> {
            Handshake(ServerHandshake<'a>),
            Alert(),
            Heartbeat(),
            Ack(),
            ApplicationData(),
        }

        impl<'a> ServerRecord<'a> {
            fn parse(buf: &mut ParseBuffer<'a>) -> Option<(Self, RecordPayloadPositions)> {
                // Parse record.
                let record_header = DTlsPlaintextHeader::parse(buf)?;
                let record_payload = buf.pop_slice(record_header.length.into())?;
                l0g::trace!("Got record: {:#?}", record_header);

                let mut buf = ParseBuffer::new(record_payload);
                let start = buf.current_pos_ptr();

                let ret = match record_header.type_ {
                    ContentType::Handshake => {
                        let handshake = ServerHandshake::parse(&mut buf)?;

                        ServerRecord::Handshake(handshake)
                    }
                    ContentType::Ack => todo!(),
                    ContentType::Heartbeat => todo!(),
                    ContentType::Alert => todo!(),
                    ContentType::ApplicationData => todo!(),
                    ContentType::ChangeCipherSpec => todo!(),
                };

                let end = buf.current_pos_ptr();

                Some((ret, RecordPayloadPositions { start, end }))
            }
        }

        enum ServerHandshake<'a> {
            ServerHello(ServerHello<'a>),
            Finished(),
            KeyUpdate(),
        }

        impl<'a> ServerHandshake<'a> {
            /// Parse a handshake message.
            pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<Self> {
                let handshake_header = HandshakeHeader::parse(buf)?;

                if handshake_header.length != handshake_header.fragment_length {
                    l0g::error!("We don't support fragmented handshakes yet.");
                    return None;
                }

                let handshake_payload =
                    buf.pop_slice(handshake_header.fragment_length.get() as usize)?;

                l0g::trace!("Got handshake: {:#?}", handshake_header);

                match handshake_header.msg_type {
                    HandshakeType::ServerHello => {
                        let mut buf = ParseBuffer::new(handshake_payload);
                        let mut server_hello = ServerHello::parse(&mut buf)?;

                        l0g::trace!("Got server hello: {:02x?}", server_hello);

                        Some(Self::ServerHello(server_hello))
                    }
                    HandshakeType::Finished => todo!(),
                    HandshakeType::KeyUpdate => todo!(),
                    _ => None,
                }
            }
        }

        #[derive(Debug)]
        pub struct ServerHello<'a> {
            pub version: ProtocolVersion,
            pub legacy_session_id_echo: &'a [u8],
            pub cipher_suite: u16,
            pub extensions: ParseServerExtensions<'a>,
        }

        impl<'a> ServerHello<'a> {
            pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<Self> {
                let version = buf.pop_u16_be()?.to_be_bytes();
                let _random = buf.pop_slice(32)?;
                let legacy_session_id_len = buf.pop_u8()?;
                let legacy_session_id_echo = buf.pop_slice(legacy_session_id_len as usize)?;

                let cipher_suite = buf.pop_u16_be()?;

                let _legacy_compression_method = buf.pop_u8()?;

                // Extensions
                let extensions = ParseServerExtensions::parse(buf)?;

                Some(Self {
                    version,
                    legacy_session_id_echo,
                    cipher_suite,
                    extensions,
                })
            }
        }
    }
}

// Lives in std land.
pub mod server {
    use crate::{
        buffer::EncodingBuffer,
        handshake::extensions::{DtlsVersions, Psk},
        key_schedule::KeySchedule,
        record::ServerRecord,
        server_config::{Identity, Key, ServerConfig},
        Datagram, Error,
    };
    use digest::Digest;
    use sha2::Sha256;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    // TODO: How to select between server and client? Typestate, flag or two separate structs?
    /// A DTLS 1.3 connection.
    pub struct ServerConnection<Socket> {
        /// Sender/receiver of data.
        socket: Socket,
        // / TODO: Keys for client->server and server->client. Also called "key schedule".
        // key_schedule: KeySchedule<CipherSuite>,
    }

    impl<Socket> ServerConnection<Socket>
    where
        Socket: Datagram,
    {
        /// Open a DTLS 1.3 server connection.
        /// This returns an active connection after handshake is completed.
        ///
        /// NOTE: This does not do timeout, it's up to the caller to give up.
        pub async fn open_server(
            socket: Socket,
            server_config: &ServerConfig,
        ) -> Result<Self, Error<Socket>> {
            // TODO: If any part fails with error, make sure to send the correct ALERT.
            let buf = &mut vec![0; 16 * 1024];

            let resp = socket.recv(buf).await.map_err(|e| Error::Recv(e))?;
            l0g::trace!("Got datagram!");

            let (client_hello, positions) = parse::parse_client_hello(resp).ok_or(Error::Parse)?;

            // Find the first supported cipher suite.
            let (mut key_schedule, selected_cipher_suite) = {
                let mut r = None;
                for cipher_suite in &client_hello.cipher_suites {
                    // Check so we can support this cipher suite.
                    if let Some(key_schedule) =
                        ServerKeySchedule::try_from_cipher_suite(*cipher_suite)
                    {
                        r = Some((key_schedule, *cipher_suite));
                    }
                }

                // TODO: This should generate an alert.
                r.ok_or(Error::InvalidClientHello)?
            };

            // At this point we know the selected cipher suite, and hence also the hash function.
            // Now we can generate transcript hashes for binders and the message in total.
            let mut transcript_hasher = key_schedule.new_transcript_hasher();
            let (up_to_binders, binders_and_rest) = positions
                .into_sub_slices(
                    resp,
                    client_hello
                        .binders_start
                        .ok_or(Error::InvalidClientHello)?,
                )
                .ok_or(Error::InvalidClientHello)?;

            transcript_hasher.update(up_to_binders);
            let binders_transcript_hash = transcript_hasher.clone().finalize();
            transcript_hasher.update(binders_and_rest);

            let their_public_key = client_hello
                .validate_and_initialize_keyschedule(
                    &mut key_schedule,
                    server_config,
                    &binders_transcript_hash,
                )
                .map_err(|_| Error::InvalidClientHello)?;

            l0g::debug!("Got valid ClientHello!");

            // Perform ECDHE -> Handshake Secret with Key Schedule
            // TODO: For now we assume X25519.
            let secret = EphemeralSecret::random();
            let our_public_key = PublicKey::from(&secret);
            let shared_secret = secret.diffie_hellman(&their_public_key);
            key_schedule.initialize_handshake_secret(shared_secret.as_bytes());

            // Send server hello.
            // TODO: We hardcode the selected PSK as the first one for now.
            let server_hello = ServerRecord::server_hello(
                client_hello.legacy_session_id,
                DtlsVersions::V1_3,
                our_public_key,
                selected_cipher_suite,
                0,
            );

            let mut enc_buf = EncodingBuffer::new(buf);
            let (to_send, to_hash) = server_hello
                .encode(&mut enc_buf)
                .map_err(|_| Error::InsufficientSpace)?;
            transcript_hasher.update(to_hash);

            // TODO: Can we do without this `Vec`? The lifetime of `enc_buf` makes it hard now.
            let mut server_hello_and_finished = Vec::from(to_send);

            l0g::debug!("Sending server hello: {server_hello:02x?}");

            // TODO: Update key schedule.

            // TODO: Add the Finished message to this datagram.

            socket
                .send(&server_hello_and_finished)
                .await
                .map_err(|e| Error::Send(e))?;

            Ok(ServerConnection {
                socket,
                // key_schedule,
            })
        }
    }

    enum ServerKeySchedule {
        /// All cipher suites which use SHA256 as the hash function will use this key schedule.
        Sha256(KeySchedule<Sha256>),
    }

    impl ServerKeySchedule {
        fn is_uninitialized(&self) -> bool {
            match self {
                ServerKeySchedule::Sha256(v) => v.is_uninitialized(),
            }
        }

        fn new_transcript_hasher(&self) -> TranscriptHasher {
            match self {
                ServerKeySchedule::Sha256(_) => TranscriptHasher::Sha256(Sha256::default()),
            }
        }

        fn try_from_cipher_suite(cipher_suites: u16) -> Option<Self> {
            Some(match cipher_suites {
                // TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
                0xCCAC => ServerKeySchedule::Sha256(KeySchedule::new()),
                _ => {
                    l0g::trace!("Detected unsupported cipher suite {cipher_suites:04x}");
                    return None;
                }
            })
        }

        fn initialize_early_secret(&mut self, psk: Option<(&Identity, &Key)>) {
            match self {
                ServerKeySchedule::Sha256(key_schedule) => {
                    key_schedule.initialize_early_secret(psk.map(|p| Psk {
                        identity: p.0.as_slice(),
                        key: p.1.as_slice(),
                    }))
                }
            }
        }

        fn create_binders(&self, transcript_hash: &[u8]) -> Vec<u8> {
            match self {
                ServerKeySchedule::Sha256(key_schedule) => Vec::from(
                    key_schedule
                        .create_binder(transcript_hash)
                        .expect("Unable to generate binder")
                        .as_slice(),
                ),
            }
        }

        fn initialize_handshake_secret(&mut self, ecdhe: &[u8]) {
            match self {
                ServerKeySchedule::Sha256(key_schedule) => {
                    key_schedule.initialize_handshake_secret(ecdhe);
                }
            }
        }
    }

    /// This is used to get the transcript hashes, it stems from the
    #[derive(Clone, Debug)]
    enum TranscriptHasher {
        Sha256(Sha256),
    }

    impl TranscriptHasher {
        fn update(&mut self, data: impl AsRef<[u8]>) {
            match self {
                TranscriptHasher::Sha256(h) => h.update(data),
            }
        }

        fn finalize(self) -> Vec<u8> {
            match self {
                TranscriptHasher::Sha256(h) => Vec::from(h.finalize().as_slice()),
            }
        }
    }

    mod parse {
        use super::ServerKeySchedule;
        use crate::{
            buffer::ParseBuffer,
            handshake::{
                extensions::{
                    ClientSupportedVersions, DtlsVersions, ExtensionType, KeyShareEntry,
                    NamedGroup, OfferedPreSharedKey, ParseExtension, PskKeyExchangeMode,
                    PskKeyExchangeModes,
                },
                HandshakeHeader, HandshakeType,
            },
            record::{
                ContentType, DTlsPlaintextHeader, ProtocolVersion, RecordPayloadPositions,
                LEGACY_DTLS_VERSION,
            },
            server_config::{Identity, ServerConfig},
        };
        use x25519_dalek::PublicKey;

        pub fn parse_client_hello(buf: &[u8]) -> Option<(ClientHello, RecordPayloadPositions)> {
            let mut buf = ParseBuffer::new(buf);

            let record = ClientRecord::parse(&mut buf)?;

            if !buf.pop_rest().is_empty() {
                return None;
            }
            if let (ClientRecord::Handshake(ClientHandshake::ClientHello(hello)), pos) = record {
                return Some((hello, pos));
            }

            None
        }

        enum ClientRecord<'a> {
            Handshake(ClientHandshake<'a>),
            Alert(),
            Heartbeat(),
            Ack(),
            ApplicationData(),
        }

        impl<'a> ClientRecord<'a> {
            fn parse(buf: &mut ParseBuffer<'a>) -> Option<(Self, RecordPayloadPositions)> {
                // Parse record.
                let record_header = DTlsPlaintextHeader::parse(buf)?;
                let record_payload = buf.pop_slice(record_header.length.into())?;
                l0g::trace!("Got record: {:#?}", record_header);

                let mut buf = ParseBuffer::new(record_payload);
                let start = buf.current_pos_ptr();

                let ret = match record_header.type_ {
                    ContentType::Handshake => {
                        let handshake = ClientHandshake::parse(&mut buf)?;

                        ClientRecord::Handshake(handshake)
                    }
                    ContentType::Ack => todo!(),
                    ContentType::Heartbeat => todo!(),
                    ContentType::Alert => todo!(),
                    ContentType::ApplicationData => todo!(),
                    ContentType::ChangeCipherSpec => todo!(),
                };

                let end = buf.current_pos_ptr();

                Some((ret, RecordPayloadPositions { start, end }))
            }
        }

        enum ClientHandshake<'a> {
            ClientHello(ClientHello<'a>),
            Finished(),
            KeyUpdate(),
        }

        impl<'a> ClientHandshake<'a> {
            /// Parse a handshake message.
            pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<Self> {
                let handshake_header = HandshakeHeader::parse(buf)?;

                if handshake_header.length != handshake_header.fragment_length {
                    l0g::error!("We don't support fragmented handshakes yet.");
                    return None;
                }

                let handshake_payload =
                    buf.pop_slice(handshake_header.fragment_length.get() as usize)?;

                l0g::trace!("Got handshake: {:#?}", handshake_header);

                match handshake_header.msg_type {
                    HandshakeType::ClientHello => {
                        let mut buf = ParseBuffer::new(handshake_payload);
                        let client_hello = ClientHello::parse(&mut buf)?;

                        l0g::trace!("Got client hello: {:02x?}", client_hello);

                        Some(Self::ClientHello(client_hello))
                    }
                    HandshakeType::Finished => todo!(),
                    HandshakeType::KeyUpdate => todo!(),
                    _ => None,
                }
            }
        }

        #[derive(Debug)]
        pub struct ClientHello<'a> {
            pub version: ProtocolVersion,
            pub legacy_session_id: Vec<u8>,
            pub cipher_suites: Vec<u16>,
            pub extensions: ClientExtensions<'a>,
            pub binders_start: Option<usize>,
        }

        impl<'a> ClientHello<'a> {
            pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<Self> {
                let version = buf.pop_u16_be()?.to_be_bytes();
                let _random = buf.pop_slice(32)?;

                //     opaque legacy_session_id<0..32>;
                //     opaque legacy_cookie<0..2^8-1>;                  // DTLS
                let legacy_session_id_len = buf.pop_u8()?;
                let legacy_session_id = Vec::from(buf.pop_slice(legacy_session_id_len as usize)?);

                let legacy_cookie = buf.pop_u8()?;
                if legacy_cookie != 0 {
                    l0g::trace!("Legacy cookie is non-zero");
                    return None;
                }

                let cipher_suites = {
                    let mut v = Vec::new();
                    let num_cipher_suites_bytes = buf.pop_u16_be()?;

                    if num_cipher_suites_bytes % 2 != 0 {
                        // Not an even amount of bytes (each cipher suite needs 2 bytes)
                        return None;
                    }

                    let num_cipher_suites = num_cipher_suites_bytes / 2;

                    for _ in 0..num_cipher_suites {
                        v.push(buf.pop_u16_be()?);
                    }

                    v
                };

                let legacy_compression_methods_len = buf.pop_u8()?;
                let legacy_compression_methods = buf.pop_u8()?;
                if legacy_compression_methods_len != 1 || legacy_compression_methods != 0 {
                    l0g::trace!("Legacy compression methods is non-zero");
                    return None;
                }

                let (extensions, binders_start) = ClientExtensions::parse(buf)?;

                Some(Self {
                    version,
                    legacy_session_id,
                    cipher_suites,
                    extensions,
                    binders_start,
                })
            }

            /// Check a client hello if it is valid, perform binder verification and setup the key
            /// schedule.
            pub fn validate_and_initialize_keyschedule(
                &self,
                key_schedule: &mut ServerKeySchedule,
                server_config: &ServerConfig,
                binders_hash: &[u8],
            ) -> Result<PublicKey, ()> {
                debug_assert!(key_schedule.is_uninitialized());

                if self.version != LEGACY_DTLS_VERSION {
                    l0g::error!(
                        "ClientHello version is not legacy DTLS version: {:02x?}",
                        self.version
                    );
                    return Err(());
                }

                l0g::trace!("DTLS legacy version OK");

                // Are all the expexted extensions there? By this we enforce that the PSK key exchange
                // is ECDHE.
                // Verify with RFC8446, section 9.2
                let (
                    Some(psk_key_exchange_modes),
                    Some(supported_versions),
                    Some(key_share),
                    Some(pre_shared_key),
                ) = (
                    &self.extensions.psk_key_exchange_modes,
                    &self.extensions.supported_versions,
                    &self.extensions.key_share,
                    &self.extensions.pre_shared_key,
                )
                else {
                    // TODO: For now we expect these specific extensions.
                    l0g::error!(
                        "ClientHello: Not all expected extensions are provided {self:02x?}"
                    );
                    return Err(());
                };

                l0g::trace!("All required extensions are present");

                if supported_versions.version != DtlsVersions::V1_3 {
                    // We only support DTLS 1.3.
                    l0g::error!("Not DTLS 1.3");
                    return Err(());
                }
                l0g::trace!("DTLS version OK: {:?}", supported_versions.version);

                if key_share.group != NamedGroup::X25519 && key_share.opaque.len() == 32 {
                    l0g::error!(
                    "ClientHello: The keyshare named group is unsupported or wrong key length: {:?}, len = {}",
                    key_share.group,
                    key_share.opaque.len()
                );
                    return Err(());
                }
                l0g::trace!("Keyshare is OK: {:?}", key_share.group);

                if psk_key_exchange_modes.ke_modes != PskKeyExchangeMode::PskDheKe {
                    l0g::error!(
                        "ClientHello: The PskKeyExchangeMode is unsupported: {:?}",
                        key_share.group
                    );
                    return Err(());
                }
                l0g::trace!(
                    "Psk key exchange mode is OK: {:?}",
                    psk_key_exchange_modes.ke_modes
                );

                // Find the PSK.
                let psk_identity = Identity::from(pre_shared_key.identity);
                let Some(psk) = server_config.psk.get(&psk_identity) else {
                    l0g::error!("ClientHello: Psk unknown identity: {psk_identity:?}");
                    return Err(());
                };
                l0g::trace!("Psk identity '{:?}' is AVAILABLE", psk_identity);

                // Perform PSK -> Early Secret with Key Schedule
                key_schedule.initialize_early_secret(Some((&psk_identity, psk)));

                // Verify binders with Early Secret
                let binder = key_schedule.create_binders(binders_hash);

                if binder != pre_shared_key.binder {
                    l0g::error!("ClientHello: Psk binder mismatch");
                    return Err(());
                }
                l0g::trace!("Psk binders MATCH");

                let their_public_key =
                    PublicKey::from(TryInto::<[u8; 32]>::try_into(key_share.opaque).unwrap());

                l0g::trace!("ClientHello VALID");

                Ok(their_public_key)
            }
        }

        #[derive(Debug, Default)]
        pub struct ClientExtensions<'a> {
            pub psk_key_exchange_modes: Option<PskKeyExchangeModes>,
            pub supported_versions: Option<ClientSupportedVersions>,
            pub key_share: Option<KeyShareEntry<'a>>,
            pub pre_shared_key: Option<OfferedPreSharedKey<'a>>,
        }

        impl<'a> ClientExtensions<'a> {
            pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<(Self, Option<usize>)> {
                let mut ret = ClientExtensions::default();
                let mut binders_start = None;

                let extensions_length = buf.pop_u16_be()?;
                let mut extensions = ParseBuffer::new(buf.pop_slice(extensions_length as usize)?);

                while let Some(extension) = ParseExtension::parse(&mut extensions) {
                    if ret.pre_shared_key.is_some() {
                        l0g::error!("Got more extensions after PreSharedKey!");
                        return None;
                    }

                    match extension.extension_type {
                        ExtensionType::SupportedVersions => {
                            let Some(v) = ClientSupportedVersions::parse(&mut ParseBuffer::new(
                                extension.extension_data,
                            )) else {
                                l0g::error!("Failed to parse supported version");
                                return None;
                            };

                            if ret.supported_versions.is_some() {
                                l0g::error!("Supported version extension already parsed!");
                                return None;
                            }

                            ret.supported_versions = Some(v);
                        }
                        ExtensionType::PskKeyExchangeModes => {
                            let Some(v) = PskKeyExchangeModes::parse(&mut ParseBuffer::new(
                                extension.extension_data,
                            )) else {
                                l0g::error!("Failed to parse PskKeyExchange");
                                return None;
                            };

                            if ret.psk_key_exchange_modes.is_some() {
                                l0g::error!("PskKeyExchangeModes extension already parsed!");
                                return None;
                            }

                            ret.psk_key_exchange_modes = Some(v);
                        }
                        ExtensionType::KeyShare => {
                            let Some(v) = KeyShareEntry::parse(&mut ParseBuffer::new(
                                extension.extension_data,
                            )) else {
                                l0g::error!("Failed to parse PskKeyExchange");
                                return None;
                            };

                            if ret.key_share.is_some() {
                                l0g::error!("Keyshare extension already parsed!");
                                return None;
                            }

                            ret.key_share = Some(v);
                        }
                        ExtensionType::PreSharedKey => {
                            let Some((psk, binders_start_pos)) = OfferedPreSharedKey::parse(
                                &mut ParseBuffer::new(extension.extension_data),
                            ) else {
                                l0g::error!("Failed to parse PreSharedKey");
                                return None;
                            };

                            if ret.pre_shared_key.is_some() {
                                l0g::error!("PreSharedKey extension already parsed!");
                                return None;
                            }

                            binders_start = Some(binders_start_pos);
                            ret.pre_shared_key = Some(psk);
                        }
                        _ => {
                            l0g::error!("Got more extensions than what's supported!");
                            return None;
                        }
                    }
                }

                Some((ret, binders_start))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, time::Duration};

    use super::*;
    use crate::{
        cipher_suites::TlsEcdhePskWithChacha20Poly1305Sha256, client::ClientConnection,
        client_config::ClientConfig, handshake::extensions::Psk, server::ServerConnection,
        server_config::ServerConfig,
    };
    use rand::{rngs::StdRng, SeedableRng};
    use tokio::sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    };

    #[derive(Debug)]
    struct ChannelSocket {
        who: &'static str,
        rx: Mutex<Receiver<Vec<u8>>>,
        tx: Sender<Vec<u8>>,
    }

    impl Datagram for ChannelSocket {
        type SendError = ();
        type ReceiveError = ();

        async fn send(&self, buf: &[u8]) -> Result<(), Self::SendError> {
            l0g::trace!("{} send ({}): {:02x?}", self.who, buf.len(), buf);
            self.tx.send(buf.into()).await.map_err(|_| ())
        }

        async fn recv<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], Self::ReceiveError> {
            let r = self.rx.lock().await.recv().await.ok_or(())?;

            buf[..r.len()].copy_from_slice(&r);

            Ok(&buf[..r.len()])
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
        simple_logger::SimpleLogger::new().init().unwrap();

        let (server_socket, client_socket) = make_server_client_channel();

        // Client
        let c = tokio::spawn(async move {
            let client_buf = &mut [0; 1024];
            let mut rng: StdRng = SeedableRng::from_entropy();
            let client_config = ClientConfig {
                psk: Psk {
                    identity: b"hello world",
                    key: b"1234567890qwertyuiopasdfghjklzxc",
                },
            };

            let mut client_connection =
                ClientConnection::<_, TlsEcdhePskWithChacha20Poly1305Sha256>::open_client(
                    &mut rng,
                    client_buf,
                    client_socket,
                    &client_config,
                )
                .await
                .unwrap();

            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        // Server
        let s = tokio::spawn(async move {
            let server_config = ServerConfig {
                psk: HashMap::from([(
                    server_config::Identity::from(b"hello world"),
                    server_config::Key::from(b"1234567890qwertyuiopasdfghjklzxc"),
                )]),
            };

            let mut server_connection =
                ServerConnection::open_server(server_socket, &server_config)
                    .await
                    .unwrap();

            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        c.await.unwrap();
        s.await.unwrap();
    }
}
