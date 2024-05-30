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

#[allow(unused)]
struct FakeRandom {
    val: u8,
}

impl rand::CryptoRng for FakeRandom {}

impl rand::RngCore for FakeRandom {
    fn next_u32(&mut self) -> u32 {
        u32::from_be_bytes([self.val; 4])
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_be_bytes([self.val; 8])
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(self.val);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        dest.fill(self.val);

        Ok(())
    }
}

pub mod client_config {
    use crate::handshake::extensions::Psk;

    /// Client configuration.
    #[derive(Debug)]
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
    /// The server finished was invalid.
    InvalidServerFinished,
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
    async fn recv<'a>(&self, buf: &'a mut [u8]) -> Result<&'a mut [u8], Self::ReceiveError>;
}

// Lives in no_std land.
pub mod client {
    use crate::{
        buffer::{EncodingBuffer, ParseBuffer, ParseBufferMut},
        cipher_suites::DtlsCipherSuite,
        client_config::ClientConfig,
        handshake::ServerHandshake,
        key_schedule::KeySchedule,
        record::{ClientRecord, ServerRecord},
        Datagram, Error,
    };
    use chacha20poly1305::{AeadCore, KeySizeUser};
    use digest::Digest;
    use rand_core::{CryptoRng, RngCore};
    use x25519_dalek::{EphemeralSecret, PublicKey};

    // TODO: How to select between server and client? Typestate, flag or two separate structs?
    /// A DTLS 1.3 connection.
    pub struct ClientConnection<Socket, CipherSuite: DtlsCipherSuite> {
        /// Sender/receiver of data.
        socket: Socket,
        /// TODO: Keys for client->server and server->client. Also called "key schedule".
        key_schedule: KeySchedule<CipherSuite>,
    }

    impl<Socket, CipherSuite> ClientConnection<Socket, CipherSuite>
    where
        Socket: Datagram,
        CipherSuite: DtlsCipherSuite + core::fmt::Debug,
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
            // transcript_hasher: <CipherSuite as DtlsCipherSuite>::Hash,     // TODO: Should this be &mut ?
            config: &ClientConfig<'_>,
        ) -> Result<Self, Error<Socket>>
        where
            Rng: RngCore + CryptoRng,
            <CipherSuite as DtlsCipherSuite>::Hash: std::fmt::Debug,
            <<CipherSuite as DtlsCipherSuite>::Cipher as AeadCore>::NonceSize: std::fmt::Debug,
            <<CipherSuite as DtlsCipherSuite>::Cipher as KeySizeUser>::KeySize: std::fmt::Debug,
        {
            let mut key_schedule = KeySchedule::new_client(cipher);
            let mut transcript_hasher = <CipherSuite::Hash as Digest>::new();

            // Initialize key-schedule for generating binders.
            key_schedule.initialize_early_secret(Some(config.psk.clone()));

            // Generate our ephemeral key for key exchange.
            let secret_key = EphemeralSecret::random_from_rng(&mut *rng);
            let our_public_key = PublicKey::from(&secret_key);

            // Send ClientHello.
            {
                let ser_buf = &mut EncodingBuffer::new(buf);
                ClientRecord::encode_client_hello::<CipherSuite, _>(
                    ser_buf,
                    config,
                    &our_public_key,
                    rng,
                    &mut key_schedule,
                    &mut transcript_hasher,
                )
                .map_err(|_| Error::InsufficientSpace)?;

                l0g::info!(
                    "Client transcript after client hello: {:02x?}",
                    transcript_hasher.clone().finalize()
                );

                socket.send(&ser_buf).await.map_err(|e| Error::Send(e))?;
            }

            // Wait for response (ServerHello and Finished).
            {
                let mut resp = socket.recv(buf).await.map_err(|e| Error::Recv(e))?;
                l0g::trace!("Got datagram!");

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

                    l0g::info!(
                        "Client transcript after server hello: {:02x?}",
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
                let finished = {
                    let mut buf = if resp.is_empty() {
                        // Wait for finished.
                        socket.recv(buf).await.map_err(|e| Error::Recv(e))?
                    } else {
                        resp
                    };

                    if let ServerRecord::Handshake(ServerHandshake::ServerFinished(fin), _) =
                        ServerRecord::parse::<CipherSuite::Hash>(&mut buf, None, &mut key_schedule)
                            .await
                            .ok_or(Error::InvalidServerFinished)?
                    {
                        fin
                    } else {
                        return Err(Error::InvalidServerFinished);
                    }
                };

                if transcript_hasher.clone().finalize().as_ref() != finished.verify {
                    l0g::error!("Server finished does not match transcript");
                    return Err(Error::InvalidServerFinished);
                }

                l0g::trace!("Server finished MATCHES transcript");
            }

            todo!();

            // l0g::error!("Client handshake traffic secrets: {handshake_traffic_secrets:02x?}");

            // TODO: Send finished.

            // TODO: Update key schedule to Master Secret using public keys.

            // TODO: Wait for server ACK.

            todo!();

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
        buffer::{EncodingBuffer, ParseBuffer},
        cipher_suites::{ChaCha20Poly1305Cipher, DtlsEcdhePskWithChacha20Poly1305Sha256},
        handshake::{
            extensions::{DtlsVersions, Psk},
            ClientHandshake,
        },
        key_schedule::KeySchedule,
        record::{
            CipherArguments, ClientRecord, DTlsCiphertextHeader, GenericCipher, ServerRecord,
        },
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

            let (client_hello, positions) = {
                let mut buf = ParseBuffer::new(resp);

                let (record, pos) =
                    ClientRecord::parse(&mut buf).ok_or(Error::InvalidClientHello)?;

                if !buf.pop_rest().is_empty() {
                    return Err(Error::InvalidClientHello);
                }

                if let ClientRecord::Handshake(ClientHandshake::ClientHello(hello), _) = record {
                    (hello, pos)
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
            let (up_to_binders, binders_and_rest) = positions
                .into_pre_post_binders(resp)
                .ok_or(Error::InvalidClientHello)?;

            transcript_hasher.update(up_to_binders);
            let binders_transcript_hash = transcript_hasher.clone().finalize();
            transcript_hasher.update(binders_and_rest);

            l0g::info!(
                "Server transcript after client hello: {:02x?}",
                transcript_hasher.clone().finalize()
            );

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

            // Send server hello.
            let legacy_session_id: Vec<_> = client_hello.legacy_session_id.into();

            // TODO: We hardcode the selected PSK as the first one for now.
            let mut enc_buf = EncodingBuffer::new(buf);
            ServerRecord::encode_server_hello(
                &legacy_session_id,
                DtlsVersions::V1_3,
                our_public_key,
                selected_cipher_suite as u16,
                0,
                &mut key_schedule,
                &mut enc_buf,
            )
            .await
            .map_err(|_| Error::InsufficientSpace)?;

            // TODO: Check that this is correct, I think this hashes the plaintext header.

            // TODO: Replace constant
            transcript_hasher.update(&enc_buf[13..]);

            l0g::info!(
                "Server transcript after server hello: {:02x?}",
                transcript_hasher.clone().finalize()
            );

            key_schedule.initialize_handshake_secret(
                shared_secret.as_bytes(),
                &transcript_hasher.clone().finalize(),
            );

            // Add the Finished message to this datagram.
            ServerRecord::finished(&transcript_hasher.clone().finalize())
                .encode(&mut enc_buf, &mut key_schedule)
                .await
                .map_err(|_| Error::InsufficientSpace)?;

            socket.send(&enc_buf).await.map_err(|e| Error::Send(e))?;

            // TODO: Finished from client

            // TODO: Update key schedule to Master Secret.

            // TODO: Send ACK.

            todo!();

            Ok(ServerConnection {
                socket,
                // key_schedule,
            })
        }
    }

    pub enum ServerKeySchedule {
        /// Key schedule for the Chacha20Poly1305 cipher suite.
        Chacha20Poly1305Sha256(KeySchedule<DtlsEcdhePskWithChacha20Poly1305Sha256>),
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
                    l0g::trace!("Detected unsupported cipher suite {cipher_suites:04x}");
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

        pub fn create_binders(&self, transcript_hash: &[u8]) -> Vec<u8> {
            match self {
                ServerKeySchedule::Chacha20Poly1305Sha256(key_schedule) => Vec::from(
                    key_schedule
                        .create_binder(transcript_hash)
                        .expect("Unable to generate binder")
                        .as_slice(),
                ),
            }
        }

        pub fn initialize_handshake_secret(&mut self, ecdhe: &[u8], transcript: &[u8]) {
            match self {
                ServerKeySchedule::Chacha20Poly1305Sha256(key_schedule) => {
                    key_schedule.initialize_handshake_secret(ecdhe, transcript);
                }
            }
        }
    }

    // All server ciphers must implement `GenericCipher`.
    impl GenericCipher for ServerKeySchedule {
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

    impl TranscriptHasher {
        pub fn update(&mut self, data: impl AsRef<[u8]>) {
            match self {
                TranscriptHasher::Sha256(h) => h.update(data),
            }
        }

        pub fn finalize(self) -> Vec<u8> {
            match self {
                TranscriptHasher::Sha256(h) => Vec::from(h.finalize().as_slice()),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, time::Duration};

    use super::*;
    use crate::{
        cipher_suites::{ChaCha20Poly1305Cipher, DtlsEcdhePskWithChacha20Poly1305Sha256},
        client::ClientConnection,
        client_config::ClientConfig,
        handshake::extensions::Psk,
        server::ServerConnection,
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
