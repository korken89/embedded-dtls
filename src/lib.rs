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
    use zeroize::Zeroizing;

    /// Pre-shared key value.
    pub struct Key(Zeroizing<Vec<u8>>);

    /// A pre-shared key.
    pub struct Psk {
        pub identity: Vec<u8>,
        pub key: Key,
    }

    /// Server configuration.
    pub struct ServerConfig {
        /// A list of allowed pre-shared keys.
        pub psk: Vec<Psk>,
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
    Send(D::SendError),
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

pub mod client {
    use crate::{
        buffer::EncodingBuffer, cipher_suites::TlsCipherSuite, client_config::ClientConfig,
        key_schedule::KeySchedule, record::ClientRecord, Datagram, Error,
    };
    use digest::Digest;
    use rand_core::{CryptoRng, RngCore};

    // TODO: How to select between server and client? Typestate, flag or two separate structs?
    /// A DTLS 1.3 connection.
    pub struct ClientConnection<Socket, CipherSuite: TlsCipherSuite> {
        /// Sender/receiver of data.
        socket: Socket,
        /// TODO: Keys for client->server and server->client. Also called "key schedule".
        key_schedule: KeySchedule<CipherSuite>,
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

            l0g::trace!("Sending client hello: {:?}", hello);
            socket.send(send_buf).await.map_err(|e| Error::Send(e))?;

            // TODO: Wait for response.
            let resp = socket.recv(buf).await.map_err(|e| Error::Recv(e))?;

            Ok(ClientConnection {
                socket,
                key_schedule,
            })
        }
    }
}

pub mod server {
    use crate::{
        buffer::{EncodingBuffer, ParseBuffer},
        cipher_suites,
        handshake::{
            extensions::{ExtensionType, NamedGroup, PskKeyExchangeMode, DTLS_13_VERSION},
            HandshakeHeader, HandshakeType, Random,
        },
        record::{
            ClientRecord, ContentType, DTlsPlaintextHeader, ProtocolVersion, LEGACY_DTLS_VERSION,
        },
        Datagram, Error,
    };
    use rand_core::{CryptoRng, RngCore};

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
        // TODO: Should this be some kind of iterator that gives out new DTLS connections?
        pub async fn open_server<Rng>(
            rng: &mut Rng,
            buf: &mut [u8],
            socket: Socket,
        ) -> Result<Self, Error<Socket>>
        where
            Rng: RngCore + CryptoRng,
        {
            let mut ser_buf = EncodingBuffer::new(buf);
            // let mut key_schedule = KeySchedule::new();
            // let mut transcript_hasher = <CipherSuite::Hash as Digest>::new();

            let resp = socket.recv(buf).await.map_err(|e| Error::Recv(e))?;
            l0g::trace!("Got datagram!");

            let hello = parse_hello(resp);

            Ok(ServerConnection {
                socket,
                // key_schedule,
            })
        }
    }

    fn parse_hello(buf: &[u8]) -> Option<()> {
        let mut buf = ParseBuffer::new(buf);

        let client_handshake = Record::parse(&mut buf);

        if !buf.pop_rest().is_empty() {
            return None;
        }

        Some(())
    }

    enum Record {
        Handshake(),
        Alert(),
        Heartbeat(),
        Ack(),
        ApplicationData(),
    }

    impl Record {
        fn parse(buf: &mut ParseBuffer) -> Option<Self> {
            // Parse record.
            let record_header = DTlsPlaintextHeader::parse(buf)?;
            let record_payload = buf.pop_slice(record_header.length.into())?;
            l0g::trace!("Got record: {:#?}", record_header);

            let mut buf = ParseBuffer::new(record_payload);

            match record_header.type_ {
                ContentType::Handshake => {
                    let handshake = ClientHandshake::parse(&mut buf)?;

                    // Validate parsed data.
                    match handshake {
                        ClientHandshake::ClientHello(hello) => {
                            if !hello.is_valid() {
                                l0g::error!("ClientHello is not valid");
                                return None;
                            }
                        }
                        ClientHandshake::Finished() => todo!(),
                        ClientHandshake::KeyUpdate() => todo!(),
                    }

                    todo!()
                }
                ContentType::Ack => todo!(),
                ContentType::Heartbeat => todo!(),
                ContentType::Alert => todo!(),
                ContentType::ApplicationData => todo!(),
                ContentType::ChangeCipherSpec => todo!(),
            }
            // TODO
        }
    }

    enum ClientHandshake {
        ClientHello(ClientHello),
        Finished(),
        KeyUpdate(),
    }

    impl ClientHandshake {
        /// Parse a handshake message.
        pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
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

                    l0g::trace!("Got client hello: {:#02x?}", client_hello);

                    if !client_hello.is_valid() {}

                    todo!()
                }
                HandshakeType::Finished => todo!(),
                HandshakeType::KeyUpdate => todo!(),
                _ => None,
            }
        }
    }

    #[derive(Debug)]
    struct ClientHello {
        version: ProtocolVersion,
        random: Random,
        cipher_suites: Vec<u16>,
        extensions: ClientExtensions,
    }

    impl ClientHello {
        pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
            let version = buf.pop_u16_be()?.to_be_bytes();
            let random = buf.pop_slice(32)?.try_into().unwrap();

            //     opaque legacy_session_id<0..32>;
            //     opaque legacy_cookie<0..2^8-1>;                  // DTLS
            let legacy_session_id = buf.pop_u8()?;
            if legacy_session_id != 0 {
                l0g::trace!("Legacy session ID is non-zero");
                return None;
            }

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

            let extensions = ClientExtensions::parse(buf)?;

            Some(Self {
                version,
                random,
                cipher_suites,
                extensions,
            })
        }

        /// Check a client hello if it is valid.
        pub fn is_valid(&self) -> bool {
            if self.version != LEGACY_DTLS_VERSION {
                l0g::error!(
                    "ClientHello version is not legacy DTLS version: {:02x?}",
                    self.version
                );
                return false;
            }

            // Are all the extensions there?
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
                l0g::error!("ClientHello: Not all extensions are provided");
                return false;
            };

            todo!()
        }
    }

    #[derive(Debug, Default)]
    pub struct ClientExtensions {
        pub psk_key_exchange_modes: Option<PskKeyExchangeModes>,
        pub supported_versions: Option<SupportedVersions>,
        pub key_share: Option<KeyShare>,
        pub pre_shared_key: Option<PreSharedKey>,
    }

    impl ClientExtensions {
        pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
            let mut ret = ClientExtensions::default();

            let extensions_length = buf.pop_u16_be()?;
            let mut extensions = ParseBuffer::new(buf.pop_slice(extensions_length as usize)?);

            while let Some(extension) = Extension::parse(&mut extensions) {
                if ret.pre_shared_key.is_some() {
                    l0g::error!("Got more extensions after PreSharedKey!");
                    return None;
                }

                match extension.extension_type {
                    ExtensionType::SupportedVersions => {
                        let Some(v) = SupportedVersions::parse(&mut ParseBuffer::new(
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
                        let Some(v) =
                            KeyShare::parse(&mut ParseBuffer::new(extension.extension_data))
                        else {
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
                        let Some(v) =
                            PreSharedKey::parse(&mut ParseBuffer::new(extension.extension_data))
                        else {
                            l0g::error!("Failed to parse PreSharedKey");
                            return None;
                        };

                        if ret.pre_shared_key.is_some() {
                            l0g::error!("PreSharedKey extension already parsed!");
                            return None;
                        }

                        ret.pre_shared_key = Some(v);
                    }
                    _ => {
                        l0g::error!("Got more extensions than what's supported!");
                        return None;
                    }
                }
            }

            Some(ret)
        }
    }

    struct Extension<'a> {
        extension_type: ExtensionType,
        extension_data: &'a [u8],
    }

    impl<'a> Extension<'a> {
        pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<Self> {
            let extension_type = ExtensionType::try_from(buf.pop_u8()?).ok()?;
            let data_len = buf.pop_u16_be()?;
            let extension_data = buf.pop_slice(data_len as usize)?;

            Some(Self {
                extension_type,
                extension_data,
            })
        }
    }

    #[derive(Debug)]
    struct SupportedVersions {}

    impl SupportedVersions {
        pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
            let size = buf.pop_u8()?;

            if size != 2 {
                // Only one version for now
                return None;
            }

            let version = buf.pop_u16_be()?;

            if version != DTLS_13_VERSION {
                l0g::error!("Not DTLS 1.3");
                // Only support DTLS 1.3 for now
                return None;
            }

            Some(SupportedVersions {})
        }
    }

    #[derive(Debug)]
    struct PskKeyExchangeModes {
        ke_modes: PskKeyExchangeMode,
    }

    impl PskKeyExchangeModes {
        pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
            if buf.pop_u8()? != 1 {
                return None;
            }

            let ke_modes = buf.pop_u8()?.try_into().ok()?;

            Some(PskKeyExchangeModes { ke_modes })
        }
    }

    #[derive(Debug)]
    struct KeyShare {
        named_group: NamedGroup,
        key: [u8; 32],
    }

    impl KeyShare {
        pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
            let size = buf.pop_u16_be()?;
            let named_group = NamedGroup::try_from(buf.pop_u16_be()?).ok()?;
            let key_length = buf.pop_u16_be()?;

            // TODO: We only support one key for now.
            let expected_size = key_length + 2 + 2;
            if expected_size != size {
                l0g::error!("The keyshare size does not match only one key, expected {size} got {expected_size}");
                return None;
            }

            let key = buf.pop_slice(key_length as usize)?;

            // TODO: Only one key share for now and it's X25519
            Some(KeyShare {
                named_group,
                key: key.try_into().ok()?,
            })
        }
    }

    #[derive(Debug)]
    struct PreSharedKey {
        identity: Vec<u8>,
        binder: Vec<u8>,
        ticket_age: u32,
    }

    impl PreSharedKey {
        pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
            // Identity part
            let identity_size = buf.pop_u16_be()?;
            let identity_length = buf.pop_u16_be()?;

            // TODO: For now we only support one identity.
            let expected_identity_size = identity_length + 4 + 2; // +4 for the ticket, +2 for size
            if identity_size != expected_identity_size {
                l0g::error!(
                    "Identity size failure, expected {expected_identity_size}, got {identity_size}"
                );

                return None;
            }

            let identity = buf.pop_slice(identity_length as usize)?;
            let ticket_age = buf.pop_u32_be()?;

            // Binders part
            let binders_size = buf.pop_u16_be()?;
            // TODO: We should check expected length based on code point
            let binder_length = buf.pop_u8()?;

            let expected_binders_size = binder_length as u16 + 1;
            if binders_size != expected_binders_size {
                l0g::error!(
                    "Binders size failure, expected {expected_binders_size}, got {binders_size}"
                );

                return None;
            }

            let binder = buf.pop_slice(binder_length as usize)?;

            Some(PreSharedKey {
                identity: identity.into(),
                binder: binder.into(),
                ticket_age,
            })
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;
    use crate::{
        cipher_suites::TlsEcdhePskWithChacha20Poly1305Sha256, client::ClientConnection,
        client_config::ClientConfig, handshake::extensions::Psk, server::ServerConnection,
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
            let server_buf = &mut [0; 1024];
            let mut rng: StdRng = SeedableRng::from_entropy();
            let mut server_connection =
                ServerConnection::open_server(&mut rng, server_buf, server_socket)
                    .await
                    .unwrap();

            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        c.await.unwrap();
        s.await.unwrap();
    }
}
