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

use defmt_or_log::{derive_format_or_debug, FormatOrDebug};

pub(crate) mod buffer;
pub(crate) mod cipher_suites;
pub mod client;
pub mod connection;
pub(crate) mod handshake;
pub(crate) mod integers;
pub(crate) mod key_schedule;
pub(crate) mod record;
pub mod server;

/// Error definitions.
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

/// Producer side of an application data queue.
pub trait ApplicationDataProducer {
    /// Error type.
    type Error;

    /// Push a full payload to the application data queue.
    ///
    /// If this returns an error it is interpreted as the queue being closed.
    async fn push(&mut self, data: impl AsRef<[u8]>) -> Result<(), Self::Error>;
}

/// Consumer side of an application data queue.
pub trait ApplicationDataConsumer {
    /// Error type.
    type Error;

    /// Pop a full payload to the application data queue.
    ///
    /// If this returns an error it is interpreted as the queue being closed.
    async fn pop(&mut self) -> Result<impl AsRef<[u8]>, Self::Error>;
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use super::*;
    use crate::{
        cipher_suites::{ChaCha20Poly1305Cipher, DtlsEcdhePskWithChacha20Poly1305Sha256},
        client::config::ClientConfig,
        client::open_client,
        handshake::extensions::Psk,
        server::config::ServerConfig,
        server::open_server,
    };
    use defmt_or_log::trace;
    use rand::{rngs::StdRng, SeedableRng};
    use tokio::sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    };

    /// Create a framed queue with specific maximum depth in number of packets.
    pub fn framed_queue(depth: usize) -> (AppSender, AppReceiver) {
        let (s, r) = channel(depth);

        (AppSender(s), AppReceiver(r))
    }

    pub struct AppSender(Sender<Vec<u8>>);

    impl crate::ApplicationDataProducer for AppSender {
        type Error = ();

        async fn push(&mut self, data: impl AsRef<[u8]>) -> Result<(), Self::Error> {
            self.0.send(data.as_ref().into()).await.map_err(|_| ())
        }
    }

    pub struct AppReceiver(Receiver<Vec<u8>>);

    impl crate::ApplicationDataConsumer for AppReceiver {
        type Error = ();

        async fn pop(&mut self) -> Result<impl AsRef<[u8]>, Self::Error> {
            self.0.recv().await.ok_or(())
        }
    }

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
                open_client::<_, _, DtlsEcdhePskWithChacha20Poly1305Sha256>(
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
                server::config::Identity::from(b"hello world"),
                server::config::Key::from(b"11111234567890qwertyuiopasdfghjklzxc"),
            )];

            let server_config = ServerConfig { psk: &psk };

            let buf = &mut vec![0; 16 * 1024];
            let rng = &mut rand::rngs::OsRng;

            let mut server_connection = open_server(server_socket, &server_config, rng, buf)
                .await
                .unwrap();

            // server_connection.send(b"hello").await;

            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        c.await.unwrap();
        s.await.unwrap();
    }
}
