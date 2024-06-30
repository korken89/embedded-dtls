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

#![cfg_attr(not(any(test, feature = "tokio-queue")), no_std)]
#![allow(async_fn_in_trait)]

use defmt_or_log::{derive_format_or_debug, FormatOrDebug};
use handshake::{ClientHelloError, ServerHelloError};

pub(crate) mod buffer;
pub(crate) mod cipher_suites;
pub mod client;
pub mod connection;
pub(crate) mod handshake;
pub(crate) mod integers;
pub(crate) mod key_schedule;
pub mod queue_helpers;
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
    InvalidClientHello(ClientHelloError),
    /// There was more data in the client hello datagram.
    MorePayloadAfterClientHello,
    /// The client finished was invalid.
    InvalidClientFinished,
    /// The server hello was invalid.
    InvalidServerHello(ServerHelloError),
    /// The server finished was invalid.
    InvalidServerFinished,
    /// The server ACK was invalid.
    InvalidServerAck,
    /// An error related to sending on the socket.
    Send(D::SendError),
    /// An error related to receiving on the socket.
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
pub trait ApplicationDataSender {
    /// Error type.
    type Error: FormatOrDebug;

    /// Send a full payload to the application data queue.
    ///
    /// If this returns an error it is interpreted as the queue being closed.
    async fn send(&mut self, data: impl AsRef<[u8]>) -> Result<(), Self::Error>;
}

/// Consumer side of an application data queue.
pub trait ApplicationDataReceiver {
    /// Error type.
    type Error: FormatOrDebug;

    /// Peek a full payload from the application data queue.
    ///
    /// If this returns an error it is interpreted as the queue being closed.
    async fn peek(&mut self) -> Result<impl AsRef<[u8]>, Self::Error>;

    /// Pop the latest payload from the application data queue.
    ///
    /// If this returns an error it is interpreted as the queue being closed.
    fn pop(&mut self) -> Result<(), Self::Error>;
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
    use defmt_or_log::{error, trace, warn};
    use embedded_hal_async::delay::DelayNs;
    use queue_helpers::framed_queue;
    use rand::{rngs::StdRng, SeedableRng};
    use tokio::sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    };

    #[allow(unused)]
    struct FakeRandom {
        fill: u8,
    }

    impl rand::RngCore for FakeRandom {
        fn next_u32(&mut self) -> u32 {
            0xcafebabe
        }

        fn next_u64(&mut self) -> u64 {
            0xdeadbeefdeadbeef
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(self.fill);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            dest.fill(self.fill);
            Ok(())
        }
    }

    impl rand::CryptoRng for FakeRandom {}

    struct Delay {}

    impl DelayNs for Delay {
        async fn delay_ns(&mut self, ns: u32) {
            tokio::time::sleep(Duration::from_nanos(ns as _)).await;
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

    async fn client(client_socket: ChannelSocket) {
        let client_buf = &mut [0; 1024];
        // let mut rng = FakeRandom { fill: 0xaa };
        let mut rng: StdRng = SeedableRng::from_entropy();
        let client_config = ClientConfig {
            psk: Psk {
                identity: b"hello world",
                key: b"11111234567890qwertyuiopasdfghjklzxc",
            },
        };

        let cipher = ChaCha20Poly1305Cipher::default();
        let client_connection = open_client::<_, _, DtlsEcdhePskWithChacha20Poly1305Sha256>(
            &mut rng,
            client_buf,
            client_socket,
            cipher,
            &client_config,
        )
        .await
        .unwrap();

        let (mut tx_sender, mut tx_receiver) = framed_queue(10);
        let (mut rx_sender, mut rx_receiver) = framed_queue(10);

        tokio::spawn(async move {
            let rx_buf = &mut vec![0; 1536];
            let tx_buf = &mut vec![0; 1536];

            if let Err(e) = client_connection
                .run(
                    rx_buf,
                    tx_buf,
                    &mut rx_sender,
                    &mut tx_receiver,
                    &mut Delay {},
                )
                .await
            {
                error!("Client connection closed with {:?}", e);
            }
        });

        // Receive
        for i in 0..10 {
            {
                let data = rx_receiver.peek().await.unwrap();
                // info!("Client got data: {:?}", data.as_ref());
                assert!(data.as_ref().iter().all(|b| *b == i as u8));
            }
            rx_receiver.pop().unwrap();

            if i % 1_000_000 == 0 {
                warn!("receive at {}", i);
            }
        }

        // Send
        for i in 10..15 {
            tx_sender.send(&vec![i; 80]).await.unwrap();
        }

        tokio::time::sleep(Duration::from_millis(50)).await;

        for i in 15..20 {
            tx_sender.send(&vec![i; 80]).await.unwrap();
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    async fn server(server_socket: ChannelSocket) {
        let psk = [(
            server::config::Identity::from(b"hello world"),
            server::config::Key::from(b"11111234567890qwertyuiopasdfghjklzxc"),
        )];

        let server_config = ServerConfig { psk: &psk };

        let buf = &mut vec![0; 16 * 1024];
        let rng = &mut rand::rngs::OsRng;
        // let rng = &mut FakeRandom { fill: 0xbb };

        let server_connection = open_server(server_socket, &server_config, rng, buf)
            .await
            .unwrap();

        let (mut tx_sender, mut tx_receiver) = framed_queue(10);
        let (mut rx_sender, mut rx_receiver) = framed_queue(10);

        tokio::spawn(async move {
            let rx_buf = &mut vec![0; 1536];
            let tx_buf = &mut vec![0; 1536];

            if let Err(e) = server_connection
                .run(
                    rx_buf,
                    tx_buf,
                    &mut rx_sender,
                    &mut tx_receiver,
                    &mut Delay {},
                )
                .await
            {
                error!("Server connection closed with {:?}", e);
            }
        });

        // Send
        for i in 0..5 {
            tx_sender.send(&vec![i; 80]).await.unwrap();
        }

        tokio::time::sleep(Duration::from_millis(50)).await;

        for i in 5..10 {
            tx_sender.send(&vec![i as u8; 80]).await.unwrap();
            if i % 1_000_000 == 0 {
                warn!("send at {}", i);
            }
        }

        // Receive
        for i in 10..20 {
            {
                let data = rx_receiver.peek().await.unwrap();
                // info!("Server got data: {:?}", data.as_ref());
                assert!(data.as_ref().iter().all(|b| *b == i));
            }
            rx_receiver.pop().unwrap();
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn open_connection() {
        simple_logger::SimpleLogger::new().env().init().unwrap();

        let (server_socket, client_socket) = make_server_client_channel();

        // Client
        let c = tokio::task::spawn(client(client_socket));

        // Server
        let s = tokio::task::spawn(server(server_socket));

        c.await.unwrap();
        s.await.unwrap();
    }
}
