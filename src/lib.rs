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

// #![no_std]
#![allow(async_fn_in_trait)]

use buffer::SliceBuffer;
use cipher_suites::TlsCipherSuite;
use digest::Digest;
use handshake::extensions::Psk;
use key_schedule::KeySchedule;
use rand_core::{CryptoRng, RngCore};
use record::ClientRecord;
use session::RecordNumber;

pub(crate) mod buffer;
pub(crate) mod cipher_suites;
pub(crate) mod handshake;
pub(crate) mod integers;
pub(crate) mod key_schedule;
pub(crate) mod record;
pub(crate) mod session;

/// Client configuration.
pub struct ClientConfig<'a> {
    /// Preshared key.
    /// TODO: Support a list of PSKs, needs work in how to calculate binders and track all the
    /// necessary early secrets derived from the PSKs.
    psk: Psk<'a>,
}

// The TLS cake
//
// 1. Record layer (fragmentation and such)
// 2. The payload (Handshake, ChangeCipherSpec, Alert, ApplicationData)

#[derive(Debug, Copy, Clone, defmt::Format)]
pub enum DTlsError<Socket: UdpSocket> {
    /// The backing buffer ran out of space.
    InsufficientSpace,
    UdpSend(Socket::SendError),
    UdpRecv(Socket::ReceiveError),
}

/// UDP socket trait, send and receives from/to a single endpoint.
///
/// This means on `std` that it cannot be implemented directly on a socket, but probably a
/// sender/receiver pair which splits the incoming packets based on IP or similar.
pub trait UdpSocket {
    /// Error type for sending.
    type SendError: defmt::Format + core::fmt::Debug;
    /// Error type for receiving.
    type ReceiveError: defmt::Format + core::fmt::Debug;

    /// Send a UDP packet.
    async fn send(&self, buf: &[u8]) -> Result<(), Self::SendError>;
    /// Receive a UDP packet.
    async fn recv<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], Self::ReceiveError>;
}

// TODO: How to select between server and client? Typestate, flag or two separate structs?
/// A DTLS 1.3 connection.
pub struct DTlsClientConnection<Socket, CipherSuite: TlsCipherSuite> {
    /// Sender/receiver of data.
    socket: Socket,
    /// TODO: Keys for client->server and server->client. Also called "key schedule".
    key_schedule: KeySchedule<CipherSuite>,
}

impl<Socket, CipherSuite> DTlsClientConnection<Socket, CipherSuite>
where
    Socket: UdpSocket,
    CipherSuite: TlsCipherSuite,
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
    ) -> Result<Self, DTlsError<Socket>>
    where
        Rng: RngCore + CryptoRng,
    {
        let mut ser_buf = SliceBuffer::new(buf);
        let mut key_schedule = KeySchedule::new();
        let mut transcript_hasher = <CipherSuite::Hash as Digest>::new();

        // TODO: In the future, implement support for more than 1 PSK.
        key_schedule.initialize_early_secret(Some(config.psk.clone()));
        let hello = ClientRecord::<'_, CipherSuite>::client_hello(config, rng);
        let send_buf =
            hello.encode::<Socket>(&mut ser_buf, &mut key_schedule, &mut transcript_hasher)?;

        socket
            .send(send_buf)
            .await
            .map_err(|e| DTlsError::UdpSend(e))?;

        // TODO: Wait for response.
        let resp = socket.recv(buf).await.map_err(|e| DTlsError::UdpRecv(e))?;

        Ok(DTlsClientConnection {
            socket,
            key_schedule,
        })
    }

    // TODO: Move to its own struct.
    // /// Open a DTLS 1.3 server connection.
    // /// This returns an active connection after handshake is completed.
    // ///
    // /// NOTE: This does not do timeout, it's up to the caller to give up.
    // pub async fn open_server<Rng>(
    //     rng: &mut Rng,
    //     buf: &mut impl DTlsBuffer,
    //     socket: Socket,
    // ) -> Result<Self, DTlsError<Socket>>
    // where
    //     Rng: RngCore + CryptoRng,
    // {
    //     todo!()
    // }

    // TODO: Seems like this is the interface we want in the end.
    pub async fn split(
        &mut self,
    ) -> (
        DTlsSender<'_, Socket, CipherSuite>,
        DTlsReceiver<'_, Socket, CipherSuite>,
    ) {
        (
            DTlsSender {
                connection: self,
                record_number: RecordNumber::new(),
            },
            DTlsReceiver {
                connection: self,
                record_number: RecordNumber::new(),
            },
        )
    }
}

/// Sender half of a DTLS connection.
pub struct DTlsSender<'a, Socket, CipherSuite: TlsCipherSuite> {
    connection: &'a DTlsClientConnection<Socket, CipherSuite>,
    record_number: RecordNumber,
}

impl<'a, Socket, CipherSuite> DTlsSender<'a, Socket, CipherSuite>
where
    Socket: UdpSocket + Clone + 'a,
    CipherSuite: TlsCipherSuite,
{
}

/// Receiver half of a DTLS connection.
pub struct DTlsReceiver<'a, Socket, CipherSuite: TlsCipherSuite> {
    connection: &'a DTlsClientConnection<Socket, CipherSuite>,
    record_number: RecordNumber,
}

impl<'a, Socket, CipherSuite> DTlsReceiver<'a, Socket, CipherSuite>
where
    Socket: UdpSocket + Clone + 'a,
    CipherSuite: TlsCipherSuite,
{
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::cipher_suites::TlsEcdhePskWithChacha20Poly1305Sha256;
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

    impl UdpSocket for ChannelSocket {
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

            let mut client_connection = DTlsClientConnection::<
                _,
                TlsEcdhePskWithChacha20Poly1305Sha256,
            >::open_client(
                &mut rng, client_buf, client_socket, &client_config
            )
            .await
            .unwrap();
        });

        // Server
        let s = tokio::spawn(async move {
            let mut rng: StdRng = SeedableRng::from_entropy();
            let mut server_connection = DTlsServerConnection::open(&mut rng, server_socket)
                .await
                .unwrap();
        });

        c.await.unwrap();
        s.await.unwrap();
    }
}
