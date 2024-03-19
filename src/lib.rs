//! A DTLS 1.3 PSK implementation.
//!
//!
//!
//!
//!
//! Heavily inspired by [`embedded-tls`].
//! [`embedded-tls`]: https://github.com/drogue-iot/embedded-tls

#![no_std]
#![allow(async_fn_in_trait)]

use buffer::DTlsBuffer;
use cipher_suites::TlsCipherSuite;
use handshake::{ClientConfig, ClientHandshake};
use key_schedule::KeySchedule;
use rand_core::{CryptoRng, RngCore};
use record::ClientRecord;
use session::RecordNumber;

pub mod buffer;
pub mod cipher_suites;
pub(crate) mod handshake;
pub mod integers;
pub mod key_schedule;
pub mod record;
pub mod session;

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
    type SendError: defmt::Format;
    /// Error type for receiving.
    type ReceiveError: defmt::Format;

    /// Send a UDP packet.
    async fn send(&self, buf: &[u8]) -> Result<(), Self::SendError>;
    /// Receive a UDP packet.
    async fn recv(&self, buf: &mut [u8]) -> Result<(), Self::ReceiveError>;
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
    Socket: UdpSocket + Clone,
    CipherSuite: TlsCipherSuite,
{
    /// Open a DTLS 1.3 client connection.
    /// This returns an active connection after handshake is completed.
    ///
    /// NOTE: This does not do timeout, it's up to the caller to give up.
    pub async fn open_client<Rng>(
        rng: &mut Rng,
        buf: &mut impl DTlsBuffer,
        socket: Socket,
        config: &ClientConfig<'_>,
    ) -> Result<Self, DTlsError<Socket>>
    where
        Rng: RngCore + CryptoRng,
    {
        // let mut handshake = ClientHandshake::new();

        // let crypto = handshake.perform(buf, &socket, rng).await?;

        let key_schedule = KeySchedule::new();

        let hello = ClientRecord::<'_, CipherSuite>::client_hello(config, rng);

        hello.encode::<Socket>(buf)?;

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

    #[test]
    fn open_connection() {}
}
