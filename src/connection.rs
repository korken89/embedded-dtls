use core::pin::pin;
use defmt_or_log::{debug, derive_format_or_debug, error, trace};
use embassy_futures::select::{select, Either};
use embassy_sync::{blocking_mutex::raw::NoopRawMutex, mutex::Mutex};
use embedded_hal_async::delay::DelayNs;
use std::convert::Infallible;

use crate::{
    buffer::EncodingBuffer,
    record::{GenericKeySchedule, Record, MINIMUM_CIPHERTEXT_OVERHEAD},
    ApplicationDataReceiver, ApplicationDataSender, Endpoint, Error,
};

/// Error definitions.
#[derive_format_or_debug]
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum ConnectionError<E, S, R> {
    DtlsError(E),
    SendError(S),
    ReceiveError(R),
}

type ErrorHelper<E, S, R> = ConnectionError<
    Error<E>,
    <S as ApplicationDataSender>::Error,
    <R as ApplicationDataReceiver>::Error,
>;

/// A DTLS 1.3 connection.
pub struct Connection<Socket, KeySchedule>
where
    Socket: Endpoint,
    KeySchedule: GenericKeySchedule,
{
    /// Sender/receiver of data.
    pub(crate) socket: Socket,
    /// Keys for client->server and server->client.
    pub(crate) key_schedule: KeySchedule,
}

impl<Socket, KeySchedule> Connection<Socket, KeySchedule>
where
    Socket: Endpoint,
    KeySchedule: GenericKeySchedule,
{
    /// Run the connection and serve the application data queues. This will return when the
    /// connection is closed.
    ///
    /// The `{rx, tx}_buffer` should ideally be the size of the MTU, but may be less as well.
    pub async fn run<Receiver, Sender>(
        mut self,
        rx_buffer: &mut [u8],
        tx_buffer: &mut [u8],
        rx_sender: &mut Sender,
        tx_receiver: &mut Receiver,
        delay: &mut impl DelayNs,
    ) -> Result<Infallible, ErrorHelper<Socket, Sender, Receiver>>
    where
        Sender: ApplicationDataSender,
        Receiver: ApplicationDataReceiver,
    {
        // Make sure we can share the key schedule between each path in the select below.
        let key_schedule = Mutex::<NoopRawMutex, _>::new(&mut self.key_schedule);
        let socket = &self.socket;

        match select(
            rx_worker::<Socket, Sender, Receiver>(socket, rx_sender, rx_buffer, &key_schedule),
            tx_worker::<Socket, Sender, Receiver>(
                socket,
                tx_receiver,
                tx_buffer,
                &key_schedule,
                delay,
            ),
        )
        .await
        {
            Either::First(f) => f,
            Either::Second(s) => s,
        }
    }
}

// Tasks:

// 1. App data handling

// 2. Alert handling

// 3. Heartbeat handling (read/write)

// 4. Key updates

// 5. Close connection

// TODO: How to indicate that TX should do something special for handling internal work?
//       such as heartbeat request/response or send ACK ASAP?
async fn tx_worker<Socket, Sender, Receiver>(
    socket: &Socket,
    tx_receiver: &mut Receiver,
    tx_buffer: &mut [u8],
    key_schedule: &Mutex<NoopRawMutex, &mut impl GenericKeySchedule>,
    delay: &mut impl DelayNs,
) -> Result<Infallible, ErrorHelper<Socket, Sender, Receiver>>
where
    Socket: Endpoint,
    Sender: ApplicationDataSender,
    Receiver: ApplicationDataReceiver,
{
    'outer: loop {
        let buf = &mut EncodingBuffer::new(tx_buffer);

        {
            let payload = tx_receiver
                .peek()
                .await
                .map_err(|e| ConnectionError::ReceiveError(e))?;

            // Encode payload, this is on a fresh buffer and should not fail.
            if let Err(e) =
                Record::encode_application_data(buf, *key_schedule.lock().await, payload.as_ref())
                    .await
            {
                error!("Encoding of application data failed with error = {:?}", e);
                continue 'outer;
            }
        }

        // Set a timeout for filling more data into the datagram.
        // TODO: Make settable.
        let mut timeout = pin!(delay.delay_ms(10));

        // Continue filling the buffer until timeout, or full.
        'stuffer: loop {
            tx_receiver
                .pop()
                .map_err(|e| ConnectionError::ReceiveError(e))?;

            // We only want to cancel the peek with timeout, not encoding of data.
            let payload = match select(&mut timeout, tx_receiver.peek()).await {
                Either::First(_) => break 'stuffer,
                Either::Second(p) => p.map_err(|e| ConnectionError::ReceiveError(e))?,
            };

            // No need to waste time encoding the payload if we know it won't fit.
            if payload.as_ref().len() + MINIMUM_CIPHERTEXT_OVERHEAD > buf.space_left() {
                debug!("Predicted TX buffer full");
                break 'stuffer;
            }

            // Encode payload.
            if Record::encode_application_data(buf, *key_schedule.lock().await, payload.as_ref())
                .await
                .is_err()
            {
                debug!("TX buffer full, without predicting");
                break 'stuffer;
            }
        }

        // Send the finished buffer.
        socket
            .send(&buf)
            .await
            .map_err(|e| ConnectionError::DtlsError(Error::Send(e)))?;
    }
}

async fn rx_worker<Socket, Sender, Receiver>(
    socket: &Socket,
    rx_sender: &mut Sender,
    rx_buffer: &mut [u8],
    key_schedule: &Mutex<NoopRawMutex, &mut impl GenericKeySchedule>,
) -> Result<Infallible, ErrorHelper<Socket, Sender, Receiver>>
where
    Socket: Endpoint,
    Sender: ApplicationDataSender,
    Receiver: ApplicationDataReceiver,
{
    loop {
        let mut data = socket
            .recv(rx_buffer)
            .await
            .map_err(|e| ConnectionError::DtlsError(Error::Recv(e)))?;

        while !data.is_empty() {
            match Record::parse(|_| {}, &mut data, Some(*key_schedule.lock().await)).await {
                Some((r, _)) => match r {
                    Record::Handshake(_, _) => {
                        debug!("Parsed a handshake");
                        trace!("{:?}", r);
                        // TODO: Perform key update (if it is key update)

                        todo!();
                    }
                    Record::Alert(_, _) => {
                        debug!("Parsed an alert");
                        trace!("{:?}", r);
                        // TODO: Handle alert, maybe close connection

                        todo!();
                    }
                    Record::Ack(_, _) => {
                        debug!("Parsed an ack");
                        trace!("{:?}", r);
                        // TODO: Check if it's ACK for the key update

                        todo!();
                    }
                    Record::Heartbeat(_) => {
                        debug!("Parsed a heartbeat");
                        trace!("{:?}", r);
                        // TODO: Send response (if we support it)

                        todo!();
                    }
                    Record::ApplicationData(data) => {
                        debug!("Parsed application data");
                        trace!("{:?}", data);

                        rx_sender
                            .send(data)
                            .await
                            .map_err(|e| ConnectionError::SendError(e))?;
                    }
                },
                None => {
                    debug!("Parsing of record failed");
                }
            }
        }
    }
}
