use crate::{
    buffer::EncodingBuffer,
    record::{GenericKeySchedule, Record, MINIMUM_CIPHERTEXT_OVERHEAD},
    ApplicationDataReceiver, ApplicationDataSender, Error, RxEndpoint, TxEndpoint,
};
use core::{convert::Infallible, ops::DerefMut, pin::pin};
use defmt_or_log::{debug, derive_format_or_debug, error, trace};
use embassy_futures::select::{select, Either};
use embedded_hal_async::delay::DelayNs;
use select_sharing::Mutex;

mod select_sharing;

// Tasks:
//
// 1. App data handling
//
// 2. Alert handling
//
// 3. Heartbeat handling (read/write)
//
// 4. Key updates
//
// 5. Close connection

/// Error definitions.
#[derive_format_or_debug]
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum ConnectionError<E, S, R> {
    DtlsError(E),
    SendError(S),
    ReceiveError(R),
}

type ErrorHelper<RxE, TxE, S, R> = ConnectionError<
    Error<RxE, TxE>,
    <S as ApplicationDataSender>::Error,
    <R as ApplicationDataReceiver>::Error,
>;

/// A DTLS 1.3 connection.
pub struct Connection<RxE, TxE, KeySchedule>
where
    RxE: RxEndpoint,
    TxE: TxEndpoint,
    KeySchedule: GenericKeySchedule,
{
    /// Receiver of data.
    pub(crate) rx_endpoint: RxE,
    /// Sender of data.
    pub(crate) tx_endpoint: TxE,
    /// Keys for client->server and server->client.
    pub(crate) key_schedule: KeySchedule,
}

/// State that is shared between the RX and TX worker.
struct SharedState<KeySchedule>
where
    KeySchedule: GenericKeySchedule,
{
    key_schedule: Mutex<KeySchedule>,
}

impl<RxE, TxE, KeySchedule> Connection<RxE, TxE, KeySchedule>
where
    RxE: RxEndpoint,
    TxE: TxEndpoint,
    KeySchedule: GenericKeySchedule,
{
    /// Run the connection and serve the application data queues. This will return when the
    /// connection is closed.
    ///
    /// The `{rx, tx}_buffer` should ideally be the size of the MTU, but may be less as well.
    pub async fn run<Receiver, Sender>(
        self,
        rx_buffer: &mut [u8],
        tx_buffer: &mut [u8],
        rx_sender: &mut Sender,
        tx_receiver: &mut Receiver,
        delay: impl DelayNs + Clone,
    ) -> Result<Infallible, ErrorHelper<RxE, TxE, Sender, Receiver>>
    where
        Sender: ApplicationDataSender,
        Receiver: ApplicationDataReceiver,
    {
        let shared_state = &SharedState {
            key_schedule: Mutex::new(self.key_schedule),
        };
        let rx_endpoint = self.rx_endpoint;
        let tx_endpoint = self.tx_endpoint;

        match select(
            rx_worker::<_, TxE, _, Receiver>(rx_endpoint, rx_sender, rx_buffer, shared_state),
            tx_worker::<RxE, _, Sender, _>(
                tx_endpoint,
                tx_receiver,
                tx_buffer,
                shared_state,
                delay.clone(),
            ),
        )
        .await
        {
            Either::First(f) => f,
            Either::Second(s) => s,
        }
    }
}

// Section B.2, RFC9147 gives the maximum to 2^23.5 ~ 11.86M encodings.
#[cfg(not(feature = "testing_key_updates"))]
const MAX_PACKETS_BEFORE_KEY_UPDATE: u64 = 11_500_000;

// For testing KeyUpdate.
#[cfg(feature = "testing_key_updates")]
const MAX_PACKETS_BEFORE_KEY_UPDATE: u64 = 100;

// TODO: How to indicate that TX should do something special for handling internal work?
//       such as heartbeat request/response or send ACK ASAP?
async fn tx_worker<RxE, TxE, Sender, Receiver>(
    mut tx_endpoint: TxE,
    tx_receiver: &mut Receiver,
    tx_buffer: &mut [u8],
    shared_state: &SharedState<impl GenericKeySchedule>,
    mut delay: impl DelayNs,
) -> Result<Infallible, ErrorHelper<RxE, TxE, Sender, Receiver>>
where
    TxE: TxEndpoint,
    RxE: RxEndpoint,
    Sender: ApplicationDataSender,
    Receiver: ApplicationDataReceiver,
{
    'outer: loop {
        let buf = &mut EncodingBuffer::new(tx_buffer);

        if shared_state.key_schedule.lock().await.write_record_number()
            > MAX_PACKETS_BEFORE_KEY_UPDATE
        {
            // TODO: Perform key update.
            todo!()
        }

        {
            debug!("TX waiting for data");
            let payload = tx_receiver
                .peek()
                .await
                .map_err(ConnectionError::ReceiveError)?;

            // Encode payload, this is on a fresh buffer and should not fail.
            if let Err(e) = Record::encode_application_data(
                buf,
                shared_state.key_schedule.lock().await.deref_mut(),
                payload.as_ref(),
            )
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
            tx_receiver.pop().map_err(ConnectionError::ReceiveError)?;

            // We only want to cancel the peek with timeout, not encoding of data.
            let payload = match select(&mut timeout, tx_receiver.peek()).await {
                Either::First(_) => break 'stuffer,
                Either::Second(p) => p.map_err(ConnectionError::ReceiveError)?,
            };

            // No need to waste time encoding the payload if we know it won't fit.
            if payload.as_ref().len() + MINIMUM_CIPHERTEXT_OVERHEAD > buf.space_left() {
                debug!("Predicted TX buffer full");
                break 'stuffer;
            }

            // Encode payload.
            if Record::encode_application_data(
                buf,
                shared_state.key_schedule.lock().await.deref_mut(),
                payload.as_ref(),
            )
            .await
            .is_err()
            {
                debug!("TX buffer full, without predicting");
                break 'stuffer;
            }
        }

        // Send the finished buffer.
        tx_endpoint
            .send(buf)
            .await
            .map_err(|e| ConnectionError::DtlsError(Error::Send(e)))?;
    }
}

async fn rx_worker<RxE, TxE, Sender, Receiver>(
    mut rx_endpoint: RxE,
    rx_sender: &mut Sender,
    rx_buffer: &mut [u8],
    shared_state: &SharedState<impl GenericKeySchedule>,
) -> Result<Infallible, ErrorHelper<RxE, TxE, Sender, Receiver>>
where
    RxE: RxEndpoint,
    TxE: TxEndpoint,
    Sender: ApplicationDataSender,
    Receiver: ApplicationDataReceiver,
{
    loop {
        debug!("RX waiting for data");
        let mut data = rx_endpoint
            .recv(rx_buffer)
            .await
            .map_err(|e| ConnectionError::DtlsError(Error::Recv(e)))?;

        while !data.is_empty() {
            let record = Record::parse(
                |_| {},
                &mut data,
                Some(shared_state.key_schedule.lock().await.deref_mut()),
            )
            .await;
            match record {
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
                            .map_err(ConnectionError::SendError)?;
                    }
                },
                None => {
                    debug!("Parsing of record failed");
                }
            }
        }
    }
}
