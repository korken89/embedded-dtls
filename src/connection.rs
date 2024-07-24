use crate::{
    buffer::EncodingBuffer,
    record::{GenericKeySchedule, HeartbeatMessageType, Record, MINIMUM_CIPHERTEXT_OVERHEAD},
    ApplicationDataReceiver, ApplicationDataSender, Error, RxEndpoint, TxEndpoint,
};
use core::{convert::Infallible, ops::DerefMut, pin::pin};
use defmt_or_log::{debug, derive_format_or_debug, error, trace};
use embassy_futures::select::{select, select3, Either, Either3};
use select_sharing::Mutex;

use self::heartbeat::{DomesticHeartbeat, ForeignHeartbeat};

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
struct SharedState<KeySchedule> {
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
    /// The `{rx, tx, heartbeat}_buffer` should ideally be the size of the MTU, but may be less as well.
    /// TODO: Should heartbeat_buffer have a different limit
    pub async fn run<Receiver, Sender, Delay>(
        self,
        rx_buffer: &mut [u8],
        tx_buffer: &mut [u8],
        hb_buffer: &mut [u8],
        rx_sender: &mut Sender,
        tx_receiver: &mut Receiver,
        delay: Delay,
    ) -> Result<Infallible, ErrorHelper<RxE, TxE, Sender, Receiver>>
    where
        Sender: ApplicationDataSender,
        Receiver: ApplicationDataReceiver,
        Delay: crate::Delay,
    {
        let shared_state = &SharedState {
            key_schedule: Mutex::new(self.key_schedule),
        };
        let rx_endpoint = self.rx_endpoint;
        let record_transmitter = Mutex::new(RecordTransmitter::new(
            tx_buffer,
            self.tx_endpoint,
            shared_state,
        ));
        let fhb = ForeignHeartbeat::new(hb_buffer);
        let hb = DomesticHeartbeat::new(delay.clone());

        match select3(
            rx_worker::<RxE, TxE, Sender, Receiver, Delay>(
                rx_endpoint,
                rx_sender,
                rx_buffer,
                shared_state,
                &fhb,
                &hb,
            ),
            tx_worker::<RxE, TxE, Sender, Receiver, Delay>(
                &record_transmitter,
                tx_receiver,
                shared_state,
                delay.clone(),
            ),
            select(
                hb.worker::<RxE, TxE, Sender, Receiver>(&record_transmitter),
                fhb.worker::<RxE, TxE, Sender, Receiver>(&record_transmitter),
            ),
        )
        .await
        {
            Either3::First(f) => f,
            Either3::Second(s) => s,
            Either3::Third(t) => match t {
                Either::First(f) => f,
                Either::Second(s) => s,
            },
        }
    }
}

mod heartbeat {
    use core::convert::Infallible;

    use defmt_or_log::info;
    use defmt_or_log::{derive_format_or_debug, error, trace, warn};
    use embassy_futures::select::{select, Either};

    use crate::{
        buffer::OutOfMemory,
        record::{GenericKeySchedule, HeartbeatMessageType},
        ApplicationDataReceiver, ApplicationDataSender, Error, Instant, RxEndpoint, TxEndpoint,
    };

    use super::{
        select_sharing::{Mutex, Signal},
        ErrorHelper, RecordTransmitter,
    };

    pub struct ForeignHeartbeat<'a> {
        // TODO: Add the configuration from the handshake
        /// Signal for Self::worker, response is ready for shipping
        request_arrived: Signal<usize>,
        buffer: Mutex<&'a mut [u8]>,
    }

    impl<'a> ForeignHeartbeat<'a> {
        pub fn new(buffer: &'a mut [u8]) -> Self {
            Self {
                request_arrived: Signal::new(),
                buffer: Mutex::new(buffer),
            }
        }

        pub async fn new_request_payload(&self, payload: &[u8]) -> Result<(), OutOfMemory> {
            let Some(mut buffer) = self.buffer.try_lock().await else {
                warn!("Previous request is still being processed, other party is too fast? Dropping.");
                return Ok(());
            };
            let payload_len = payload.len();
            if buffer.len() < payload_len {
                return Err(OutOfMemory);
            }
            if self.request_arrived.try_send(payload_len) {
                (&mut buffer[..payload_len]).copy_from_slice(payload);
            } else {
                warn!("Previous request is not processed yet, other party is too fast? Dropping.");
            }
            Ok(())
        }

        pub async fn worker<'b, RxE, TxE, Sender, Receiver>(
            &self,
            rt: &Mutex<RecordTransmitter<'b, TxE, impl GenericKeySchedule>>,
        ) -> Result<Infallible, ErrorHelper<RxE, TxE, Sender, Receiver>>
        where
            RxE: RxEndpoint,
            TxE: TxEndpoint,
            Sender: ApplicationDataSender,
            Receiver: ApplicationDataReceiver,
        {
            loop {
                let payload_len = self.request_arrived.recv().await;
                // Hold the lock to the buffer until we flush to uphold the invariant of the state machine.
                let buffer = self.buffer.lock().await;
                let mut rt = rt.lock().await;
                rt.enqueue_heartbeat(HeartbeatMessageType::Response, &buffer[..payload_len])
                    .await?;
                rt.flush().await?;
            }
        }
    }

    pub struct DomesticHeartbeat<D: crate::Delay> {
        // TODO: Add the configuration from the handshake
        /// Signal indicating that a response arrived
        response_arrived: Signal<(usize, D::Instant)>,
        // Buffer for responses hidden behind a mutex
        buffer: Mutex<[u8; 64]>,
        delay: D,
    }

    impl<D: crate::Delay> DomesticHeartbeat<D> {
        pub(crate) fn new(delay: D) -> Self {
            Self {
                response_arrived: Signal::new(),
                buffer: Mutex::new([0_u8; 64]),
                delay,
            }
        }

        pub async fn new_response_payload(&self, payload: &[u8]) -> Result<(), OutOfMemory> {
            let Some(mut buffer) = self.buffer.try_lock().await else {
                warn!(
                    "Previous response is currently being processed, unsolicited response? Dropping."
                );
                return Ok(());
            };
            let buffer = &mut *buffer;
            let payload_len = payload.len();
            if buffer.len() < payload_len {
                return Err(OutOfMemory);
            }
            if self
                .response_arrived
                .try_send((payload_len, self.delay.now()))
            {
                (&mut buffer[..payload_len]).copy_from_slice(payload);
            } else {
                warn!("Previous response is not processed yet, unsolicited response? Dropping.");
            }
            Ok(())
        }

        pub async fn worker<'a, RxE, TxE, Sender, Receiver>(
            &self,
            record_transmitter: &Mutex<RecordTransmitter<'a, TxE, impl GenericKeySchedule>>,
        ) -> Result<Infallible, ErrorHelper<RxE, TxE, Sender, Receiver>>
        where
            RxE: RxEndpoint,
            TxE: TxEndpoint,
            Sender: ApplicationDataSender,
            Receiver: ApplicationDataReceiver,
        {
            let mut delay = self.delay.clone();
            const REFERENCE_PAYLOAD_LEN: usize = 64;
            let mut payload_filler: u8 = 0;
            loop {
                let reference_payload = [payload_filler; REFERENCE_PAYLOAD_LEN];
                let mut request_sent_instant;
                {
                    let _ = self.buffer.lock().await;
                    let mut rt = record_transmitter.lock().await;
                    trace!("Enqueuing a heartbeat request");
                    rt.enqueue_heartbeat(HeartbeatMessageType::Request, &reference_payload)
                        .await?;
                    trace!("Sending a heartbeat request");
                    rt.flush().await?;
                    trace!("Sent a heartbeat request");
                    request_sent_instant = delay.now();
                }
                // TODO: Overflows? :|
                let mut deadline = delay.now().add_s(1);
                let mut retransmission_counter = 0;
                'retransmission: loop {
                    trace!("Wait for a heartbeat response (");
                    let response_arrived_or_timeout =
                        select(self.response_arrived.recv(), delay.delay_until(deadline)).await;
                    let mut buffer = self.buffer.lock().await;
                    let buffer = &mut *buffer;
                    match response_arrived_or_timeout {
                        Either::First((response_payload_len, response_arrived_instant)) => {
                            trace!("response_arrived::recv() DONE");
                            if &buffer[..response_payload_len] != &reference_payload {
                                warn!("Heartbeat response has unexpected payload. Ignoring");
                                // Throttle in case we are _timely_ bombarded with unsolicited messages
                                delay.delay_ms(100).await;
                            } else {
                                let latency =
                                    response_arrived_instant.sub_as_ms(&request_sent_instant);
                                info!(
                                    "Heartbeat request - response loop succeeded. Latency: {} ms",
                                    latency
                                );
                                // Hold `buffer` guard here while sleeping in order to reject unsolicited heartbeat responses on RX
                                delay.delay_ms(1000).await;
                                break 'retransmission;
                            }
                        }
                        Either::Second(_timeout) => {
                            trace!("response_arrived::recv() TIMED OUT");
                            const R_CNT_MAX: u8 = 7;
                            if retransmission_counter >= R_CNT_MAX {
                                error!(
                                    "Retransmission counter reached {} attempts. Terminating connection.",
                                    R_CNT_MAX
                                );
                                return Err(ErrorHelper::<RxE, TxE, Sender, Receiver>::DtlsError(
                                    Error::TooManyRetransmissions,
                                ));
                            }
                            retransmission_counter += 1;
                            warn!(
                                "Waiting for heartbeat response timed out, retransmitting ({}/{})",
                                retransmission_counter, R_CNT_MAX
                            );
                            let mut rt = record_transmitter.lock().await;
                            trace!("Enqueuing a heartbeat request retransmission");
                            rt.enqueue_heartbeat(HeartbeatMessageType::Request, &reference_payload)
                                .await?;
                            trace!("Sending a heartbeat request retransmission");
                            rt.flush().await?;
                            trace!("Sent a heartbeat request retransmission");
                            request_sent_instant = delay.now();
                            // TODO: Overflows? :|
                            deadline = deadline.add_s(1);
                        }
                    };
                }
                payload_filler = payload_filler.wrapping_add(1);
            }
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
async fn tx_worker<'a, RxE, TxE, Sender, Receiver, Delay>(
    record_transmitter: &Mutex<RecordTransmitter<'a, TxE, impl GenericKeySchedule>>,
    tx_receiver: &mut Receiver,
    shared_state: &SharedState<impl GenericKeySchedule>,
    mut delay: Delay,
) -> Result<Infallible, ErrorHelper<RxE, TxE, Sender, Receiver>>
where
    RxE: RxEndpoint,
    TxE: TxEndpoint,
    Sender: ApplicationDataSender,
    Receiver: ApplicationDataReceiver,
    Delay: crate::Delay,
{
    'outer: loop {
        // TODO: This logic has to be moved out into the separate worker
        // I think that all code that tries to access `key_schedule`
        // (that is encrypt the message), should block and wait until the
        // "key_schedule_update_worker" provides fresh keys.
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
            if let Err(e) = record_transmitter
                .lock()
                .await
                .enqueue_application_data(payload.as_ref())
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

            let mut rt = record_transmitter.lock().await;

            // No need to waste time encoding the payload if we know it won't fit.
            if payload.as_ref().len() + MINIMUM_CIPHERTEXT_OVERHEAD > rt.space_left() {
                debug!("Predicted TX buffer full");
                break 'stuffer;
            }

            // Encode payload.
            if rt.enqueue_application_data(payload.as_ref()).await.is_err() {
                debug!("TX buffer full, without predicting");
                break 'stuffer;
            }
        }

        // Send the finished buffer.
        debug!("Sending application data");
        record_transmitter.lock().await.flush().await?;
        debug!("Sent application data");
    }
}

async fn rx_worker<'a, RxE, TxE, Sender, Receiver, Delay>(
    mut rx_endpoint: RxE,
    rx_sender: &mut Sender,
    rx_buffer: &mut [u8],
    shared_state: &SharedState<impl GenericKeySchedule>,
    fhb: &ForeignHeartbeat<'a>,
    hb: &heartbeat::DomesticHeartbeat<Delay>,
) -> Result<Infallible, ErrorHelper<RxE, TxE, Sender, Receiver>>
where
    RxE: RxEndpoint,
    TxE: TxEndpoint,
    Sender: ApplicationDataSender,
    Receiver: ApplicationDataReceiver,
    Delay: crate::Delay,
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
                Some((r, _)) => {
                    match r {
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
                        Record::Heartbeat(ref heartbeat) => {
                            debug!("Parsed a heartbeat");
                            trace!("{:?}", r);
                            match heartbeat.type_ {
                                HeartbeatMessageType::Request => {
                                    fhb.new_request_payload(heartbeat.payload).await.map_err(
                                        |_| ConnectionError::DtlsError(Error::InsufficientSpace),
                                    )?
                                }
                                HeartbeatMessageType::Response => {
                                    hb.new_response_payload(heartbeat.payload).await.map_err(
                                        |_| ConnectionError::DtlsError(Error::InsufficientSpace),
                                    )?
                                }
                            };
                        }
                        Record::ApplicationData(data) => {
                            debug!("Parsed application data");
                            trace!("{:?}", data);

                            rx_sender
                                .send(data)
                                .await
                                .map_err(ConnectionError::SendError)?;
                        }
                    }
                }
                None => {
                    debug!("Parsing of record failed");
                }
            }
        }
    }
}

pub struct RecordTransmitter<'a, TxE, KeySchedule> {
    encoding_buffer: EncodingBuffer<'a>,
    tx_endpoint: TxE,
    shared_state: &'a SharedState<KeySchedule>,
}

#[derive_format_or_debug]
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum RecordTransmitterError<TxE: TxEndpoint> {
    OutOfMemory,
    Send(TxE::SendError),
}

impl<RxE: RxEndpoint, TxE: TxEndpoint, S, R> From<RecordTransmitterError<TxE>>
    for ConnectionError<Error<RxE, TxE>, S, R>
{
    fn from(value: RecordTransmitterError<TxE>) -> Self {
        match value {
            RecordTransmitterError::OutOfMemory => Self::DtlsError(Error::InsufficientSpace),
            RecordTransmitterError::Send(e) => Self::DtlsError(Error::Send(e)),
        }
    }
}

impl<'a, TxE, KeySchedule> RecordTransmitter<'a, TxE, KeySchedule> {
    fn new(
        buffer: &'a mut [u8],
        tx_endpoint: TxE,
        shared_state: &'a SharedState<KeySchedule>,
    ) -> Self {
        Self {
            encoding_buffer: EncodingBuffer::new(buffer),
            tx_endpoint,
            shared_state,
        }
    }
}
impl<'a, TxE: TxEndpoint, KeySchedule: GenericKeySchedule> RecordTransmitter<'a, TxE, KeySchedule> {
    async fn enqueue_heartbeat(
        &mut self,
        type_: HeartbeatMessageType,
        payload: &[u8],
    ) -> Result<(), RecordTransmitterError<TxE>> {
        Record::encode_heartbeat(
            &mut self.encoding_buffer,
            self.shared_state.key_schedule.lock().await.deref_mut(),
            payload,
            type_,
        )
        .await
        .map_err(|_: crate::buffer::OutOfMemory| RecordTransmitterError::OutOfMemory)
    }

    async fn enqueue_application_data(
        &mut self,
        payload: &[u8],
    ) -> Result<(), RecordTransmitterError<TxE>> {
        Record::encode_application_data(
            &mut self.encoding_buffer,
            self.shared_state.key_schedule.lock().await.deref_mut(),
            payload,
        )
        .await
        .map_err(|_: crate::buffer::OutOfMemory| RecordTransmitterError::OutOfMemory)
    }

    fn space_left(&self) -> usize {
        self.encoding_buffer.space_left()
    }

    async fn flush(&mut self) -> Result<(), RecordTransmitterError<TxE>> {
        let r = self
            .tx_endpoint
            .send(&self.encoding_buffer)
            .await
            .map_err(|e| RecordTransmitterError::Send(e));
        self.encoding_buffer.reset();
        r
    }
}
