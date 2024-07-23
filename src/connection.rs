use crate::{
    buffer::EncodingBuffer,
    record::{GenericKeySchedule, HeartbeatMessageType, Record, MINIMUM_CIPHERTEXT_OVERHEAD},
    ApplicationDataReceiver, ApplicationDataSender, Error, RxEndpoint, TxEndpoint,
};
use core::{convert::Infallible, ops::DerefMut, pin::pin};
use defmt_or_log::{debug, derive_format_or_debug, error, info, trace, warn};
use embassy_futures::select::{select, select3, Either, Either3};
use select_sharing::Mutex;

use self::heartbeat::Heartbeat;

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
        let hb = Heartbeat::new(hb_buffer, delay.clone());

        match select3(
            rx_worker::<RxE, TxE, Sender, Receiver, Delay>(
                rx_endpoint,
                rx_sender,
                rx_buffer,
                shared_state,
                &hb,
            ),
            tx_worker::<RxE, TxE, Sender, Receiver, Delay>(
                &record_transmitter,
                tx_receiver,
                shared_state,
                delay.clone(),
                &hb,
            ),
            heartbeat_worker::<RxE, TxE, Sender, Receiver, Delay>(&record_transmitter, delay, &hb),
        )
        .await
        {
            Either3::First(f) => f,
            Either3::Second(s) => s,
            Either3::Third(t) => t,
        }
    }
}

async fn heartbeat_worker<'a, RxE, TxE, Sender, Receiver, Delay>(
    record_transmitter: &Mutex<RecordTransmitter<'a, TxE, impl GenericKeySchedule>>,
    mut delay: Delay,
    hb: &Heartbeat<'_, Delay>,
) -> Result<Infallible, ErrorHelper<RxE, TxE, Sender, Receiver>>
where
    RxE: RxEndpoint,
    TxE: TxEndpoint,
    Sender: ApplicationDataSender,
    Receiver: ApplicationDataReceiver,
    Delay: crate::Delay,
{
    let hb = &hb;
    const REFERENCE_PAYLOAD_LEN: usize = 64;
    loop {
        // TODO: Replace with some RNG
        let reference_payload = [0xAB_u8; REFERENCE_PAYLOAD_LEN];
        {
            let mut guard = hb.out_in.lock().await;
            let (_, state) = &mut *guard;
            match *state {
                heartbeat::DomesticHeartbeatState::Empty => {
                    let mut rt = record_transmitter.lock().await;
                    rt.enqueue_heartbeat(HeartbeatMessageType::Request, &reference_payload)
                        .await
                        .inspect_err(|e| {
                            error!(
                            "Heartbeat request enqueuing failed ({:?})! Terminating connection.",
                            e
                        );
                        })?;
                    trace!("Sending heartbeat request");
                    rt.flush().await.inspect_err(|e| {
                        error!(
                            "Heartbeat request sending failed ({:?})! Terminating connection.",
                            e
                        );
                    })?;
                    *state = heartbeat::DomesticHeartbeatState::InFlight;
                }
                state => {
                    error!(
                        "Trying to setup the heartbeat but state is invalid: {:?}",
                        state
                    );
                    return Err(ErrorHelper::<RxE, TxE, Sender, Receiver>::DtlsError(
                        Error::Placeholder,
                    ));
                }
            }
        }
        let mut retransmission_counter = 0;
        'retransmission: loop {
            trace!("response_arrived::recv() WAIT (with timeout)");
            let result = select(hb.response_arrived.recv(), delay.delay_ms(1000)).await;
            let mut guard = hb.out_in.lock().await;
            let (buffer, state) = &mut *guard;
            match result {
                Either::First((response_payload_len, _response_arrived_instant)) => match *state {
                    heartbeat::DomesticHeartbeatState::In => {
                        trace!("response_arrived::recv() DONE");
                        let mut is_payload_validated = true;
                        if response_payload_len != REFERENCE_PAYLOAD_LEN {
                            warn!("Heartbeat response payload has unexpected length: {}, expected: {}.",response_payload_len,REFERENCE_PAYLOAD_LEN, );
                            is_payload_validated = false;
                        }
                        if &buffer[..response_payload_len] != &reference_payload {
                            warn!("Heartbeat response payload has unexpected payload.");
                            is_payload_validated = false;
                        }
                        if is_payload_validated {
                            *state = heartbeat::DomesticHeartbeatState::Empty;
                            // let latency = response_arrived_instant.sub_as_ms(&request_sent_instant);
                            info!("Heartbeat request - response loop succeeded",);
                            delay.delay_ms(1000).await;
                            break 'retransmission;
                        }
                    }
                    state => {
                        trace!("response_arrived::recv() DONE");
                        error!("Heartbeat response arrival is being signalled but state is invalid: {:?}.", state);
                        return Err(ErrorHelper::<RxE, TxE, Sender, Receiver>::DtlsError(
                            Error::Placeholder,
                        ));
                    }
                },
                // Timeout
                Either::Second(_) => {
                    trace!("response_arrived::recv() TIMED OUT");
                    const R_CNT_MAX: u8 = 3;
                    if retransmission_counter >= R_CNT_MAX {
                        error!(
                            "Retransmission counter reached {} attempts. Terminating connection.",
                            R_CNT_MAX
                        );
                        return Err(ErrorHelper::<RxE, TxE, Sender, Receiver>::DtlsError(
                            Error::Placeholder,
                        ));
                    } else {
                        warn!(
                            "Heartbeat response timed out ({}/{} retransmissions)",
                            retransmission_counter, R_CNT_MAX
                        );
                    }
                }
            }
            let mut rt = record_transmitter.lock().await;
            rt.enqueue_heartbeat(HeartbeatMessageType::Request, &reference_payload)
                .await
                .inspect_err(|e| {
                    error!(
                        "Heartbeat request enqueuing failed ({:?})! Terminating connection.",
                        e
                    );
                })?;
            trace!("Sending heartbeat request");
            rt.flush().await.inspect_err(|e| {
                error!(
                    "Heartbeat request sending failed ({:?})! Terminating connection.",
                    e
                );
            })?;
            *state = heartbeat::DomesticHeartbeatState::InFlight;
            retransmission_counter += 1;
        }
    }
}

mod heartbeat {
    use defmt_or_log::{debug, derive_format_or_debug, trace, warn};

    use crate::record::{self, HeartbeatMessageType};

    use super::select_sharing::{Mutex, Signal};

    #[derive_format_or_debug]
    #[derive(Copy, Clone)]
    pub enum ForeignHeartbeatState {
        /// Buffer is empty and available for writes
        Empty,
        /// Buffer is occupied by _their_ heartbeat payload which awaits encryption & transmission
        /// `transmit_response` should have been triggered.
        In,
    }

    #[derive_format_or_debug]
    #[derive(Copy, Clone)]
    pub enum DomesticHeartbeatState {
        /// Buffer is empty and available for writes for our requests
        Empty,
        /// Buffer is not relevant anymore. Response is being awaited.
        InFlight,
        /// Buffer is occupied by _their_ heartbeat payload and awaits validation
        /// `response_arrived` should have been triggered.
        In,
    }

    // TODO: Consider splitting Heartbeat into two types: one for foreign and one
    // for domestic heartbeats. Then, the whole type should be behind a Mutex and
    // not its internal fields. Mutation analysis should also become simplier
    pub struct Heartbeat<'a, D: crate::Delay> {
        // TODO: Add the configuration from the handshake
        /// Signal for tx_worker, response is ready for shipping
        /// Such heartbeat should be prioritised by the worker
        /// and should interrupt enqueueing and ship the UDP datagram
        /// immediately
        pub transmit_response: Signal<usize>,
        /// Signal for heartbeat worker, response to our request arrived
        pub response_arrived: Signal<(usize, D::Instant)>,
        /// Buffer for their heartbeats requests and our heartbeat responses.
        /// It is unknown how big the payload is so we have to be flexible
        /// Only one heartbeat can be "in flight" so it can be shared
        pub in_out: Mutex<(&'a mut [u8], ForeignHeartbeatState)>,
        /// Buffer for our heartbeats requests and their heartbeat responses.
        /// We generate the payload and thus we cap it at some small upper limit
        /// Only one heartbeat can be "in flight" so it can be shared
        pub out_in: Mutex<([u8; 64], DomesticHeartbeatState)>,
        delay: D,
    }

    impl<'a, D: crate::Delay> Heartbeat<'a, D> {
        pub(crate) fn new(buffer: &'a mut [u8], delay: D) -> Self {
            Self {
                transmit_response: Signal::new(),
                response_arrived: Signal::new(),
                in_out: Mutex::new((buffer, ForeignHeartbeatState::Empty)),
                out_in: Mutex::new(([0_u8; 64], DomesticHeartbeatState::Empty)),
                delay,
            }
        }

        pub async fn new_record(&self, record: &record::Heartbeat<'_>) {
            debug!("New heartbeat arrived: {:?}", record.type_);
            match record.type_ {
                HeartbeatMessageType::Request => {
                    let mut guard = self.in_out.lock().await;
                    let (buffer, state) = &mut *guard;
                    match *state {
                        ForeignHeartbeatState::Empty => {
                            let payload = record.payload;
                            let payload_len = payload.len();
                            if buffer.len() < payload_len {
                                // TODO: Should not be a panic
                                panic!("Buffer is too small");
                            }
                            *state = ForeignHeartbeatState::In;
                            trace!("transmit_response::send({}) WAIT", payload_len);
                            self.transmit_response.send(payload_len).await;
                            trace!("transmit_response::send({}) DONE", payload_len);
                            (&mut buffer[..payload_len]).copy_from_slice(payload);
                        }
                        // TODO: I assume that some alert should be sent out as well.
                        ForeignHeartbeatState::In => {
                            warn!("New heartbeat request even though the old is 'in-flight'? Dropping");
                        }
                    }
                }
                HeartbeatMessageType::Response => {
                    let mut guard = self.out_in.lock().await;
                    let (buffer, state) = &mut *guard;
                    match *state {
                        DomesticHeartbeatState::InFlight => {
                            let payload = record.payload;
                            let payload_len = payload.len();
                            if buffer.len() < payload_len {
                                // TODO: Should not be a panic
                                panic!("Buffer is too small");
                            }
                            *state = DomesticHeartbeatState::In;
                            trace!("response_arrived::send(({}, _)) WAIT", payload_len);
                            self.response_arrived
                                .send((payload_len, self.delay.now()))
                                .await;
                            trace!("response_arrived::send(({}, _)) DONE", payload_len);
                            (&mut buffer[..payload_len]).copy_from_slice(payload);
                        }
                        state => {
                            // TODO: I assume that some alert should be sent out as well.
                            warn!(
                                "Heartbeat response arrived but state is: {:?}. Unsolicited response? Dropping",
                                state
                            );
                        }
                    }
                }
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
    hb: &heartbeat::Heartbeat<'a, Delay>,
) -> Result<Infallible, ErrorHelper<RxE, TxE, Sender, Receiver>>
where
    TxE: TxEndpoint,
    RxE: RxEndpoint,
    Sender: ApplicationDataSender,
    Receiver: ApplicationDataReceiver,
    Delay: crate::Delay,
{
    'outer: loop {
        if shared_state.key_schedule.lock().await.write_record_number()
            > MAX_PACKETS_BEFORE_KEY_UPDATE
        {
            // TODO: Perform key update.
            todo!()
        }

        {
            debug!("TX waiting for data or heartbeat transmission");
            let payload = match select(hb.transmit_response.recv(), tx_receiver.peek()).await {
                Either::First(response_payload_len) => {
                    trace!("transmit_response::recv() DONE");
                    let mut guard = hb.in_out.lock().await;
                    let (buffer, state) = &mut *guard;
                    match *state {
                        heartbeat::ForeignHeartbeatState::In => {
                            let mut rt = record_transmitter.lock().await;
                            rt.enqueue_heartbeat(
                                 HeartbeatMessageType::Response,
                                 &buffer[..response_payload_len],
                            ).await
                             .inspect_err(|e| {
                                 // TODO: Should only happen if tx_buffer is smaller than rx_buffer and hb_buffer?
                                 error!("Heartbeat response enqueuing failed ({:?})! Terminating connection.", e);
                             })?;
                            trace!("Sending heartbeat response");
                            rt.flush().await.inspect_err(|e| {
                                 error!("Heartbeat response sending failed ({:?})! Terminating connection.", e);
                            })?;
                            *state = heartbeat::ForeignHeartbeatState::Empty;
                        }
                        state => {
                            error!(
                                "Signalled to transmit heartbeat response but state is invalid: {:?}.", state
                            );
                            return Err(ErrorHelper::<RxE, TxE, Sender, Receiver>::DtlsError(
                                Error::Placeholder,
                            ));
                        }
                    }
                    continue 'outer;
                }
                Either::Second(maybe_payload) => {
                    trace!("tx_receiver::peek() DONE");
                    maybe_payload.map_err(ConnectionError::ReceiveError)?
                }
            };

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
        record_transmitter.lock().await.flush().await?;
    }
}

async fn rx_worker<'a, RxE, TxE, Sender, Receiver, Delay>(
    mut rx_endpoint: RxE,
    rx_sender: &mut Sender,
    rx_buffer: &mut [u8],
    shared_state: &SharedState<impl GenericKeySchedule>,
    hb: &heartbeat::Heartbeat<'a, Delay>,
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
                    Record::Heartbeat(ref heartbeat) => {
                        debug!("Parsed a heartbeat");
                        trace!("{:?}", r);
                        hb.new_record(heartbeat).await;
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
