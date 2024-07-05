use defmt_or_log::debug;
use embassy_futures::select::{select, Either};
use embedded_hal_async::delay::DelayNs;

use super::{ErrorHelper, SharedState};
use crate::{
    connection::select_sharing::Signal, record::GenericKeySchedule, ApplicationDataReceiver,
    ApplicationDataSender, RxEndpoint, TxEndpoint,
};
use core::{
    convert::Infallible,
    sync::atomic::{AtomicBool, Ordering},
};

pub struct KeyUpdateWorkerState {
    /// External signal to start doing a key update.
    do_key_update: Signal<()>,
    /// Send a key update message, with support for knowing that it has been sent.
    send_key_update: Signal<()>,
    /// Wait for ACK signal.
    got_ack: Signal<()>,
    /// Marker to show that a key update is ongoing.
    key_update_ongoing: AtomicBool,
}

impl KeyUpdateWorkerState {
    pub const fn new() -> Self {
        Self {
            do_key_update: Signal::new(),
            send_key_update: Signal::new(),
            got_ack: Signal::new(),
            key_update_ongoing: AtomicBool::new(false),
        }
    }

    fn key_update_ongoing(&self) -> bool {
        self.key_update_ongoing.load(Ordering::Relaxed)
    }

    /// Start a key update in case one is not already ongoing.
    pub fn start_key_update(&self) {
        if !self.key_update_ongoing() {
            self.do_key_update.try_send(());
        }
    }
}

pub async fn key_update_worker<RxE, TxE, Sender, Receiver>(
    shared_state: &SharedState<impl GenericKeySchedule>,
    mut delay: impl DelayNs,
) -> Result<Infallible, ErrorHelper<RxE, TxE, Sender, Receiver>>
where
    TxE: TxEndpoint,
    RxE: RxEndpoint,
    Sender: ApplicationDataSender,
    Receiver: ApplicationDataReceiver,
{
    let worker = &shared_state.key_update_worker;
    let key_schedule = &shared_state.key_schedule;

    loop {
        // 1. Wait for key update request.
        worker.key_update_ongoing.store(false, Ordering::Relaxed);
        worker.do_key_update.recv().await;
        worker.key_update_ongoing.store(true, Ordering::Relaxed);

        // 2. Send a key update request and wait for it to be sent.
        worker.send_key_update.send(()).await;

        // 3. When sent, update key schedule to new keys
        {
            key_schedule.lock().await.update_sending_keys();
        }

        // 4. Wait for ack
        // TODO: Double check that this is the correct thing to do, if no ACK is received the
        // receiving side can update the keys based on the new epoch number, and no ACK is really
        // necessary.
        match select(delay.delay_ms(1_000), worker.got_ack.recv()).await {
            Either::First(_) => debug!("Key update ACK not received"),
            Either::Second(_) => debug!("Got key update ACK"),
        };
    }
}
