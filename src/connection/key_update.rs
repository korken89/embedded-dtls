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
    /// Marker to show that a key update is ongoing.
    key_update_ongoing: AtomicBool,
}
impl KeyUpdateWorkerState {
    pub const fn new() -> Self {
        Self {
            do_key_update: Signal::new(),
            send_key_update: Signal::new(),
            key_update_ongoing: AtomicBool::new(false),
        }
    }

    fn key_update_ongoing(&self) -> bool {
        self.key_update_ongoing.load(Ordering::Relaxed)
    }

    /// Start a key update.
    pub fn start_key_update(&self) {
        if !self.key_update_ongoing() {
            self.do_key_update.try_send(());
        }
    }
}

pub async fn key_update_worker<RxE, TxE, Sender, Receiver>(
    shared_state: &SharedState<impl GenericKeySchedule>,
) -> Result<Infallible, ErrorHelper<RxE, TxE, Sender, Receiver>>
where
    TxE: TxEndpoint,
    RxE: RxEndpoint,
    Sender: ApplicationDataSender,
    Receiver: ApplicationDataReceiver,
{
    loop {
        // TODO
        //
        // 1. Wait for key update request.
        // 2. Send a key update request
        // 3. When sent, update key schedule to new keys
        // 4. Wait for ack, TODO: what needs to happen if no ACK?
    }
}
