use crate::app;
use heapless::Vec;
use rpc_definition::{
    postcard_rpc::{self, Topic},
    topics::heartbeat::{Heartbeat, TopicHeartbeat},
};
use rtic_monotonics::systick::{ExtU64, Systick};
use rtic_sync::channel::Sender;

/// Main UDP RX/TX data pump. Also sets up the UDP socket.
pub async fn send_heartbeat(
    _: app::send_heartbeat::Context<'_>,
    mut ethernet_tx_sender: Sender<'static, Vec<u8, 128>, 1>,
) -> ! {
    let mut buf = [0; 128];
    let mut sequence_number = 0;

    loop {
        Systick::delay(2.secs()).await;

        let hb = Heartbeat {
            value: 1.,
            sequence_number,
        };
        sequence_number += 1;
        if let Ok(used) = postcard_rpc::headered::to_slice_keyed(
            sequence_number,
            TopicHeartbeat::TOPIC_KEY,
            &hb,
            &mut buf,
        ) {
            defmt::info!("Sending heartbeat {}", hb.sequence_number);

            ethernet_tx_sender
                .send(Vec::from_slice(used).unwrap())
                .await
                .ok();
        }
    }
}
