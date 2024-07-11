#![no_main]
#![no_std]
#![allow(incomplete_features)]

use rtic_monotonics::{
    systick::{fugit::MicrosDurationU64, Systick},
    Monotonic,
};

pub mod command_handling;
pub mod ethernet;
pub mod send_heartbeat;

defmt::timestamp!("{=u64:us}", {
    let time_us: MicrosDurationU64 = Systick::now().duration_since_epoch().convert();

    time_us.ticks()
});

#[rtic::app(device = embassy_stm32::pac, dispatchers = [I2C1_EV, I2C1_ER, I2C2_EV, I2C2_ER], peripherals = false)]
mod app {
    use crate::{
        command_handling::handle_sleep_command,
        ethernet::{handle_stack, run_comms},
        send_heartbeat::send_heartbeat,
    };
    use heapless::Vec;
    use rpc_definition::endpoints::sleep::Sleep;
    use rpc_testing::bsp::{self, NetworkStack, Rng};
    use rtic_sync::{
        channel::{Receiver, Sender},
        make_channel,
    };

    #[shared]
    struct Shared {
        network_stack: NetworkStack,
    }

    #[local]
    struct Local {
        rng: Rng,
    }

    #[init]
    fn init(cx: init::Context) -> (Shared, Local) {
        defmt::info!("pre init");

        // Initialize the underlying HW.
        let (network_stack, rng) = bsp::init(cx.core);

        // Create channels for communication.
        let (ethernet_tx_sender, ethernet_tx_receiver) = make_channel!(Vec<u8, 128>, 1);
        let (sleep_request_sender, sleep_request_receiver) = make_channel!((u32, Sleep), 8);

        handle_stack::spawn().ok();
        run_comms::spawn(
            ethernet_tx_receiver,
            ethernet_tx_sender.clone(),
            sleep_request_sender,
        )
        .ok();
        handle_sleep_command::spawn(sleep_request_receiver, ethernet_tx_sender.clone()).ok();
        send_heartbeat::spawn(ethernet_tx_sender).ok();

        (Shared { network_stack }, Local { rng })
    }

    extern "Rust" {
        // Network stack hander, does the background work of the stack.
        #[task(shared = [&network_stack])]
        async fn handle_stack(_: handle_stack::Context);

        // Main RX/TX data pump for Ethernet.
        #[task(shared = [&network_stack], local = [rng])]
        async fn run_comms(
            _: run_comms::Context,
            _: Receiver<'static, Vec<u8, 128>, 1>,
            _: Sender<'static, Vec<u8, 128>, 1>,
            _: Sender<'static, (u32, Sleep), 8>,
        );

        // The `sleep` command handling will run at elevated priority.
        #[task(priority = 1)]
        async fn handle_sleep_command(
            _: handle_sleep_command::Context,
            _: Receiver<'static, (u32, Sleep), 8>,
            _: Sender<'static, Vec<u8, 128>, 1>,
        );

        #[task]
        async fn send_heartbeat(_: send_heartbeat::Context, _: Sender<'static, Vec<u8, 128>, 1>);
    }
}
