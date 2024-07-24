//! A small example ingress handling many concurrent connections to embedded devices connected via
//! UDP, where each device implementes `postcard-rpc` for RPCs and unsoliced messages (topics).
//!
//! Note: This app uses IP as identifier for each device, you should not do that when running UDP,
//! as UDP source addresses are trivial to spoof.

use ingress::subscriptions::{connection, Connection};
use log::*;
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};
use tokio::{join, time::interval};

// This is the library
pub mod ingress;

// This is the app using the library
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init_timed();

    info!("Starting ingress");
    tokio::spawn(ingress::run_ingress());

    // TODO: Use the API here.
    let mut connecton = connection();

    tokio::spawn(streaming_test());

    loop {
        let Ok(connection) = connecton.recv().await else {
            continue;
        };

        match connection {
            Connection::New(ip) => {
                info!("{ip}: New connection established.");

                tokio::spawn(test_sleep_api(ip));
                tokio::spawn(test_pingpong_api(ip));
            }
            Connection::Closed(ip) => info!("{ip}: Connection lost."),
        }
    }
}

/// The the Sleep API.
///
/// This is a command that will take as long as we request to finish, exemplifying a command that
/// has processing delay associated with it.
async fn test_sleep_api(ip: IpAddr) {
    info!("{ip}: Sleep API test started.");

    loop {
        // `join!` over multiple commands in reverse order, this should still work as this
        // command can execute out-of-order.
        let (r1, r2, r3) = join!(
            sleep_request(ip, Duration::from_millis(500)),
            sleep_request(ip, Duration::from_millis(400)),
            sleep_request(ip, Duration::from_millis(300)),
        );

        if r1.is_err() || r2.is_err() || r3.is_err() {
            break;
        }
    }
}

/// Helper for sleep requests.
async fn sleep_request(ip: IpAddr, sleep: Duration) -> Result<(), ()> {
    let now = Instant::now();
    match ingress::api::sleep(ip, sleep).await {
        Ok(done) => {
            let elapsed = now.elapsed();
            let sleep_time = Duration::from_micros(
                done.slept_for.seconds as u64 * 1000000 + done.slept_for.micros as u64,
            );
            info!("{ip}: Sleep done! {sleep_time:?}. Round trip took {elapsed:?}");
            Ok(())
        }
        Err(e) => {
            error!("{ip}: Sleep failed! Error = {e:?}");
            Err(())
        }
    }
}

/// Test the ping pong API and measure round trip time.
///
/// This exemplifies a command that answers directly.
async fn test_pingpong_api(ip: IpAddr) {
    info!("{ip}: Pingpong API test started.");

    let mut interval = interval(Duration::from_secs(1));

    loop {
        interval.tick().await;

        let now = Instant::now();
        match ingress::api::ping(ip).await {
            Ok(_pong) => {
                let elapsed = now.elapsed();
                info!("{ip}: Pong! Round trip took {elapsed:?}");
            }
            Err(e) => {
                error!("{ip}: Ping failed! Error = {e:?}");
                break;
            }
        }
    }
}

/// Subscribe to the heartbeat topic and await streaming data to come.
///
/// This exemplifies unsolicited data.
async fn streaming_test() {
    let mut heartbeat = ingress::subscriptions::heartbeat().await;

    loop {
        let Ok((ip, heartbeat)) = heartbeat.recv().await else {
            error!("Subscription has lost messages!");
            continue;
        };

        info!("{ip}: Got heartbeat! {heartbeat:?}");
    }
}
