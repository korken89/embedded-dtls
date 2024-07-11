use super::{api_handle, engine};
use log::*;
use once_cell::sync::Lazy;
use rpc_definition::topics::{
    heartbeat::{Heartbeat, TopicHeartbeat},
    some_data::{SomeData, TopicSomeData},
};
use std::net::IpAddr;
use tokio::sync::broadcast;

pub use engine::Connection;

/// Subscription handle. All data for the topic will come here.
pub struct Subscription<T>(broadcast::Receiver<T>);

impl<T> Subscription<T>
where
    T: Clone,
{
    /// Receive a value from a subscription.
    pub async fn recv(&mut self) -> Result<T, SubscriptionError> {
        self.0.recv().await.map_err(|e| match e {
            broadcast::error::RecvError::Closed => unreachable!("We don't close the channel"),
            broadcast::error::RecvError::Lagged(_) => SubscriptionError::MessagesDropped,
        })
    }
}

/// Get an event on connection change.
pub fn connection() -> Subscription<Connection> {
    Subscription(engine::CONNECTION_SUBSCRIBER.subscribe())
}

/// Errors on subscription.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SubscriptionError {
    /// The requested IP did not exist in the system.
    IpNotFound,
    /// Some messages were dropped due to queue being full, `recv` again to get the oldest value.
    MessagesDropped,
}

// TODO: The entire module from here could be a macro.
// ```
// subscriptions!(
//  /* [method name, data type, static name, RPC queue depth, broadcast queue depth], */
//     [heartbeat, Heartbeat, HEARTBEAT_SUBSCRIBER, 10, 100],
//     [some_data, SomeData, SOMEDATA_SUBSCRIBER, 10, 100],
// );
// ```

/// Global subscription for heartbeats.
pub(crate) static HEARTBEAT_SUBSCRIBER: Lazy<broadcast::Sender<(IpAddr, Heartbeat)>> =
    Lazy::new(|| broadcast::channel(100).0);

/// Example public topic subscription (unsolicited messages).
///
/// Get heartbeats from a device.
pub async fn heartbeat() -> Subscription<(IpAddr, Heartbeat)> {
    Subscription(HEARTBEAT_SUBSCRIBER.subscribe())
}

/// Global subscription for some data.
pub(crate) static SOMEDATA_SUBSCRIBER: Lazy<broadcast::Sender<(IpAddr, SomeData)>> =
    Lazy::new(|| broadcast::channel(100).0);

/// Example public topic subscription (unsolicited messages).
///
/// Get some data from a device.
pub async fn some_data() -> Subscription<(IpAddr, SomeData)> {
    Subscription(SOMEDATA_SUBSCRIBER.subscribe())
}

/// This tracks unsolicited messages and sends them on the correct endpoint, in the end
/// consolidating all messages of the same type into one stream of `(source, message)`.
pub(crate) async fn subscription_consolidation() {
    loop {
        // On every new connection, subscribe to data for that device.
        match connection().recv().await {
            Ok(Connection::New(ip)) => {
                let Ok(api) = api_handle(&ip).await else {
                    continue;
                };

                // Get subscriptions to all topic
                let Ok(mut heartbeat) = api.subscribe::<TopicHeartbeat>(10).await else {
                    continue;
                };

                let Ok(mut some_data) = api.subscribe::<TopicSomeData>(10).await else {
                    continue;
                };

                // TODO: Add next subscription here.

                tokio::spawn(async move {
                    tokio::select! {
                        _ = async {
                            while let Some(s) = heartbeat.recv().await {
                                let _ = HEARTBEAT_SUBSCRIBER.send((ip, s));
                            }
                        } => {}
                        _ = async {
                            while let Some(s) = some_data.recv().await {
                                let _ = SOMEDATA_SUBSCRIBER.send((ip, s));
                            }
                        } => {}

                        // TODO: Add next subscription forwarder here.
                    }
                });
            }
            Ok(Connection::Closed(_)) => {}
            Err(_) => error!("subscription_consolidation: Unable to keep up with new connecitons"),
        }
    }
}
