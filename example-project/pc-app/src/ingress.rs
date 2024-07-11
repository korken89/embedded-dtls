//! Embedded device ingress.
//!
//! Here the public APIs of the ingress are exposed.
//!
//! TODO: Is it worth trying to remove the `static` variables in this lib?

use rpc_definition::{postcard_rpc::host_client::HostClient, wire_error::FatalError};
use std::net::IpAddr;
use tokio::net::UdpSocket;

// Private internals that run the communication.
mod engine;

/// Public RPC APIs are handled here.
pub mod api;

/// Public subscriptions to data are handled here.
pub mod subscriptions;

/// Run the device ingress.
pub async fn run_ingress() {
    let socket = UdpSocket::bind("0.0.0.0:8321")
        .await
        .expect("Unable to bind socket");

    tokio::select! {
        _ = subscriptions::subscription_consolidation() => {}
        _ = engine::udp_listener(socket) => {}
    }
}

/// Helper method to get access to a specific device's API client.
async fn api_handle(device: &IpAddr) -> Result<HostClient<FatalError>, api::ApiError> {
    // Hold the read lock to the global state as short as possible.
    engine::API_CLIENTS
        .read()
        .await
        .get(&device)
        .ok_or(api::ApiError::IpNotFound)
        .cloned()
}
