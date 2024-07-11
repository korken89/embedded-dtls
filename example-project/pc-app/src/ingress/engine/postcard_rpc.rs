use std::{convert::Infallible, net::IpAddr};

use embedded_dtls::{ApplicationDataReceiver, ApplicationDataSender};
use log::{debug, trace};
use rpc_definition::{
    postcard_rpc::{
        headered::extract_header_from_bytes,
        host_client::{HostClient, ProcessError, RpcFrame, WireContext},
    },
    wire_error::FatalError,
};
use rustc_hash::FxHashMap;

pub trait HostClientExt {
    fn new_edtls(
        err_uri_path: &str,
        outgoing_depth: usize,
    ) -> (HostClient<FatalError>, HostClientEdtlsWorker) {
        #[allow(deprecated)]
        let (hc, w) = HostClient::new_manual(err_uri_path, outgoing_depth);
        (hc, HostClientEdtlsWorker { w })
    }
}

impl HostClientExt for HostClient<FatalError> {}

pub struct HostClientEdtlsWorker {
    w: WireContext,
}

impl HostClientEdtlsWorker {
    pub async fn run<Receiver, Sender>(
        self,
        ip: IpAddr,
        rx_receiver: &mut Receiver,
        tx_sender: &mut Sender,
    ) -> Result<Infallible, anyhow::Error>
    where
        Receiver: ApplicationDataReceiver,
        Sender: ApplicationDataSender,
    {
        // Start handling of all I/O.
        let WireContext {
            mut outgoing,
            incoming,
            mut new_subs,
        } = self.w;

        let mut subs = FxHashMap::default();

        loop {
            // Adapted from `cobs_wire_worker`.
            // Wait for EITHER a serialized request, OR some data from the embedded device.
            tokio::select! {
                sub = new_subs.recv() => {
                    // Receiver returns None when all Senders have hung up.
                    let Some(new_subscription) = sub else {
                        return Err(anyhow::anyhow!("{ip}: Subscription channel sender closed - HostClient dropped?"));
                    };

                    subs.insert(new_subscription.key, new_subscription.tx);
                }
                out = outgoing.recv() => {
                    // Receiver returns None when all Senders have hung up.
                    let Some(msg) = out else {
                        return Err(anyhow::anyhow!("{ip}: Outgoing channel sender closed - HostClient dropped"));
                    };

                    // Send message via the UDP socket.
                    // TODO: Fix comments
                    if let Err(_) = tx_sender.send(msg.to_bytes()).await {
                        return Err(anyhow::anyhow!("{ip}: Edtls tx_receiver closed - connection dropped?"));
                    }
                }
                // FIXME: This is really ugly but it works
                // Otherwise, borrow-checker freaks out and it it impossible to call
                // `rx_receiver.pop()`
                _ = async { let _ = rx_receiver.peek().await; } => {
                    {
                        // Make sure the UDP RX worker is still alive.
                        let Ok(packet) = rx_receiver.peek().await else {
                            return Err(anyhow::anyhow!("{ip}: Edtls rx_sender closed - connection dropped?"));
                        };

                        let packet = packet.as_ref();

                        trace!("{ip}: Received packet {packet:02x?}");

                        // Attempt to extract a header so we can get the sequence number.
                        // Since UDP is already full packets, we don't need to use COBS or similar, a
                        // packet is a full message.
                        if let Ok((hdr, body)) = extract_header_from_bytes(&packet) {
                            // Got a header, turn it into a frame.
                            let frame = RpcFrame { header: hdr.clone(), body: body.to_vec() };

                            // Give priority to subscriptions. TBH I only do this because I know a hashmap
                            // lookup is cheaper than a waitmap search.
                            if let Some(tx) = subs.get_mut(&hdr.key) {
                                // Yup, we have a subscription.
                                if tx.send(frame).await.is_err() {
                                    // But if sending failed, the listener is gone, so drop it.
                                    subs.remove(&hdr.key);
                                }
                            } else {
                                // Wake the given sequence number. If the WaitMap is closed, we're done here
                                if let Err(ProcessError::Closed) = incoming.process(frame) {
                                    return Err(anyhow::anyhow!("{ip}: Incoming channel receiver closed - HostClient dropped"));
                                }
                            }
                        } else {
                            debug!("{ip}: Malformed packet {packet:x?}");
                        }
                    }
                    rx_receiver.pop().ok();
                }
            }
        }
    }
}
