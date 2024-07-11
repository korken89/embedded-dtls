use std::{fmt::Debug, net::IpAddr, time::Duration};

use embedded_dtls::{self, DelayNs};
use tokio::{
    sync::mpsc::Receiver,
    time::{error::Elapsed, timeout},
};

pub struct Delay;

impl DelayNs for Delay {
    async fn delay_ns(&mut self, ns: u32) {
        tokio::time::sleep(Duration::from_nanos(ns as _)).await;
    }
}

use super::SOCKET;

pub struct TxEndpoint {
    endpoint: (IpAddr, u16),
}

impl TxEndpoint {
    pub fn new(endpoint: (IpAddr, u16)) -> Self {
        Self { endpoint }
    }
}

pub struct RxEndpoint {
    endpoint: (IpAddr, u16),
    rx: Receiver<Vec<u8>>,
}

impl RxEndpoint {
    pub fn new(endpoint: (IpAddr, u16), rx: Receiver<Vec<u8>>) -> Self {
        Self { endpoint, rx }
    }
}

impl Debug for TxEndpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (ip, port) = self.endpoint;
        write!(f, "DtlsSocket {{ endpoint: {ip}:{port} }}")
    }
}

impl Debug for RxEndpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (ip, port) = self.endpoint;
        write!(f, "DtlsSocket {{ endpoint: {ip}:{port} }}")
    }
}

impl embedded_dtls::RxEndpoint for RxEndpoint {
    type ReceiveError = anyhow::Error;

    async fn recv<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a mut [u8], Self::ReceiveError> {
        match timeout(Duration::from_secs(5), self.rx.recv()).await {
            Ok(Some(received_data)) => {
                let n = received_data.len();
                if buf.len() < n {
                    return Err(anyhow::anyhow!(
                        "Could not fit the received datagram into the buffer"
                    ));
                }
                let buf = &mut buf[..n];
                buf.copy_from_slice(&received_data);
                Ok(buf)
            }
            Ok(None) => Err(anyhow::anyhow!("All senders were closed")),
            Err(Elapsed { .. }) => Err(anyhow::anyhow!("Connection timed out")),
        }
    }
}
impl embedded_dtls::TxEndpoint for TxEndpoint {
    type SendError = anyhow::Error;

    async fn send(&mut self, buf: &[u8]) -> Result<(), Self::SendError> {
        let socket = SOCKET
            .get()
            .ok_or_else(|| anyhow::anyhow!("Socket is not initialized"))?;
        socket
            .send_to(buf, self.endpoint)
            .await
            .map_err(|e| anyhow::Error::from(e))?;
        Ok(())
    }
}
