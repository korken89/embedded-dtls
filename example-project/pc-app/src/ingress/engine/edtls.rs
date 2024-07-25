use std::{fmt::Debug, net::IpAddr, time::Duration};

use embedded_dtls;
use tokio::sync::mpsc::Receiver;

type Instant = tokio::time::Instant;
#[derive(Copy, Clone)]
pub struct InstantWrapper(Instant);

impl From<Instant> for InstantWrapper {
    fn from(value: Instant) -> Self {
        Self(value)
    }
}

impl From<InstantWrapper> for Instant {
    fn from(value: InstantWrapper) -> Self {
        value.0
    }
}

// TODO: Overflows? IDC for now
impl embedded_dtls::Instant for InstantWrapper {
    fn add_s(&self, s: u32) -> Self {
        Self(self.0.checked_add(Duration::from_secs(s as _)).unwrap())
    }

    fn sub_as_us(&self, rhs: &Self) -> u32 {
        (self.0 - rhs.0).as_micros() as u32
    }
}

#[derive(Clone)]
pub struct Delay;

impl embedded_dtls::Delay for Delay {
    async fn delay_ms(&mut self, ms: u32) {
        tokio::time::sleep(Duration::from_millis(ms as _)).await;
    }

    type Instant = InstantWrapper;

    async fn delay_until(&mut self, instant: Self::Instant) {
        tokio::time::sleep_until(instant.into()).await
    }

    fn now(&self) -> Self::Instant {
        tokio::time::Instant::now().into()
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
        match self.rx.recv().await {
            Some(received_data) => {
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
            None => Err(anyhow::anyhow!("All senders were closed")),
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
