use crate::app;
use embassy_futures::join::join3;
use embassy_net::{
    udp::{PacketMetadata, UdpSocket},
    Ipv4Address,
};
use embassy_time::{with_timeout, Duration, TimeoutError};
use embedded_dtls::{
    cipher_suites::{ChaCha20Poly1305Cipher, DtlsEcdhePskWithChacha20Poly1305Sha256},
    client::{
        config::{ClientConfig, Psk},
        open_client,
    },
    queue_helpers::FramedQueue,
    ApplicationDataReceiver, ApplicationDataSender,
};
use heapless::Vec;
use rpc_definition::endpoints::sleep::Sleep;
use rtic_monotonics::systick::Systick;
use rtic_sync::channel::{Receiver, Sender};

// Backend IP.
const BACKEND_ENDPOINT: (Ipv4Address, u16) = (Ipv4Address::new(192, 168, 0, 220), 8321);

/// Main UDP RX/TX data pump. Also sets up the UDP socket.
pub async fn run_comms(
    cx: app::run_comms::Context<'_>,
    mut ethernet_tx_receiver: Receiver<'static, Vec<u8, 128>, 1>,
    mut ethernet_tx_sender: Sender<'static, Vec<u8, 128>, 1>,
    mut sleep_command_sender: Sender<'static, (u32, Sleep), 8>,
) -> ! {
    let stack = *cx.shared.network_stack;
    let rng = cx.local.rng;

    // Ensure DHCP configuration is up before trying connect
    stack.wait_config_up().await;

    defmt::info!("Network task initialized");

    // Then we can use it!
    let mut rx_buffer = [0; 1024];
    let mut tx_buffer = [0; 1024];
    let mut rx_meta = [PacketMetadata::EMPTY; 16];
    let mut tx_meta = [PacketMetadata::EMPTY; 16];

    let mut buf = [0; 1024];

    let mut socket = UdpSocket::new(
        stack,
        &mut rx_meta,
        &mut rx_buffer,
        &mut tx_meta,
        &mut tx_buffer,
    );
    socket.bind(8321).unwrap();

    let mut fq = FramedQueue::<128>::new();
    let (mut rx_sender, mut rx_receiver) = fq.split().unwrap();
    let mut fq = FramedQueue::<128>::new();
    let (mut tx_sender, mut tx_receiver) = fq.split().unwrap();
    let client_config = ClientConfig {
        psk: Psk {
            identity: b"hello world",
            key: b"11111234567890qwertyuiopasdfghjklzxc",
        },
    };

    join3(
        async move {
            loop {
                let rx = edtls::DtlsSocket::new(&socket, BACKEND_ENDPOINT);
                let tx = edtls::DtlsSocket::new(&socket, BACKEND_ENDPOINT);
                let cipher = ChaCha20Poly1305Cipher::default();
                let client_connection = match with_timeout(
                    Duration::from_secs(5),
                    open_client::<_, _, _, DtlsEcdhePskWithChacha20Poly1305Sha256>(
                        rng,
                        &mut buf,
                        rx,
                        tx,
                        cipher,
                        &client_config,
                    ),
                )
                .await
                {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => {
                        defmt::error!("Failed to open a DTLS client connection: {}", e);
                        continue;
                    }
                    Err(TimeoutError) => {
                        defmt::error!("Attempt to open a DTLS connection timed out");
                        continue;
                    }
                };

                let mut rx_buf = [0; 1536];
                let mut tx_buf = [0; 1536];

                if let Err(e) = client_connection
                    .run(
                        &mut rx_buf,
                        &mut tx_buf,
                        &mut rx_sender,
                        &mut tx_receiver,
                        &mut Systick,
                    )
                    .await
                {
                    defmt::error!("Client connection closed with {:?}", e);
                }
            }
        },
        async {
            loop {
                if let Err(e) = tx_sender
                    .send(ethernet_tx_receiver.recv().await.unwrap())
                    .await
                {
                    defmt::error!("Could not fit data in the tx_sender: {}", e);
                }
            }
        },
        async {
            // Receive worker.
            loop {
                crate::command_handling::dispatch(
                    rx_receiver.peek().await.unwrap().as_ref(),
                    &mut ethernet_tx_sender,
                    &mut sleep_command_sender,
                )
                .await;
                rx_receiver.pop().unwrap();
            }
        },
    )
    .await
    .0
}

/// `embassy-net` stack poller.
pub async fn handle_stack(cx: app::handle_stack::Context<'_>) -> ! {
    cx.shared.network_stack.run().await
}

pub mod edtls {
    use embassy_net::{udp::UdpSocket, IpEndpoint};

    pub struct DtlsSocket<'stack, 'socket> {
        inner: &'socket UdpSocket<'stack>,
        endpoint: IpEndpoint,
    }

    impl<'stack, 'socket> DtlsSocket<'stack, 'socket> {
        pub fn new(inner: &'socket UdpSocket<'stack>, endpoint: impl Into<IpEndpoint>) -> Self {
            let endpoint = endpoint.into();
            Self { inner, endpoint }
        }
    }

    impl<'stack, 'socket> defmt::Format for DtlsSocket<'stack, 'socket> {
        fn format(&self, fmt: defmt::Formatter) {
            defmt::write!(fmt, "DtlsSocket {{ endpoint: {} }}", self.endpoint)
        }
    }

    #[derive(defmt::Format)]
    pub enum RecvError {
        UnexpectedSender(IpEndpoint),
        Inner(embassy_net::udp::RecvError),
    }

    impl From<embassy_net::udp::RecvError> for RecvError {
        fn from(value: embassy_net::udp::RecvError) -> Self {
            Self::Inner(value)
        }
    }

    impl<'stack, 'socket> embedded_dtls::RxEndpoint for DtlsSocket<'stack, 'socket> {
        type ReceiveError = RecvError;

        async fn recv<'a>(
            &mut self,
            buf: &'a mut [u8],
        ) -> Result<&'a mut [u8], Self::ReceiveError> {
            // Problem: If "backend" restarts, client continues with the old keypair and thus just bounces off.
            // I guess only a heartbeat is a solution and a timeout on a receiving side to restart the connection altogether?
            let (n, sender_ep) = self.inner.recv_from(buf).await?;
            if self.endpoint != sender_ep {
                return Err(RecvError::UnexpectedSender(sender_ep));
            }
            Ok(&mut buf[..n])
        }
    }

    impl<'stack, 'socket> embedded_dtls::TxEndpoint for DtlsSocket<'stack, 'socket> {
        type SendError = embassy_net::udp::SendError;

        async fn send(&mut self, buf: &[u8]) -> Result<(), Self::SendError> {
            self.inner.send_to(buf, self.endpoint).await
        }
    }
}
