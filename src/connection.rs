use crate::{record::GenericKeySchedule, Endpoint};

/// A DTLS 1.3 connection.
pub struct Connection<Socket, KeySchedule>
where
    Socket: Endpoint,
    KeySchedule: GenericKeySchedule,
{
    /// Sender/receiver of data.
    pub(crate) socket: Socket,
    /// Keys for client->server and server->client.
    pub(crate) key_schedule: KeySchedule,
}

impl<Socket, KeySchedule> Connection<Socket, KeySchedule>
where
    Socket: Endpoint,
    KeySchedule: GenericKeySchedule,
{
    /// Run the connection and serve the application data queues. This will return when the
    /// connection is closed.
    ///
    /// The `{rx, tx}_buffer` should ideally be the size of the MTU, but may be less as well.
    // TODO: How to request the connection closed?
    pub async fn run(
        &mut self,
        rx_buffer: &mut [u8],
        tx_buffer: &mut [u8],
        tx_consumer: &mut impl crate::ApplicationDataConsumer,
        rx_producer: &mut impl crate::ApplicationDataProducer,
    ) {
        // Tasks:

        // 1. App data handling

        // 2. Alert handling

        // 3. Heartbeat handling

        // 4. Key updates

        // 5. Close connection
    }
}
