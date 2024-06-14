use crate::{
    buffer::EncodingBuffer,
    record::{GenericKeySchedule, Record},
    Endpoint,
};

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
        // RX task
        {
            let mut data = self.socket.recv(rx_buffer).await.unwrap();

            match Record::parse(|_| {}, &mut data, Some(&mut self.key_schedule)).await {
                Some((r, _)) => match r {
                    Record::Handshake(_, _) => todo!(),
                    Record::Alert(_, _) => todo!(),
                    Record::Ack(_, _) => todo!(),
                    Record::Heartbeat(_) => todo!(),
                    Record::ApplicationData(data) => {
                        rx_producer.push(data).await;
                    }
                },
                None => todo!(),
            }
        }

        // TX task
        {
            // TODO: This needs to select over sending internal data as well. Prio on internal?

            match tx_consumer.pop().await {
                Ok(payload) => {
                    let buf = &mut EncodingBuffer::new(tx_buffer);
                    Record::encode_application_data(
                        |_| {},
                        buf,
                        &mut self.key_schedule,
                        payload.as_ref(),
                    )
                    .await;

                    self.socket.send(&buf).await;
                }
                Err(_) => todo!(),
            }
        }

        // Tasks:

        // 1. App data handling

        // 2. Alert handling

        // 3. Heartbeat handling (read/write)

        // 4. Key updates

        // 5. Close connection
    }
}
