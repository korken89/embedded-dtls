use crate::{
    buffer::EncodingBuffer,
    cipher_suites::DtlsCipherSuite,
    client::config::ClientConfig,
    connection::Connection,
    handshake::Handshake,
    key_schedule::KeySchedule,
    record::{EncodeOrParse, GenericKeySchedule, Record},
    Endpoint, Error,
};
use defmt_or_log::{debug, error, info, trace};
use digest::Digest;
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub mod config;

/// Open a DTLS 1.3 client connection.
/// This returns an active connection after handshake is completed.
///
/// NOTE: This does not do timeout, it's up to the caller to give up.
pub async fn open_client<Rng, Socket, CipherSuite>(
    rng: &mut Rng,
    buf: &mut [u8],
    socket: Socket,
    cipher: <CipherSuite as DtlsCipherSuite>::Cipher,
    config: &ClientConfig<'_>,
) -> Result<Connection<Socket, KeySchedule<CipherSuite, false>>, Error<Socket>>
where
    Rng: RngCore + CryptoRng,
    Socket: Endpoint,
    CipherSuite: DtlsCipherSuite,
{
    info!("Starting handshake for client connection {:?}", socket);

    let mut key_schedule = KeySchedule::new_client(cipher);
    let mut transcript_hasher = <CipherSuite::Hash as Digest>::new();

    // Initialize key-schedule for generating binders.
    key_schedule.initialize_early_secret(Some(config.psk.clone()));

    // Generate our ephemeral key for key exchange.
    let secret_key = EphemeralSecret::random_from_rng(&mut *rng);
    let our_public_key = PublicKey::from(&secret_key);

    // Send ClientHello.
    {
        let mut ser_buf = EncodingBuffer::new(buf);

        // We read out the positions instead of doing hashing inline due to the fact that
        // the binders need to be inserted and hashed as well. The hasher API does not allow
        // for writing within the closure.
        let mut positions = Default::default();
        Record::encode_client_hello::<CipherSuite, _>(
            |(p, _buf)| {
                positions = p;
            },
            &mut ser_buf,
            config,
            &our_public_key,
            rng,
            &mut key_schedule,
        )
        .await
        .map_err(|_| Error::InsufficientSpace)?;

        // Write binders.
        if let Some((up_to_binders, binders)) = positions.pre_post_binders_mut(&mut ser_buf) {
            transcript_hasher.update(up_to_binders);
            let binder_entry = key_schedule.create_binder(&transcript_hasher.clone().finalize());

            let mut binders_enc = EncodingBuffer::new(binders);
            binders_enc.push_u8(binder_entry.len() as u8).unwrap();
            binders_enc.extend_from_slice(&binder_entry).unwrap();

            transcript_hasher.update(&binders_enc);
        } else {
            // TODO: As we only support PSK right now, we don't really exercise this path.
            let buf = positions.as_slice(&ser_buf).expect("UNREACHABLE");
            transcript_hasher.update(buf);
        }

        trace!(
            "Client transcript after client hello: {:?}",
            transcript_hasher.clone().finalize()
        );

        socket.send(&ser_buf).await.map_err(|e| Error::Send(e))?;
    }

    // Wait for response (ServerHello and Finished).
    {
        let mut resp = socket.recv(buf).await.map_err(|e| Error::Recv(e))?;
        trace!("Got datagram!");

        // Parse and validate ServerHello.
        // let mut parse_buffer = ParseBufferMut::new(resp);

        let shared_secret = {
            let server_hello = if let (Record::Handshake(Handshake::ServerHello(hello), _), _) =
                Record::parse(
                    |(p, buf)| {
                        if let Some(buf) = p.as_slice(buf) {
                            transcript_hasher.update(buf);
                        }
                    },
                    &mut resp,
                    Some(&mut key_schedule),
                )
                .await
                .ok_or(Error::InvalidServerHello)?
            {
                hello
            } else {
                return Err(Error::InvalidServerHello);
            };

            trace!(
                "Client transcript after server hello: {:?}",
                transcript_hasher.clone().finalize()
            );

            // Update key schedule to Handshake Secret using public keys.
            let their_public_key = server_hello
                .validate()
                .map_err(|_| Error::InvalidServerHello)?;

            secret_key.diffie_hellman(&their_public_key)
        };

        key_schedule.initialize_handshake_secret(
            shared_secret.as_bytes(),
            &transcript_hasher.clone().finalize(),
        );

        // Check if we got more datagrams, we're expecting a finished.
        let expected_verify =
            key_schedule.create_verify_data(&transcript_hasher.clone().finalize(), true);
        let finished = {
            let mut buf = if resp.is_empty() {
                // Wait for finished.
                socket.recv(buf).await.map_err(|e| Error::Recv(e))?
            } else {
                resp
            };

            if let (Record::Handshake(Handshake::Finished(fin), _), _) = Record::parse(
                |(p, buf)| {
                    if let Some(buf) = p.as_slice(buf) {
                        transcript_hasher.update(buf);
                    }
                },
                &mut buf,
                Some(&mut key_schedule),
            )
            .await
            .ok_or(Error::InvalidServerFinished)?
            {
                fin
            } else {
                return Err(Error::InvalidServerFinished);
            }
        };

        if expected_verify.as_ref() != finished.verify {
            error!("Server finished does not match transcript");
            return Err(Error::InvalidServerFinished);
        }

        debug!("Server finished MATCHES expected transcript");
    }

    // Send finished.
    {
        let ser_buf = &mut EncodingBuffer::new(buf);

        let verify = key_schedule.create_verify_data(&transcript_hasher.clone().finalize(), false);

        // Add the Finished message to this datagram.
        Record::encode_finished(&verify, &mut key_schedule, |_| {}, ser_buf)
            .await
            .map_err(|_| Error::InsufficientSpace)?;

        socket.send(ser_buf).await.map_err(|e| Error::Send(e))?;
    }

    // Update key schedule to Master Secret.
    key_schedule.initialize_master_secret(&transcript_hasher.clone().finalize());

    // Wait for server ACK.
    {
        let mut ack = socket.recv(buf).await.map_err(|e| Error::Recv(e))?;

        let ack = if let (Record::Ack(ack, _), _) =
            Record::parse(|_| {}, &mut ack, Some(&mut key_schedule))
                .await
                .ok_or(Error::InvalidServerFinished)?
        {
            ack
        } else {
            return Err(Error::InvalidServerFinished);
        };

        debug!("Got server ACK");
        trace!("{:?}", ack);
        let EncodeOrParse::Parse(record_numbers) = ack.record_numbers else {
            panic!("ACK: Expected parse, got encode");
        };

        if record_numbers.is_empty() {
            error!("There was no record number in the handshake ACK");
            return Err(Error::InvalidServerAck);
        }

        for record_number in record_numbers {
            if record_number.epoch != key_schedule.epoch_number() {
                return Err(Error::InvalidServerAck);
            }

            // TODO: Should we check sequence number?
        }
    }

    info!("New client connection created for {:?}", socket);

    Ok(Connection {
        socket,
        key_schedule,
    })
}
