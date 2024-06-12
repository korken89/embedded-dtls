use crate::{
    buffer::EncodingBuffer,
    cipher_suites::{ChaCha20Poly1305Cipher, DtlsEcdhePskWithChacha20Poly1305Sha256},
    handshake::{
        extensions::{DtlsVersions, Psk},
        ClientHandshake,
    },
    key_schedule::KeySchedule,
    record::{
        CipherArguments, ClientRecord, DTlsCiphertextHeader, GenericKeySchedule, GenericTranscript,
        NoKeySchedule, RecordNumber, ServerRecord,
    },
    server::config::{Identity, Key, ServerConfig},
    Endpoint, Error,
};
use defmt_or_log::{debug, error, info, trace};
use digest::Digest;
use heapless::Vec as HVec;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub mod config;

/// The maximum hash size the server supports. If we start using larger hashes, update this
/// constant.
const MAX_HASH_SIZE: usize = 32;

// TODO: How to select between server and client? Typestate, flag or two separate structs?
/// A DTLS 1.3 connection.
pub struct ServerConnection<Socket> {
    /// Sender/receiver of data.
    socket: Socket,
    /// Keys for client->server and server->client. Also called "key schedule".
    key_schedule: ServerKeySchedule,
}

impl<Socket> ServerConnection<Socket>
where
    Socket: Endpoint,
{
    /// Open a DTLS 1.3 server connection.
    /// This returns an active connection after handshake is completed.
    ///
    /// NOTE: This does not do timeout, it's up to the caller to give up.
    pub async fn open_server<Rng>(
        socket: Socket,
        server_config: &ServerConfig<'_, '_>,
        rng: &mut Rng,
        buf: &mut [u8],
    ) -> Result<Self, Error<Socket>>
    where
        Rng: RngCore + CryptoRng,
    {
        // TODO: If any part fails with error, make sure to send the correct ALERT.
        info!("Starting handshake for server connection {:?}", socket);

        let mut resp = socket.recv(buf).await.map_err(|e| Error::Recv(e))?;
        trace!("Got datagram!");

        let (client_hello, positions, buffer_that_was_parsed) = {
            let record = ClientRecord::parse::<NoKeySchedule>(&mut resp, None)
                .await
                .ok_or(Error::InvalidClientHello)?;

            if let ((ClientRecord::Handshake(ClientHandshake::ClientHello(hello), _), pos), buf) =
                record
            {
                (hello, pos, buf)
            } else {
                return Err(Error::InvalidClientHello);
            }
        };

        // Find the first supported cipher suite.
        let (mut key_schedule, selected_cipher_suite) = {
            let mut r = None;
            for (index, cipher_suite) in client_hello
                .cipher_suites
                .chunks_exact(2)
                .map(|chunk| u16::from_be_bytes(chunk.try_into().unwrap()))
                .enumerate()
            {
                // Check so we can support this cipher suite.
                if let Some(key_schedule) = ServerKeySchedule::try_from_cipher_suite(cipher_suite) {
                    r = Some((key_schedule, index));
                }
            }

            // TODO: This should generate an alert.
            r.ok_or(Error::InvalidClientHello)?
        };

        // At this point we know the selected cipher suite, and hence also the hash function.
        // Now we can generate transcript hashes for binders and the message in total.
        let mut transcript_hasher = key_schedule.new_transcript_hasher();
        {
            let binders_transcript_hash = {
                let (up_to_binders, binders_and_rest) = positions
                    .pre_post_binders(buffer_that_was_parsed)
                    .ok_or(Error::InvalidClientHello)?;

                transcript_hasher.update(up_to_binders);
                let binders_transcript_hash = transcript_hasher.clone().finalize();
                transcript_hasher.update(binders_and_rest);
                binders_transcript_hash
            };

            trace!(
                "Server transcript after client hello: {:?}",
                transcript_hasher.clone().finalize()
            );

            let their_public_key = client_hello
                .validate_and_initialize_keyschedule(
                    &mut key_schedule,
                    server_config,
                    &binders_transcript_hash,
                )
                .map_err(|_| Error::InvalidClientHello)?;

            // Perform ECDHE -> Handshake Secret with Key Schedule
            // TODO: For now we assume X25519.
            let secret = EphemeralSecret::random();
            let our_public_key = PublicKey::from(&secret);
            let shared_secret = secret.diffie_hellman(&their_public_key);

            // Send server hello.
            let legacy_session_id: HVec<u8, 32> = HVec::from_slice(client_hello.legacy_session_id)
                .map_err(|_| Error::InsufficientSpace)?;

            // TODO: Can we move this up somehow?
            if !resp.is_empty() {
                error!("More data after client hello");
                return Err(Error::InvalidClientHello);
            }

            // TODO: We hardcode the selected PSK as the first one for now.
            let mut enc_buf = EncodingBuffer::new(buf);
            ServerRecord::encode_server_hello(
                &legacy_session_id,
                DtlsVersions::V1_3,
                our_public_key,
                selected_cipher_suite as u16,
                0,
                rng,
                &mut key_schedule,
                &mut transcript_hasher,
                &mut enc_buf,
            )
            .await
            .map_err(|_| Error::InsufficientSpace)?;

            trace!(
                "Server transcript after server hello: {:?}",
                transcript_hasher.clone().finalize()
            );

            key_schedule.initialize_handshake_secret(
                shared_secret.as_bytes(),
                &transcript_hasher.clone().finalize(),
            );

            // Add the Finished message to this datagram.
            let verify =
                key_schedule.create_verify_data(&transcript_hasher.clone().finalize(), true);
            ServerRecord::encode_finished(
                &verify,
                &mut key_schedule,
                &mut transcript_hasher,
                &mut enc_buf,
            )
            .await
            .map_err(|_| Error::InsufficientSpace)?;

            socket.send(&enc_buf).await.map_err(|e| Error::Send(e))?;
        }

        // Finished from client
        {
            let mut resp = socket.recv(buf).await.map_err(|e| Error::Recv(e))?;

            // Check if we got more datagrams, we're expecting a finished.
            let expected_verify =
                key_schedule.create_verify_data(&transcript_hasher.clone().finalize(), false);

            let finished = {
                if let ((ClientRecord::Handshake(ClientHandshake::ClientFinished(fin), _), _), _) =
                    ClientRecord::parse(&mut resp, Some(&mut key_schedule))
                        .await
                        .ok_or(Error::InvalidClientFinished)?
                {
                    fin
                } else {
                    return Err(Error::InvalidClientFinished);
                }
            };

            if expected_verify != finished.verify {
                error!("Client finished does not match transcript");
                return Err(Error::InvalidServerFinished);
            }

            debug!("Client finished MATCHES expected transcript");
        }

        // Update key schedule to Master Secret.
        key_schedule.initialize_master_secret(&transcript_hasher.clone().finalize());

        // Send ACK.
        {
            let mut enc_buf = EncodingBuffer::new(buf);
            let sequence_number = key_schedule.read_record_number();
            let epoch = key_schedule.epoch_number();

            ServerRecord::encode_ack(
                &[RecordNumber {
                    epoch,
                    sequence_number,
                }],
                &mut key_schedule,
                &mut enc_buf,
            )
            .await
            .map_err(|_| Error::InsufficientSpace)?;

            socket.send(&enc_buf).await.map_err(|e| Error::Send(e))?;
        }

        // Handshake complete!
        info!("New server connection created for {:?}", socket);

        Ok(ServerConnection {
            socket,
            key_schedule,
        })
    }
}

pub enum ServerKeySchedule {
    /// Key schedule for the Chacha20Poly1305 cipher suite.
    Chacha20Poly1305Sha256(KeySchedule<DtlsEcdhePskWithChacha20Poly1305Sha256, true>),
}

impl ServerKeySchedule {
    pub fn is_uninitialized(&self) -> bool {
        match self {
            ServerKeySchedule::Chacha20Poly1305Sha256(v) => v.is_uninitialized(),
        }
    }

    pub fn new_transcript_hasher(&self) -> TranscriptHasher {
        match self {
            ServerKeySchedule::Chacha20Poly1305Sha256(_) => {
                TranscriptHasher::Sha256(Sha256::default())
            }
        }
    }

    pub fn try_from_cipher_suite(cipher_suites: u16) -> Option<Self> {
        Some(match cipher_suites {
            // TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
            0xCCAC => ServerKeySchedule::Chacha20Poly1305Sha256(KeySchedule::new_server(
                ChaCha20Poly1305Cipher::default(),
            )),
            _ => {
                trace!("Detected unsupported cipher suite {:?}", cipher_suites);
                return None;
            }
        })
    }

    pub fn initialize_early_secret(&mut self, psk: Option<(&Identity, &Key)>) {
        match self {
            ServerKeySchedule::Chacha20Poly1305Sha256(key_schedule) => key_schedule
                .initialize_early_secret(psk.map(|p| Psk {
                    identity: p.0.as_slice(),
                    key: p.1.as_slice(),
                })),
        }
    }

    pub fn create_binder(&self, transcript_hash: &[u8]) -> HVec<u8, MAX_HASH_SIZE> {
        match self {
            ServerKeySchedule::Chacha20Poly1305Sha256(key_schedule) => {
                HVec::from_slice(key_schedule.create_binder(transcript_hash).as_slice()).unwrap()
            }
        }
    }

    pub fn create_verify_data(
        &self,
        transcript_hash: &[u8],
        use_server_key: bool,
    ) -> HVec<u8, MAX_HASH_SIZE> {
        match self {
            ServerKeySchedule::Chacha20Poly1305Sha256(key_schedule) => HVec::from_slice(
                key_schedule
                    .create_verify_data(transcript_hash, use_server_key)
                    .as_slice(),
            )
            .unwrap(),
        }
    }

    pub fn initialize_handshake_secret(&mut self, ecdhe: &[u8], transcript: &[u8]) {
        match self {
            ServerKeySchedule::Chacha20Poly1305Sha256(key_schedule) => {
                key_schedule.initialize_handshake_secret(ecdhe, transcript);
            }
        }
    }

    fn initialize_master_secret(&mut self, transcript: &[u8]) {
        match self {
            ServerKeySchedule::Chacha20Poly1305Sha256(key_schedule) => {
                key_schedule.initialize_master_secret(transcript);
            }
        }
    }
}

// All server ciphers must implement `GenericCipher`.
impl GenericKeySchedule for ServerKeySchedule {
    async fn encrypt_record(&mut self, args: CipherArguments<'_>) -> aead::Result<()> {
        match self {
            ServerKeySchedule::Chacha20Poly1305Sha256(cipher) => cipher.encrypt_record(args).await,
        }
    }

    async fn decrypt_record<'a>(
        &mut self,
        ciphertext_header: &DTlsCiphertextHeader<'_>,
        args: CipherArguments<'a>,
    ) -> aead::Result<&'a [u8]> {
        match self {
            ServerKeySchedule::Chacha20Poly1305Sha256(cipher) => {
                cipher.decrypt_record(ciphertext_header, args).await
            }
        }
    }

    fn tag_size(&self) -> usize {
        match self {
            ServerKeySchedule::Chacha20Poly1305Sha256(cipher) => cipher.tag_size(),
        }
    }

    fn write_record_number(&self) -> u64 {
        match self {
            ServerKeySchedule::Chacha20Poly1305Sha256(cipher) => cipher.write_record_number(),
        }
    }

    fn increment_write_record_number(&mut self) {
        match self {
            ServerKeySchedule::Chacha20Poly1305Sha256(cipher) => {
                cipher.increment_write_record_number()
            }
        }
    }

    fn read_record_number(&self) -> u64 {
        match self {
            ServerKeySchedule::Chacha20Poly1305Sha256(cipher) => cipher.read_record_number(),
        }
    }

    fn epoch_number(&self) -> u64 {
        match self {
            ServerKeySchedule::Chacha20Poly1305Sha256(cipher) => cipher.epoch_number(),
        }
    }
}

/// This is used to get the transcript hashes, it stems from the
#[derive(Clone, Debug)]
pub enum TranscriptHasher {
    Sha256(Sha256),
}

impl GenericTranscript for TranscriptHasher {
    fn update(&mut self, data: &[u8]) {
        self.update(data);
    }
}

impl TranscriptHasher {
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        match self {
            TranscriptHasher::Sha256(h) => Digest::update(h, data),
        }
    }

    pub fn finalize(self) -> HVec<u8, MAX_HASH_SIZE> {
        match self {
            TranscriptHasher::Sha256(h) => HVec::from_slice(h.finalize().as_slice()).unwrap(),
        }
    }
}
