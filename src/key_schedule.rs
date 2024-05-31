// From RFC:
// HKDF-Expand-Label(Secret, Label, Context, Length) =
//      HKDF-Expand(Secret, HkdfLabel, Length)
//
// Where HkdfLabel is specified as:
//
// struct {
//     uint16 length = Length;
//     opaque label<7..255> = "tls13 " + Label;
//     opaque context<0..255> = Context;
// } HkdfLabel;
//
// Derive-Secret(Secret, Label, Messages) =
//      HKDF-Expand-Label(Secret, Label,
//                        Transcript-Hash(Messages), Hash.length)

use crate::{
    buffer::{CryptoBuffer, EncodingBuffer},
    cipher_suites::{DtlsCipher, DtlsCipherSuite, DtlsReKeyInPlace},
    handshake::extensions::Psk,
    record::{CipherArguments, CiphertextSequenceNumber, DTlsCiphertextHeader, GenericCipher},
};
use aead::Buffer;
use chacha20poly1305::{AeadCore, KeySizeUser};
use digest::{
    core_api::BlockSizeUser,
    generic_array::{ArrayLength, GenericArray},
    Digest, KeyInit, Mac, OutputSizeUser,
};
use hkdf::{hmac::SimpleHmac, SimpleHkdf};
use zeroize::Zeroize;

type HashArray<Hash> = GenericArray<u8, <Hash as OutputSizeUser>::OutputSize>;

struct EarlySecret<Hash: Digest + OutputSizeUser + BlockSizeUser + Clone> {
    // TODO: This is not used as the `secret` is stored in the hkdf. One could instead store the
    // `secret` and create the HDKF from `SimpleHkdf::<D>::from_prk(secret)`. Not sure what makes
    // most sense. The use will show what we need.
    // /// Extract secret.
    // secret: HashArray<D>,
    /// Binder key.
    binder_key: HashArray<Hash>,
    /// HKDF to derive secrets from.
    hkdf: SimpleHkdf<Hash>,
}

/// A pair of traffic secrets.
#[derive(Zeroize)]
pub struct TrafficSecrets<Cipher>
where
    Cipher: DtlsCipher + KeySizeUser,
{
    /// Client traffic keying material.
    pub client:
        TrafficKeyingMaterial<<Cipher as KeySizeUser>::KeySize, <Cipher as AeadCore>::NonceSize>,
    /// Server traffic keying material.
    pub server:
        TrafficKeyingMaterial<<Cipher as KeySizeUser>::KeySize, <Cipher as AeadCore>::NonceSize>,
}

impl<Cipher> core::fmt::Debug for TrafficSecrets<Cipher>
where
    Cipher: DtlsCipher + KeySizeUser,
    <Cipher as KeySizeUser>::KeySize: std::fmt::Debug,
    <Cipher as AeadCore>::NonceSize: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TrafficSecrets {{ client: {:02x?}, server: {:02x?} }}",
            self.client, self.server
        )
    }
}

/// A single direction keying material. Holds the symmetric encryption key and the initialization
/// vector.
#[derive(Zeroize, Debug)]
pub struct TrafficKeyingMaterial<KeySize: ArrayLength<u8>, IvSize: ArrayLength<u8>> {
    pub write_key: GenericArray<u8, KeySize>,
    pub write_iv: GenericArray<u8, IvSize>,
    pub sn_key: GenericArray<u8, KeySize>,
}

impl<KeySize: ArrayLength<u8>, IvSize: ArrayLength<u8>> TrafficKeyingMaterial<KeySize, IvSize> {
    /// Create the nonce given the record sequence number.
    pub fn create_nonce(&self, record_number: u64) -> GenericArray<u8, IvSize> {
        // Defined in Section 5.3, RFC8446.
        let mut iv = self.write_iv.clone();

        // NOTE(rev): The sequence number is padded to the left with zeros,
        // so apply the XOR from the end instead of skipping from the start of `iv`.
        for (iv, seq) in iv
            .iter_mut()
            .rev()
            .zip(record_number.to_be_bytes().iter().rev().copied())
        {
            *iv ^= seq;
        }

        iv
    }
}

/// Initialization vector that will clear the IV on drop.
#[derive(Zeroize, Debug)]
pub struct Iv<N: ArrayLength<u8>> {
    key: GenericArray<u8, N>,
}

struct Secret<CipherSuite: DtlsCipherSuite> {
    // TODO: This is not used as the `secret` is stored in the hkdf.
    // /// Extract secret.
    // secret: HashArray<D>,
    /// HKDF to derive secrets from.
    hkdf: SimpleHkdf<<CipherSuite as DtlsCipherSuite>::Hash>,
    /// Traffic secret.
    traffic_secrets: TrafficSecrets<<CipherSuite as DtlsCipherSuite>::Cipher>,
    // /// Server handshake traffic secret.
    // server_handshake_traffic_secret: Key<D>,
}

enum KeyScheduleState<CipherSuite: DtlsCipherSuite, const IS_SERVER: bool> {
    /// Not initialized.
    Uninitialized,
    /// Optional PSK initialization is done.
    EarlySecret(EarlySecret<<CipherSuite as DtlsCipherSuite>::Hash>),
    /// Handshake secret is created.
    HandshakeSecret(Secret<CipherSuite>),
    /// Master secret is created.
    MasterSecret(Secret<CipherSuite>),
}

impl<CipherSuite: DtlsCipherSuite, const IS_SERVER: bool> KeyScheduleState<CipherSuite, IS_SERVER> {
    fn create_encryption_nonce(
        &self,
        record_number: u64,
    ) -> GenericArray<u8, <<CipherSuite as DtlsCipherSuite>::Cipher as AeadCore>::NonceSize> {
        let traffic_secrets = self.traffic_secrets();

        if IS_SERVER {
            &traffic_secrets.server
        } else {
            &traffic_secrets.client
        }
        .create_nonce(record_number)
    }

    fn create_decryption_nonce(
        &self,
        record_number: u64,
    ) -> GenericArray<u8, <<CipherSuite as DtlsCipherSuite>::Cipher as AeadCore>::NonceSize> {
        let traffic_secrets = self.traffic_secrets();

        if IS_SERVER {
            &traffic_secrets.client
        } else {
            &traffic_secrets.server
        }
        .create_nonce(record_number)
    }

    fn encryption_mask_key(
        &self,
    ) -> &GenericArray<u8, <<CipherSuite as DtlsCipherSuite>::Cipher as KeySizeUser>::KeySize> {
        let traffic_secrets = self.traffic_secrets();

        if IS_SERVER {
            &traffic_secrets.server.sn_key
        } else {
            &traffic_secrets.client.sn_key
        }
    }

    fn decryption_mask_key(
        &self,
    ) -> &GenericArray<u8, <<CipherSuite as DtlsCipherSuite>::Cipher as KeySizeUser>::KeySize> {
        let traffic_secrets = self.traffic_secrets();

        if IS_SERVER {
            &traffic_secrets.client.sn_key
        } else {
            &traffic_secrets.server.sn_key
        }
    }

    fn encryption_aead_key(
        &self,
    ) -> &GenericArray<u8, <<CipherSuite as DtlsCipherSuite>::Cipher as KeySizeUser>::KeySize> {
        let traffic_secrets = self.traffic_secrets();

        if IS_SERVER {
            &traffic_secrets.server.write_key
        } else {
            &traffic_secrets.client.write_key
        }
    }

    fn decryption_aead_key(
        &self,
    ) -> &GenericArray<u8, <<CipherSuite as DtlsCipherSuite>::Cipher as KeySizeUser>::KeySize> {
        let traffic_secrets = self.traffic_secrets();

        if IS_SERVER {
            &traffic_secrets.client.write_key
        } else {
            &traffic_secrets.server.write_key
        }
    }

    fn traffic_secrets(&self) -> &TrafficSecrets<<CipherSuite as DtlsCipherSuite>::Cipher> {
        match self {
            KeyScheduleState::Uninitialized => unreachable!(),
            KeyScheduleState::EarlySecret(_) => unreachable!(),
            KeyScheduleState::HandshakeSecret(s) => &s.traffic_secrets,
            KeyScheduleState::MasterSecret(s) => &s.traffic_secrets,
        }
    }
}

/// This tracks the state of the shared secrets.
// The HKDF can be seen as state that goes through many tranformations.
// Check the flow-chart in RFC8446 section 7.1, page 93 to see the entire flow.
// This means that the HKDF needs to be tracked as continous state for the entire lifetime of the
// connection.
pub struct KeySchedule<CipherSuite: DtlsCipherSuite, const IS_SERVER: bool> {
    keyschedule_state: KeyScheduleState<CipherSuite, IS_SERVER>,
    cipher: CipherSuite::Cipher,
    write_record_number: u64,
    read_record_number: u64,
    epoch_number: u64,
}

impl<CipherSuite> KeySchedule<CipherSuite, true>
where
    CipherSuite: DtlsCipherSuite,
{
    /// Create a new key schedule for a server.
    pub fn new_server(cipher: CipherSuite::Cipher) -> Self {
        Self {
            keyschedule_state: KeyScheduleState::Uninitialized,
            cipher,
            write_record_number: 0,
            read_record_number: 0,
            epoch_number: 0,
        }
    }
}

impl<CipherSuite> KeySchedule<CipherSuite, false>
where
    CipherSuite: DtlsCipherSuite,
{
    /// Create a new key schedule for a client.
    pub fn new_client(cipher: CipherSuite::Cipher) -> Self {
        Self {
            keyschedule_state: KeyScheduleState::Uninitialized,
            cipher,
            write_record_number: 0,
            read_record_number: 0,
            epoch_number: 0,
        }
    }
}

impl<CipherSuite, const IS_SERVER: bool> KeySchedule<CipherSuite, IS_SERVER>
where
    CipherSuite: DtlsCipherSuite,
    <<CipherSuite as DtlsCipherSuite>::Cipher as AeadCore>::NonceSize: std::fmt::Debug,
    <<CipherSuite as DtlsCipherSuite>::Cipher as KeySizeUser>::KeySize: std::fmt::Debug,
{
    /// Check if the key schedule is uninitialized.
    pub fn is_uninitialized(&self) -> bool {
        match &self.keyschedule_state {
            KeyScheduleState::Uninitialized => true,
            _ => false,
        }
    }

    /// Derive a secret for the current state in the key schedule.
    fn derive_secret(
        &self,
        label: HkdfLabelContext,
    ) -> HashArray<<CipherSuite as DtlsCipherSuite>::Hash> {
        let hkdf = match &self.keyschedule_state {
            KeyScheduleState::Uninitialized => unreachable!("Internal error! `derive_secret` was called before the key schedule was initialized"),
            KeyScheduleState::EarlySecret(secret) =>  &secret.hkdf,
            KeyScheduleState::HandshakeSecret(secret) =>  &secret.hkdf,
            KeyScheduleState::MasterSecret(secret) => &secret.hkdf,
        };

        let mut secret = HashArray::<<CipherSuite as DtlsCipherSuite>::Hash>::default();
        hkdf_make_expanded_label::<<CipherSuite as DtlsCipherSuite>::Hash>(
            hkdf,
            label,
            &mut secret,
        );
        secret
    }

    /// Calculate a binder. The hash must be the same size as the output for the hash function.
    pub fn create_binder(
        &self,
        transcript_hash: &[u8],
    ) -> Option<HashArray<<CipherSuite as DtlsCipherSuite>::Hash>> {
        if transcript_hash.len()
            != <<CipherSuite as DtlsCipherSuite>::Hash as Digest>::output_size()
        {
            return None;
        }

        let secret = match &self.keyschedule_state {
            KeyScheduleState::EarlySecret(secret) => secret,
            _ => {
                unreachable!("Internal error! `create_binder` was called when not in early secret")
            }
        };

        let binder_hkdf =
            SimpleHkdf::<<CipherSuite as DtlsCipherSuite>::Hash>::from_prk(&secret.binder_key)
                .unwrap();
        let mut binder_key = HashArray::<<CipherSuite as DtlsCipherSuite>::Hash>::default();
        hkdf_make_expanded_label::<<CipherSuite as DtlsCipherSuite>::Hash>(
            &binder_hkdf,
            HkdfLabelContext {
                label: b"finished",
                context: &[],
            },
            &mut binder_key,
        );

        let mut hmac =
            <SimpleHmac<<CipherSuite as DtlsCipherSuite>::Hash> as KeyInit>::new_from_slice(
                &binder_key,
            )
            .unwrap();
        Mac::update(&mut hmac, &transcript_hash);

        Some(hmac.finalize().into_bytes())
    }

    /// Move to the next step in the secrets.
    ///
    /// Note that the next state needs to be initialized with new input key material.
    fn derived(&self) -> HashArray<<CipherSuite as DtlsCipherSuite>::Hash> {
        self.derive_secret(HkdfLabelContext {
            label: b"derived",
            context: &[],
        })
    }

    /// Initialize the key schedule with an optional PSK.
    pub fn initialize_early_secret(&mut self, psk: Option<Psk>) {
        match self.keyschedule_state {
            KeyScheduleState::Uninitialized => {}
            _ => unreachable!(
                "Internal error! Called initialize on an already initialized key schedule"
            ),
        }

        // When there is no PSK, input 0s as IKM.
        let no_psk_ikm = HashArray::<<CipherSuite as DtlsCipherSuite>::Hash>::default();
        let (_secret, hkdf) = SimpleHkdf::<<CipherSuite as DtlsCipherSuite>::Hash>::extract(
            Some(&HashArray::<<CipherSuite as DtlsCipherSuite>::Hash>::default()),
            psk.map(|psk| psk.key).unwrap_or(&no_psk_ikm),
        );

        // binder_key derivation, not using `derive_secret` due to the `keyschedule_state` being
        // wrong here. We update it below.
        let mut binder_key = HashArray::<<CipherSuite as DtlsCipherSuite>::Hash>::default();
        hkdf_make_expanded_label::<<CipherSuite as DtlsCipherSuite>::Hash>(
            &hkdf,
            HkdfLabelContext {
                label: b"ext binder",
                context: &[],
            },
            &mut binder_key,
        );

        self.keyschedule_state = KeyScheduleState::EarlySecret(EarlySecret { binder_key, hkdf });
    }

    /// Initialize the handshake secret using the (EC)DHE shared secret as input key material.
    /// The transcript hash is over the ClientHello and ServerHello.
    pub fn initialize_handshake_secret(&mut self, ecdhe_secret: &[u8], transcript: &[u8]) {
        match self.keyschedule_state {
            KeyScheduleState::EarlySecret(_) => {}
            _ => unreachable!(
                "Internal error! Not in early secret stage, cannot initialize handshake secret"
            ),
        }

        l0g::trace!(
            "Crate handshake secrets ecdhe {ecdhe_secret:02x?}, transcript {transcript:02x?}"
        );

        // Prepare the previous secret for use in the next stage.
        let (_secret, hkdf) = SimpleHkdf::<<CipherSuite as DtlsCipherSuite>::Hash>::extract(
            Some(&self.derived()),
            ecdhe_secret,
        );

        let traffic_secrets = Self::create_handshake_traffic_secrets(&hkdf, transcript);

        // According to Figure 13, RFC9147 epoch is now 2.
        self.epoch_number = 2;

        self.keyschedule_state = KeyScheduleState::HandshakeSecret(Secret {
            hkdf,
            traffic_secrets,
        });
    }

    /// Get the handshake traffic secrets.
    /// The transcript hash is over the ClientHello and ServerHello.
    fn create_handshake_traffic_secrets(
        hkdf: &SimpleHkdf<<CipherSuite as DtlsCipherSuite>::Hash>,
        transcript_hash: &[u8],
    ) -> TrafficSecrets<<CipherSuite as DtlsCipherSuite>::Cipher> {
        // This follows Section 7.3. Traffic Key Calculation in RFC8446.
        let mut client = HashArray::<<CipherSuite as DtlsCipherSuite>::Hash>::default();
        hkdf_make_expanded_label::<<CipherSuite as DtlsCipherSuite>::Hash>(
            hkdf,
            HkdfLabelContext {
                label: b"c hs traffic",
                context: transcript_hash,
            },
            &mut client,
        );

        let mut server = HashArray::<<CipherSuite as DtlsCipherSuite>::Hash>::default();
        hkdf_make_expanded_label::<<CipherSuite as DtlsCipherSuite>::Hash>(
            hkdf,
            HkdfLabelContext {
                label: b"s hs traffic",
                context: transcript_hash,
            },
            &mut server,
        );

        TrafficSecrets {
            client: Self::create_traffic_keying_material(&client),
            server: Self::create_traffic_keying_material(&server),
        }
    }

    /// Initialize the master secret.
    pub fn initialize_master_secret(&mut self) {
        match self.keyschedule_state {
            KeyScheduleState::HandshakeSecret(_) => {}
            _ => unreachable!(
                "Internal error! Not in handshake secret stage, cannot initialize master secret"
            ),
        }

        // Prepare the previous secret for use in the next stage.
        let (_secret, hkdf) = SimpleHkdf::<<CipherSuite as DtlsCipherSuite>::Hash>::extract(
            Some(&self.derived()),
            &HashArray::<<CipherSuite as DtlsCipherSuite>::Hash>::default(), // The input key material is the "0" string
        );
        let traffic_secrets = todo!();

        self.keyschedule_state = KeyScheduleState::MasterSecret(Secret {
            hkdf,
            traffic_secrets,
        });

        // TODO: Create application traffic secrets

        // TODO: Create sn_key for record number encryption (section 4.2.3, RFC9147)
    }

    fn create_traffic_keying_material<KeySize: ArrayLength<u8>, IvSize: ArrayLength<u8>>(
        secret: &HashArray<<CipherSuite as DtlsCipherSuite>::Hash>,
    ) -> TrafficKeyingMaterial<KeySize, IvSize> {
        let hkdf = SimpleHkdf::from_prk(&secret).unwrap();

        let mut write_key = GenericArray::default();
        hkdf_make_expanded_label::<<CipherSuite as DtlsCipherSuite>::Hash>(
            &hkdf,
            HkdfLabelContext {
                label: b"key",
                context: &[],
            },
            &mut write_key,
        );

        let mut write_iv = GenericArray::default();
        hkdf_make_expanded_label::<<CipherSuite as DtlsCipherSuite>::Hash>(
            &hkdf,
            HkdfLabelContext {
                label: b"iv",
                context: &[],
            },
            &mut write_iv,
        );

        let mut sn_key = GenericArray::default();
        hkdf_make_expanded_label::<<CipherSuite as DtlsCipherSuite>::Hash>(
            &hkdf,
            HkdfLabelContext {
                label: b"sn",
                context: &[],
            },
            &mut sn_key,
        );

        TrafficKeyingMaterial {
            write_key,
            write_iv,
            sn_key,
        }
    }
}

struct HkdfLabelContext<'a, 'b> {
    label: &'a [u8],
    context: &'b [u8],
}

fn hkdf_make_expanded_label<Hash>(hkdf: &SimpleHkdf<Hash>, label: HkdfLabelContext, okm: &mut [u8])
where
    Hash: Digest + BlockSizeUser + Clone,
{
    // Max length of a label is:
    // - length: 2
    // - label: 1 + 18
    // - context: 1 + hash length
    // = 22 + hash length
    // and lets assume the largest hash is 512 bits = 64 bytes
    // this gives the max size of 86 bytes.

    // NOTE: Why is this not a typenum sum? It infects the entire call tree with trait bounds.
    // Instead we just pay the stack overhead of a few bytes here.
    let mut hkdf_label = [0; 86];
    let mut hkdf_label = EncodingBuffer::new(&mut hkdf_label);

    // Length
    hkdf_label.push_u16_be(hkdf_label.capacity() as u16).ok();
    // Label

    hkdf_label.push_u8(label.label.len() as u8).ok();
    hkdf_label.extend_from_slice(label.label).ok();

    // Context
    hkdf_label.push_u8(label.context.len() as u8).ok();
    hkdf_label.extend_from_slice(label.context).ok();

    okm.fill(0);
    hkdf.expand(&hkdf_label, okm).expect("Internal error");
}

impl<CipherSuite, const IS_SERVER: bool> GenericCipher for KeySchedule<CipherSuite, IS_SERVER>
where
    CipherSuite: DtlsCipherSuite,
{
    async fn encrypt_record(&mut self, args: CipherArguments<'_>) -> aead::Result<()> {
        let CipherArguments {
            mut unified_hdr,
            payload_with_tag,
        } = args;

        if payload_with_tag.len() < 16 {
            // Invalid record.
            return Err(aead::Error);
        }

        let mut payload_with_tag = {
            let payload_len = payload_with_tag.len();
            let mut buf = CryptoBuffer::new(payload_with_tag);
            // Make the buffer indicate that the tag space is unwritten.
            buf.truncate(payload_len - self.tag_size());
            buf
        };

        // Set the key for AEAD cipher. We re-key for every time as encryption and decryption
        // shares the underlying cipher.
        self.cipher
            .rekey_aead(self.keyschedule_state.encryption_aead_key());

        self.cipher
            .encrypt_plaintext(
                &self
                    .keyschedule_state
                    .create_encryption_nonce(self.write_record_number),
                &mut payload_with_tag,
                unified_hdr.full_header(),
            )
            .await?;

        // Set the key for mask cipher. We re-key for every time as encryption and decryption
        // shares the underlying cipher.
        self.cipher
            .rekey_mask(self.keyschedule_state.encryption_mask_key());

        self.cipher
            .apply_mask_for_record_number(
                // NOTE(unwrap/slicing): Guaranteed to succeed. The length must be at least 16.
                &payload_with_tag.as_ref()[..16].try_into().unwrap(),
                unified_hdr.sequence_number_mut(),
            )
            .await?;

        Ok(())
    }

    async fn decrypt_record<'a>(
        &mut self,
        ciphertext_header: &DTlsCiphertextHeader<'_>,
        args: CipherArguments<'a>,
    ) -> aead::Result<&'a [u8]> {
        let CipherArguments {
            mut unified_hdr,
            payload_with_tag,
        } = args;

        if payload_with_tag.len() < 16.max(self.tag_size()) {
            l0g::debug!("Invalid record, too short");
            // Invalid record, 16 bytes minimum for record number max and tag size to make sure
            // there is a tag.
            return Err(aead::Error);
        }

        // Check the epoch, early return if wrong.
        if ciphertext_header.epoch & 0b11 != self.epoch_number as u8 & 0b11 {
            l0g::debug!("Wrong epoch");
            return Err(aead::Error);
        }

        // Set the key for mask cipher. We re-key for every time as encryption and decryption
        // shares the underlying cipher.
        self.cipher
            .rekey_mask(self.keyschedule_state.decryption_mask_key());

        let mut payload_with_tag_buffer = CryptoBuffer::new(payload_with_tag);

        if self
            .cipher
            .apply_mask_for_record_number(
                // NOTE(unwrap/slicing): Guaranteed to succeed. The length must be at least 16.
                &payload_with_tag_buffer.as_ref()[..16].try_into().unwrap(),
                unified_hdr.sequence_number_mut(),
            )
            .await
            .is_err()
        {
            l0g::debug!("Applying sequence number mask failed");
        }

        let sequence_number = unified_hdr.sequence_number();
        l0g::trace!("Got sequence number: {sequence_number:?}");
        let estimated_read_record_number =
            find_closest_record_number(self.read_record_number, sequence_number);
        l0g::trace!(
            "Estimated read record number: {estimated_read_record_number:?} ({})",
            if IS_SERVER { "server" } else { "client" }
        );

        // Set the key for AEAD cipher. We re-key for every time as encryption and decryption
        // shares the underlying cipher.
        self.cipher
            .rekey_aead(self.keyschedule_state.decryption_aead_key());

        self.cipher
            .decrypt_ciphertext(
                &self
                    .keyschedule_state
                    .create_decryption_nonce(estimated_read_record_number),
                &mut payload_with_tag_buffer,
                unified_hdr.full_header(),
            )
            .await?;

        l0g::trace!("Decryption successful");

        // Decryption successful, store the read_record_number if it is larger.
        self.read_record_number = self.read_record_number.max(estimated_read_record_number);

        Ok(&payload_with_tag[..payload_with_tag.len() - self.tag_size()])
    }

    fn tag_size(&self) -> usize {
        use aead::generic_array::typenum::Unsigned;
        <CipherSuite::Cipher as AeadCore>::TagSize::to_usize()
    }

    fn write_record_number(&self) -> u64 {
        let r = self.write_record_number;

        l0g::trace!("using write record number: {}", r);
        r
    }

    fn increment_write_record_number(&mut self) {
        self.write_record_number += 1;
        l0g::trace!(
            "incremented write record number to: {} ({})",
            self.write_record_number,
            if IS_SERVER { "server" } else { "client" }
        );
    }

    fn epoch_number(&self) -> u64 {
        self.epoch_number
    }
}

/// This implements the recommended reconstruction algorithm in Section 4.2.2 RFC 9147.
fn find_closest_record_number(
    last_successful_record_number: u64,
    seq: CiphertextSequenceNumber,
) -> u64 {
    const MASK_UPPER16: u64 = !0xffff;
    const MASK_MSB16: u16 = 0x8000;
    const OFFSET16: u64 = 0x8000;

    const MASK_UPPER8: u64 = !0xff;
    const MASK_MSB8: u16 = 0x80;
    const OFFSET8: u64 = 0x80;

    let (mask_upper, mask_msb, offset, seq) = match seq {
        CiphertextSequenceNumber::Short(s) => (MASK_UPPER8, MASK_MSB8, OFFSET8, s as u64),
        CiphertextSequenceNumber::Long(l) => (MASK_UPPER16, MASK_MSB16, OFFSET16, l as u64),
    };

    let lower = (last_successful_record_number as u16).wrapping_add(1);
    // If MSB is set we need to check the current record number and the next overflow for the
    // match. If it is not set we need to check the current and the previous.
    let msb = lower & mask_msb != 0;

    let candidate_center = (last_successful_record_number & mask_upper) | seq;
    let diff_center = last_successful_record_number.abs_diff(candidate_center + 1) as u16;

    if msb {
        let candidate_next = ((last_successful_record_number + offset) & mask_upper) | seq;
        let diff_next = last_successful_record_number.abs_diff(candidate_next + 1) as u16;

        if diff_center < diff_next {
            candidate_center
        } else {
            candidate_next
        }
    } else {
        if last_successful_record_number < offset {
            return candidate_center;
        }

        let candidate_prev = ((last_successful_record_number - offset) & mask_upper) | seq;
        let diff_prev = last_successful_record_number.abs_diff(candidate_prev + 1) as u16;

        if diff_center < diff_prev {
            candidate_center
        } else {
            candidate_prev
        }
    }
}

#[cfg(test)]
mod test {
    // TODO: More tests. One that takes worst case +/- around current and shuffles.
    use super::find_closest_record_number;
    use crate::record::CiphertextSequenceNumber;

    #[test]
    fn closest_record_number_linear_u8() {
        let mut last_record_number = 0;

        for num in 0..10_000_000 {
            let estimated = find_closest_record_number(
                last_record_number,
                CiphertextSequenceNumber::Short(num as u8),
            );

            assert_eq!(num, estimated);

            last_record_number = estimated;
        }
    }

    #[test]
    fn closest_record_number_linear_u16() {
        let mut last_record_number = 0;

        for num in 0..10_000_000 {
            let estimated = find_closest_record_number(
                last_record_number,
                CiphertextSequenceNumber::Long(num as u16),
            );

            assert_eq!(num, estimated);

            last_record_number = estimated;
        }
    }
}
