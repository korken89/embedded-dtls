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

use crate::{buffer::EncodingBuffer, cipher_suites::TlsCipherSuite, handshake::extensions::Psk};
use digest::{generic_array::GenericArray, Digest, KeyInit, Mac, OutputSizeUser};
use hkdf::{hmac::SimpleHmac, SimpleHkdf};

/// Define the HDKF for a cipher suite, so it uses the hash function defined in the trait.
pub type Hkdf<CipherSuite> = SimpleHkdf<<CipherSuite as TlsCipherSuite>::Hash>;

type HashArray<CipherSuite> =
    GenericArray<u8, <<CipherSuite as TlsCipherSuite>::Hash as OutputSizeUser>::OutputSize>;

struct EarlySecret<CipherSuite: TlsCipherSuite> {
    /// Extract secret.
    secret: HashArray<CipherSuite>,
    /// Binder key.
    binder_key: HashArray<CipherSuite>,
    /// HKDF to derive secrets from.
    hkdf: Hkdf<CipherSuite>,
}

struct Secret<CipherSuite: TlsCipherSuite> {
    /// Extract secret.
    secret: HashArray<CipherSuite>,
    // HKDF to derive secrets from.
    hkdf: Hkdf<CipherSuite>,
}

enum KeyScheduleState<CipherSuite: TlsCipherSuite> {
    /// Not initialized.
    Uninitialized,
    /// Optional PSK initialization is done.
    EarlySecret(EarlySecret<CipherSuite>),
    /// Handshake secret is created.
    HandshakeSecret(Secret<CipherSuite>),
    /// Master secret is created.
    MasterSecret(Secret<CipherSuite>),
}

/// This tracks the state of the shared secrets.
// The HKDF can be seen as state that goes through many tranformations.
// Check the flow-chart in RFC8446 section 7.1, page 93 to see the entire flow.
// This means that the HKDF needs to be tracked as continous state for the entire lifetime of the
// connection.
pub struct KeySchedule<CipherSuite: TlsCipherSuite> {
    keyschedule_state: KeyScheduleState<CipherSuite>,
    // server_state: ServerKeySchedule<CipherSuite>,
    // client_state: ClientKeySchedule<CipherSuite>,
}

impl<CipherSuite> KeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new() -> Self {
        Self {
            keyschedule_state: KeyScheduleState::Uninitialized,
        }
    }

    /// Derive a secret for the current state in the key schedule.
    pub fn derive_secret(&self, label: HkdfLabelContext) -> HashArray<CipherSuite> {
        let hkdf = match &self.keyschedule_state {
            KeyScheduleState::Uninitialized => unreachable!("Internal error! `derive_secret` was called before the key schedule was initialized"),
            KeyScheduleState::EarlySecret(secret) =>  &secret.hkdf,
            KeyScheduleState::HandshakeSecret(secret) =>  &secret.hkdf,
            KeyScheduleState::MasterSecret(secret) => &secret.hkdf,
        };

        hkdf_make_expanded_label::<CipherSuite>(hkdf, label)
    }

    /// Calculate a binder.
    pub fn create_binder(&self, transcript_hasher: &CipherSuite::Hash) -> HashArray<CipherSuite> {
        let secret = match &self.keyschedule_state {
            KeyScheduleState::EarlySecret(secret) => secret,
            _ => {
                unreachable!("Internal error! `create_binder` was called when not in early secret")
            }
        };

        let binder_hkdf = Hkdf::<CipherSuite>::from_prk(&secret.binder_key).unwrap();
        let binder_key = hkdf_make_expanded_label::<CipherSuite>(
            &binder_hkdf,
            HkdfLabelContext {
                label: b"finished",
                context: &[],
            },
        );

        let mut hmac =
            <SimpleHmac<CipherSuite::Hash> as KeyInit>::new_from_slice(&binder_key).unwrap();
        Mac::update(&mut hmac, &transcript_hasher.clone().finalize());

        hmac.finalize().into_bytes()
    }

    /// Move to the next step in the secrets.
    ///
    /// Note that the next state needs to be initialized with new input key material.
    fn derived(&mut self) -> HashArray<CipherSuite> {
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

        let no_psk_ikm = HashArray::<CipherSuite>::default();
        let (secret, hkdf) = Hkdf::<CipherSuite>::extract(
            Some(&HashArray::<CipherSuite>::default()),
            psk.map(|psk| psk.key).unwrap_or(&no_psk_ikm),
        );

        // binder_key derivation, not using `derive_secret` due to the `keyschedule_state` being
        // wrong here. We update it below.
        let binder_key = hkdf_make_expanded_label::<CipherSuite>(
            &hkdf,
            HkdfLabelContext {
                label: b"ext binder",
                context: &[],
            },
        );

        self.keyschedule_state = KeyScheduleState::EarlySecret(EarlySecret {
            secret,
            binder_key,
            hkdf,
        });
    }

    /// Initialize the handshake secret using the (EC)DHE shared secret as input key material.
    pub fn initialize_handshake_secret(&mut self, ecdhe_secret: &[u8]) {
        match self.keyschedule_state {
            KeyScheduleState::EarlySecret(_) => {}
            _ => unreachable!(
                "Internal error! Not in early secret stage, cannot initialize handshake secret"
            ),
        }

        // Prepare the previous secret for use in the next stage.
        let (secret, hkdf) = Hkdf::<CipherSuite>::extract(Some(&self.derived()), ecdhe_secret);
        self.keyschedule_state = KeyScheduleState::HandshakeSecret(Secret { secret, hkdf });

        // TODO: Create traffic secrets
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
        let (secret, hkdf) = Hkdf::<CipherSuite>::extract(
            Some(&self.derived()),
            &HashArray::<CipherSuite>::default(), // The input key material is the "0" string
        );
        self.keyschedule_state = KeyScheduleState::MasterSecret(Secret { secret, hkdf });

        // TODO: Create traffic secrets
    }
}

pub struct HkdfLabelContext<'a, 'b> {
    label: &'a [u8],
    context: &'b [u8],
}

fn hkdf_make_expanded_label<CipherSuite: TlsCipherSuite>(
    hkdf: &SimpleHkdf<CipherSuite::Hash>,
    label: HkdfLabelContext,
) -> GenericArray<u8, <<CipherSuite as TlsCipherSuite>::Hash as OutputSizeUser>::OutputSize> {
    let mut hkdf_label = GenericArray::<u8, CipherSuite::LabelBufferSize>::default();
    let mut hkdf_label = EncodingBuffer::new(&mut hkdf_label);

    // Length
    hkdf_label.push_u16_be(hkdf_label.capacity() as u16).ok();
    // Label

    hkdf_label.push_u8(label.label.len() as u8).ok();
    hkdf_label.extend_from_slice(label.label).ok();

    // Context
    hkdf_label.push_u8(label.context.len() as u8).ok();
    hkdf_label.extend_from_slice(label.context).ok();

    let mut okm = GenericArray::default();
    hkdf.expand(&hkdf_label, &mut okm).expect("Internal error");
    okm
}
