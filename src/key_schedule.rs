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

use crate::cipher_suites::TlsCipherSuite;
use digest::{generic_array::GenericArray, OutputSizeUser};
use hkdf::SimpleHkdf;

/// Define the HDKF for a cipher suite, so it uses the hash function defined in the trait.
pub type Hkdf<CipherSuite> = SimpleHkdf<<CipherSuite as TlsCipherSuite>::Hash>;

type HashArray<CipherSuite> =
    GenericArray<u8, <<CipherSuite as TlsCipherSuite>::Hash as OutputSizeUser>::OutputSize>;

struct Secret<CipherSuite: TlsCipherSuite> {
    /// Extract secret.
    secret: HashArray<CipherSuite>,
    // HKDF to derive secrets from.
    hkdf: Hkdf<CipherSuite>,
}

impl<CipherSuite> Secret<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        let (secret, hkdf) = Hkdf::<CipherSuite>::extract(salt, ikm);
        Secret { secret, hkdf }
    }
}

enum KeyScheduleState<CipherSuite: TlsCipherSuite> {
    /// Not initialized.
    Uninitialized,
    /// Optional PSK initialization is done.
    EarlySecret(Secret<CipherSuite>),
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

    // pub fn derive_secret(&mut self) {
    //     match self.keyschedule_state {
    //         KeyScheduleState::Uninitialized => {}
    //         KeyScheduleState::EarlySecret(s) => todo!(),
    //         KeyScheduleState::HandshakeSecret() => todo!(),
    //         KeyScheduleState::MasterSecret() => {}
    //     }
    // }

    pub fn initialize_early_secret(&mut self, psk: Option<&[u8]>) {
        match self.keyschedule_state {
            KeyScheduleState::Uninitialized => {}
            _ => return, // TODO: Handle error
        }
    }
}

struct HkdfLabel<'a> {
    label: &'a [u8],
    context: &'a [u8],
}

// fn hkdf_expand<CipherSuite: TlsCipherSuite, OutSize>(
//     secret: &[u8],
//     label: &HkdfLabel,
// ) -> GenericArray<u8, CipherSuite::HashDigestSize> {
//     let mut hkdf_label = ArrayBuffer::<CipherSuite::LabelBufferSize>::new();

//     // Length
//     hkdf_label.push_u16_be(hkdf_label.capacity() as u16).ok();

//     // Label
//     hkdf_label.push_u8(label.label.len() as u8).ok();
//     hkdf_label.extend_from_slice(label.label).ok();

//     // Context
//     hkdf_label.push_u8(label.context.len() as u8).ok();
//     hkdf_label.extend_from_slice(label.context).ok();

//     let mut okm = GenericArray::default();

//     let (secret, hkdf_that_can_expand) = SimpleHkdf::extract(
//         Some(&GenericArray::<u8, CipherSuite::HashDigestSize>::default()),
//         secret,
//     );

//     okm
// }
