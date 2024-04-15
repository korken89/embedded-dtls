use chacha20poly1305::{
    aead::{AeadMutInPlace, KeySizeUser},
    ChaCha20Poly1305,
};
use digest::{core_api::BlockSizeUser, Digest, FixedOutput, OutputSizeUser, Reset};
use sha2::Sha256;

/// Represents a TLS 1.3 cipher suite
#[repr(u16)]
#[derive(Copy, Clone, Debug, defmt::Format, num_enum::TryFromPrimitive)]
pub enum CipherSuite {
    // TlsAes128GcmSha256 = 0x1301,
    // TlsAes256GcmSha384 = 0x1302,
    // TlsChacha20Poly1305Sha256 = 0x1303,
    // TlsAes128CcmSha256 = 0x1304,
    // TlsAes128Ccm8Sha256 = 0x1305,
    // TlsPskAes128GcmSha256 = 0x00A8,
    TlsEcdhePskWithChacha20Poly1305Sha256 = 0xCCAC,
}

/// Defines cipher and hash to use for as crypto suite.
pub trait TlsCipherSuite {
    /// The code point as defined in https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    const CODE_POINT: u16;

    /// Cipher to use with this cipher suite.
    type Cipher: AeadMutInPlace + KeySizeUser;

    /// The hash to use with this cipher suite.
    type Hash: Digest + Reset + Clone + OutputSizeUser + BlockSizeUser + FixedOutput;
}

/// Chacha chipher.
#[derive(Debug)]
pub struct TlsEcdhePskWithChacha20Poly1305Sha256;

impl TlsCipherSuite for TlsEcdhePskWithChacha20Poly1305Sha256 {
    const CODE_POINT: u16 = CipherSuite::TlsEcdhePskWithChacha20Poly1305Sha256 as u16;

    type Cipher = ChaCha20Poly1305;
    type Hash = Sha256;
}
