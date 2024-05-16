use chacha20poly1305::{
    aead::{AeadMutInPlace, KeySizeUser},
    ChaCha20Poly1305,
};
use digest::{core_api::BlockSizeUser, Digest, FixedOutput, OutputSizeUser, Reset};
use sha2::Sha256;

/// Represents a TLS 1.3 cipher suite
#[repr(u16)]
#[derive(Copy, Clone, Debug, defmt::Format, num_enum::TryFromPrimitive)]
pub enum CodePoint {
    // TlsAes128GcmSha256 = 0x1301,
    // TlsAes256GcmSha384 = 0x1302,
    // TlsChacha20Poly1305Sha256 = 0x1303,
    // TlsAes128CcmSha256 = 0x1304,
    // TlsAes128Ccm8Sha256 = 0x1305,
    // TlsPskAes128GcmSha256 = 0x00A8,
    TlsEcdhePskWithChacha20Poly1305Sha256 = 0xCCAC,
}

/// Defines cipher and hash to use for as crypto suite.
pub trait DtlsCipherSuite {
    /// The code point as defined in https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    const CODE_POINT: CodePoint;

    // TODO: Add if this cipher suite uses PskDheKe or not. Needs proper piping and handling.
    // const ECDHE_KEYSHARE: bool;

    /// Cipher to use with this cipher suite.
    type Cipher: AeadMutInPlace + KeySizeUser;

    /// The hash to use with this cipher suite.
    type Hash: Digest + Reset + Clone + OutputSizeUser + BlockSizeUser + FixedOutput;
}

/// Chacha chipher.
#[derive(Debug)]
pub struct DtlsEcdhePskWithChacha20Poly1305Sha256;

impl DtlsCipherSuite for DtlsEcdhePskWithChacha20Poly1305Sha256 {
    const CODE_POINT: CodePoint = CodePoint::TlsEcdhePskWithChacha20Poly1305Sha256;
    // const ECDHE_KEYSHARE: bool = true;

    type Cipher = ChaCha20Poly1305;
    type Hash = Sha256;
}
