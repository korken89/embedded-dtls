use aead::{AeadCore, AeadMutInPlace, KeyInit, KeySizeUser};
use chacha20poly1305::{ChaCha20Poly1305, ChaChaPoly1305};
use defmt_or_log::derive_format_or_debug;
use digest::{
    core_api::BlockSizeUser, generic_array::GenericArray, Digest, FixedOutput, OutputSizeUser,
    Reset,
};
use sha2::Sha256;

use crate::buffer::CryptoBuffer;

/// Represents a TLS 1.3 cipher suite
#[repr(u16)]
#[derive_format_or_debug]
#[derive(Copy, Clone, num_enum::TryFromPrimitive)]
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
    type Cipher: DtlsCipher + DtlsReKeyInPlace;

    /// The hash to use with this cipher suite.
    type Hash: Digest + Reset + Clone + OutputSizeUser + BlockSizeUser + FixedOutput;
}

/// A DTLS 1.3 cipher's required operations.
///
/// It is guaranteed that `DtlsReKeyInPlace` is called before any of the methods in this trait
/// are used. This allows for implementing `Defaul` using 0s as keys on ciphers.
pub trait DtlsCipher: AeadCore {
    /// Encrypt a plaintext using the provided key and nonce. The `plaintext_with_tag` here is
    /// defined as the actual plaintext together with the AEAD tag allocated at the end. So the
    /// length of `plaintext_with_tag` is `plaintext.len()`, with extra `aead_tag.len()` left for
    /// encoding.
    ///
    /// Note: The `unified_hdr` does not have its sequence number encrypted here and is to
    /// be used as Associated Data (AD).
    ///
    /// Implementation is defined in Section 4.2.3 in RFC9147.
    async fn encrypt_plaintext(
        &mut self,
        nonce: &GenericArray<u8, <Self as AeadCore>::NonceSize>,
        plaintext_with_tag: &mut CryptoBuffer<'_>,
        unified_hdr: &[u8],
    ) -> aead::Result<()>;

    /// Decrypt a ciphertext, including tag, using the provided key and nonce.
    ///
    /// Note: The `unified_hdr` does not have its sequence number encrypted here and is to
    /// be used as Associated Data (AD).
    ///
    /// Implementation is defined in Section 4.2.3 in RFC9147.
    async fn decrypt_ciphertext(
        &mut self,
        nonce: &GenericArray<u8, <Self as AeadCore>::NonceSize>,
        ciphertext_with_tag: &mut CryptoBuffer<'_>,
        unified_hdr: &[u8],
    ) -> aead::Result<()>;

    /// Encrypt/decrypt a record number using the provided ciphertext block.
    ///
    /// Implementation and how to use the ciphertext block is defined in Section 4.2.3 RFC9147.
    async fn apply_mask_for_record_number(
        &mut self,
        ciphertext: &[u8; 16],
        record_number: &mut [u8],
    ) -> aead::Result<()>;
}

/// Chacha cipher.
#[derive_format_or_debug]
pub struct DtlsEcdhePskWithChacha20Poly1305Sha256;

impl DtlsCipherSuite for DtlsEcdhePskWithChacha20Poly1305Sha256 {
    const CODE_POINT: CodePoint = CodePoint::TlsEcdhePskWithChacha20Poly1305Sha256;
    // const ECDHE_KEYSHARE: bool = true; // TODO, this needs defining

    type Cipher = ChaCha20Poly1305Cipher;
    type Hash = Sha256;
}

/// A DTLS 1.3 cipher implementation based on ChaCha20Poly1305.
pub struct ChaCha20Poly1305Cipher {
    aead: ChaCha20Poly1305,
    mask_key: GenericArray<u8, <chacha20::ChaCha20 as KeySizeUser>::KeySize>,
}

impl Default for ChaCha20Poly1305Cipher {
    fn default() -> Self {
        // NOTE: Default keys are OK since the `DtlsCipher` trait guarantees re-keying before
        // the ciphers are used.
        Self {
            aead: ChaChaPoly1305::new(&Default::default()),
            mask_key: Default::default(),
        }
    }
}

impl AeadCore for ChaCha20Poly1305Cipher {
    type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;
    type TagSize = <ChaCha20Poly1305 as AeadCore>::TagSize;
    type CiphertextOverhead = <ChaCha20Poly1305 as AeadCore>::CiphertextOverhead;
}

impl KeySizeUser for ChaCha20Poly1305Cipher {
    type KeySize = <ChaCha20Poly1305 as KeySizeUser>::KeySize;
}

/// DTLS 1.3 ciphers needs to be re-keyed from time to time, this interface allows for this.
pub trait DtlsReKeyInPlace: KeySizeUser {
    /// Re-key the AEAD cipher from fixed size key.
    ///
    /// This is called the `*_traffic_secret*` in Section 7.1 RFC8446.
    fn rekey_aead(&mut self, key: &aead::Key<Self>);

    /// Re-key the record number mask cipher from fixed size key.
    ///
    /// This is called the `sn_key` in Section 4.2.3 RFC9147.
    fn rekey_mask(&mut self, key: &aead::Key<Self>);
}

impl DtlsReKeyInPlace for ChaCha20Poly1305Cipher {
    fn rekey_aead(&mut self, key: &aead::Key<Self>) {
        #[cfg(feature = "unsafe_debug_keys")]
        defmt_or_log::debug!("New aead key: {:?}", key.as_slice());
        // The ChaCha20Poly1305 allows for creation from the key.
        self.aead = ChaCha20Poly1305::new(key);
    }

    fn rekey_mask(&mut self, key: &aead::Key<Self>) {
        #[cfg(feature = "unsafe_debug_keys")]
        defmt_or_log::debug!("New mask key: {:?}", key.as_slice());
        // The ChaCha20 stream cipher does not allow for creation from the key, it also needs the
        // IV. The cipher is created on the fly in `apply_mask_for_record_number` instead where
        // the IV is available.
        self.mask_key = *key;
    }
}

impl DtlsCipher for ChaCha20Poly1305Cipher {
    async fn encrypt_plaintext(
        &mut self,
        nonce: &GenericArray<u8, <Self as AeadCore>::NonceSize>,
        plaintext_with_tag: &mut CryptoBuffer<'_>,
        unified_hdr: &[u8],
    ) -> aead::Result<()> {
        #[cfg(feature = "unsafe_debug_keys")]
        defmt_or_log::debug!("Encrypting with nonce: {:?}", nonce.as_slice());

        self.aead
            .encrypt_in_place(nonce, unified_hdr, plaintext_with_tag)
    }

    async fn decrypt_ciphertext(
        &mut self,
        nonce: &GenericArray<u8, <Self as AeadCore>::NonceSize>,
        ciphertext_with_tag: &mut CryptoBuffer<'_>,
        unified_hdr: &[u8],
    ) -> aead::Result<()> {
        #[cfg(feature = "unsafe_debug_keys")]
        defmt_or_log::debug!("Decrypting with nonce: {:?}", nonce.as_slice());

        self.aead
            .decrypt_in_place(nonce, &unified_hdr, ciphertext_with_tag)
    }

    async fn apply_mask_for_record_number(
        &mut self,
        ciphertext: &[u8; 16],
        record_number: &mut [u8],
    ) -> aead::Result<()> {
        use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
        use chacha20::ChaCha20;

        // NOTE(block_counter): From section 2.3 in RFC8439: The block counter is
        // interpreted as a little endian integer.
        let block_counter = u32::from_le_bytes(ciphertext[..4].try_into().unwrap());

        let iv = &ciphertext[4..];
        let mut cipher = <ChaCha20 as KeyIvInit>::new(&self.mask_key, iv.try_into().unwrap());
        cipher.seek(block_counter as u64 * 64); // Block size for Chacha is 64 bytes.
        cipher.apply_keystream(record_number);

        Ok(())
    }
}

// /// Preliminary async support for hashing.
// pub mod async_digest {
//     use digest::{Digest, OutputSizeUser};

//     // To allow normal sync `Digest` methods to be used.
//     impl<T> DtlsTranscript for T
//     where
//         T: Digest,
//     {
//         async fn update(&mut self, data: impl AsRef<[u8]>) {
//             <Self as Digest>::update(self, data)
//         }

//         fn intermediate_result(&self) -> digest::Output<Self> {
//             <Self as Digest>::
//         }
//     }

//     pub trait DtlsTranscript: OutputSizeUser {
//         /// Process data, updating the internal state.
//         async fn update(&mut self, data: impl AsRef<[u8]>);

//         /// Retrieve result and consume hasher instance.
//         fn intermediate_result(&self) -> digest::Output<Self>;

//         // /// Write result into provided array and consume the hasher instance.
//         // fn finalize_into(self, out: &mut digest::Output<Self>);
//     }
// }

// /// Preliminary async support for encryption.
// pub mod async_aead {
//     use aead::AeadCore;
//     use chacha20poly1305::aead::{self, AeadMutInPlace, Buffer, Nonce, Tag};

//     // To allow normal sync `AeadMutInPlace` methods to be used.
//     impl<T> AsyncAeadMutInPlace for T
//     where
//         T: AeadMutInPlace,
//     {
//         async fn encrypt_in_place_detached(
//             &mut self,
//             nonce: &Nonce<Self>,
//             associated_data: &[u8],
//             buffer: &mut [u8],
//         ) -> aead::Result<Tag<Self>> {
//             <Self as AeadMutInPlace>::encrypt_in_place_detached(
//                 self,
//                 nonce,
//                 associated_data,
//                 buffer,
//             )
//         }

//         async fn decrypt_in_place_detached(
//             &mut self,
//             nonce: &Nonce<Self>,
//             associated_data: &[u8],
//             buffer: &mut [u8],
//             tag: &Tag<Self>,
//         ) -> aead::Result<()> {
//             <Self as AeadMutInPlace>::decrypt_in_place_detached(
//                 self,
//                 nonce,
//                 associated_data,
//                 buffer,
//                 tag,
//             )
//         }
//     }

//     /// Implement the `decrypt_in_place` method on [`AeadInPlace`] and
//     /// [`AeadMutInPlace]`, using a macro to gloss over the `&self` vs `&mut self`.
//     ///
//     /// Assumes a postfix authentication tag. AEAD ciphers which do not use a
//     /// postfix authentication tag will need to define their own implementation.
//     macro_rules! impl_decrypt_in_place {
//         ($aead:expr, $nonce:expr, $aad:expr, $buffer:expr) => {{
//             use digest::typenum::Unsigned;

//             if $buffer.len() < Self::TagSize::to_usize() {
//                 return Err(aead::Error);
//             }

//             let tag_pos = $buffer.len() - Self::TagSize::to_usize();
//             let (msg, tag) = $buffer.as_mut().split_at_mut(tag_pos);
//             <Self as AsyncAeadMutInPlace>::decrypt_in_place_detached(
//                 $aead,
//                 $nonce,
//                 $aad,
//                 msg,
//                 Tag::<Self>::from_slice(tag),
//             )
//             .await?;
//             $buffer.truncate(tag_pos);
//             Ok(())
//         }};
//     }

//     /// In-place stateful AEAD trait.
//     ///
//     /// This trait is both object safe and has no dependencies on `alloc` or `std`.
//     pub trait AsyncAeadMutInPlace: AeadCore {
//         /// Encrypt the given buffer containing a plaintext message in-place.
//         ///
//         /// The buffer must have sufficient capacity to store the ciphertext
//         /// message, which will always be larger than the original plaintext.
//         /// The exact size needed is cipher-dependent, but generally includes
//         /// the size of an authentication tag.
//         ///
//         /// Returns an error if the buffer has insufficient capacity to store the
//         /// resulting ciphertext message.
//         async fn encrypt_in_place(
//             &mut self,
//             nonce: &Nonce<Self>,
//             associated_data: &[u8],
//             buffer: &mut impl Buffer,
//         ) -> aead::Result<()> {
//             let tag = <Self as AsyncAeadMutInPlace>::encrypt_in_place_detached(
//                 self,
//                 nonce,
//                 associated_data,
//                 buffer.as_mut(),
//             )
//             .await?;
//             buffer.extend_from_slice(tag.as_slice())?;
//             Ok(())
//         }

//         /// Encrypt the data in-place, returning the authentication tag
//         async fn encrypt_in_place_detached(
//             &mut self,
//             nonce: &Nonce<Self>,
//             associated_data: &[u8],
//             buffer: &mut [u8],
//         ) -> aead::Result<Tag<Self>>;

//         /// Decrypt the message in-place, returning an error in the event the
//         /// provided authentication tag does not match the given ciphertext.
//         ///
//         /// The buffer will be truncated to the length of the original plaintext
//         /// message upon success.
//         async fn decrypt_in_place(
//             &mut self,
//             nonce: &Nonce<Self>,
//             associated_data: &[u8],
//             buffer: &mut impl Buffer,
//         ) -> aead::Result<()> {
//             impl_decrypt_in_place!(self, nonce, associated_data, buffer)
//         }

//         /// Decrypt the data in-place, returning an error in the event the provided
//         /// authentication tag does not match the given ciphertext (i.e. ciphertext
//         /// is modified/unauthentic)
//         async fn decrypt_in_place_detached(
//             &mut self,
//             nonce: &Nonce<Self>,
//             associated_data: &[u8],
//             buffer: &mut [u8],
//             tag: &Tag<Self>,
//         ) -> aead::Result<()>;
//     }
// }
