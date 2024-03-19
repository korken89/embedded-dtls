use core::marker::PhantomData;

use crate::{
    buffer::{AllocSliceHandle, AllocU16Handle, AllocU24Handle, DTlsBuffer},
    cipher_suites::TlsCipherSuite,
    record::LEGACY_DTLS_VERSION,
};
use digest::OutputSizeUser;
use extensions::{ClientExtensions, PskKeyExchangeModes};
use heapless::Vec;
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey};

use self::extensions::{KeyShareEntry, NamedGroup, OfferedPsks, PskIdentity, PskKeyExchangeMode};

pub mod extensions;

/// The random bytes in a handshake.
pub type Random = [u8; 32];

pub struct ClientConfig<'a> {
    /// List of PSK identities.
    psk_identities: &'a [PskIdentity<'a>],
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ClientHandshake<'a, CipherSuite> {
    ClientHello(ClientHello<'a, CipherSuite>),
    Finished(Finished<64>), // TODO: 64 should not be hardcoded.
}

impl<'a, CipherSuite: TlsCipherSuite> ClientHandshake<'a, CipherSuite> {
    pub fn encode(&self, buf: &mut impl DTlsBuffer) -> Result<Option<AllocSliceHandle>, ()> {
        // TODO: Encode client handshake.
        let handshake_header_allocations = HandshakeHeader {
            msg_type: self.handshake_type(),
        }
        .encode(buf)?;

        // TODO: How to support fragmentation so we can ship this over e.g. IEEE802.15.4 radio that
        // only has payload of 60-100 bytes?
        // For now just assume everything goes into one `DTlsHandshake`.

        let content_start = buf.len();

        let binders = match self {
            ClientHandshake::ClientHello(hello) => Some(hello.encode(buf)?),
            ClientHandshake::Finished(finnished) => {
                finnished.encode(buf)?;
                None
            }
        };

        let content_length = (content_start - buf.len()) as u32;

        handshake_header_allocations
            .length
            .set(buf, content_length.into());
        handshake_header_allocations.message_seq.set(buf, 1);
        handshake_header_allocations
            .fragment_offset
            .set(buf, 0.into());
        handshake_header_allocations
            .fragment_length
            .set(buf, content_length.into());

        // TODO: Is there more to do here?

        Ok(binders)
    }

    fn handshake_type(&self) -> HandshakeType {
        match self {
            ClientHandshake::ClientHello(_) => HandshakeType::ClientHello,
            ClientHandshake::Finished(_) => HandshakeType::Finished,
        }
    }

    // /// Perform DTLS 1.3 handshake.
    // pub async fn perform<Socket, Rng>(
    //     &mut self,
    //     buffer: &mut impl DTlsBuffer,
    //     socket: &Socket,
    //     rng: &mut Rng,
    // ) -> Result<(), DTlsError<Socket>>
    // where
    //     Socket: UdpSocket,
    //     Rng: RngCore + CryptoRng,
    // {
    //     // TODO: Send client hello
    //     let client_hello = ClientHello::new(rng);

    //     // TODO: Receive server hello

    //     // TODO: Calculate cryptographic secrets (do verification?)

    //     // TODO: Should return the cryptographic stuff for later use as application data.
    //     todo!()
    // }
}

// --------------------------------------------------------------------------
//
// TODO: This below should be its own files most likely. This will get large.
//
// --------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
#[allow(unused)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    RequestConnectionID = 9,
    NewConnectionID = 10,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
}

/// The handshake header, defined in RFC 9147 section 5.2.
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct HandshakeHeader {
    msg_type: HandshakeType,
    // length: U24,
    // message_seq: u16,
    // fragment_offset: U24,
    // fragment_length: U24,
    // body: HandshakeType,
}

/// The to-be-filled locations in the handshake header, defined in RFC 9147 section 5.2.
pub struct HandshakeHeaderAllocations {
    pub length: AllocU24Handle,
    pub message_seq: AllocU16Handle,
    pub fragment_offset: AllocU24Handle,
    pub fragment_length: AllocU24Handle,
}

impl HandshakeHeader {
    /// Encode the handshake header. The return contains allocated space for
    /// `(length, fragment_length)`.
    pub fn encode(&self, buf: &mut impl DTlsBuffer) -> Result<HandshakeHeaderAllocations, ()> {
        buf.push_u8(self.msg_type as u8)?;

        let length = buf.alloc_u24()?;
        let message_seq = buf.alloc_u16()?;
        let fragment_offset = buf.alloc_u24()?;
        let fragment_length = buf.alloc_u24()?;

        Ok(HandshakeHeaderAllocations {
            length,
            message_seq,
            fragment_offset,
            fragment_length,
        })
    }
}

/// ClientHello payload in an DTlsHandshake.
pub struct ClientHello<'a, CipherSuite> {
    random: Random,
    secret: EphemeralSecret,
    config: &'a ClientConfig<'a>,
    _c: PhantomData<CipherSuite>,
}

impl<'a, CipherSuite> core::fmt::Debug for ClientHello<'a, CipherSuite> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ClientHello {{ random: {:02x?}, secret: <REDACTED> }}",
            &self.random,
        )
    }
}

impl<'a, CipherSuite: TlsCipherSuite> ClientHello<'a, CipherSuite> {
    pub fn new<Rng>(config: &'a ClientConfig, rng: &mut Rng) -> Self
    where
        Rng: RngCore + CryptoRng,
    {
        let mut random = [0; 32];
        rng.fill_bytes(&mut random);

        let key = EphemeralSecret::random_from_rng(rng);

        Self {
            random,
            secret: key,
            config,
            _c: PhantomData,
        }
    }

    /// Encode a client hello payload in a Handshake. RFC 9147 section 5.3.
    ///
    /// Returns the allocated position for binders.
    pub fn encode(&self, buf: &mut impl DTlsBuffer) -> Result<AllocSliceHandle, ()> {
        // struct {
        //     ProtocolVersion legacy_version = { 254,253 }; // DTLSv1.2
        //     Random random;
        //     opaque legacy_session_id<0..32>;
        //     opaque legacy_cookie<0..2^8-1>;                  // DTLS
        //     CipherSuite cipher_suites<2..2^16-2>;
        //     opaque legacy_compression_methods<1..2^8-1>;
        //     Extension extensions<8..2^16-1>;
        // } ClientHello;

        // Legacy version.
        buf.extend_from_slice(&LEGACY_DTLS_VERSION)?;

        // Random.
        buf.extend_from_slice(&self.random)?;

        // Legacy Session ID.
        buf.push_u8(0)?;

        // Legacy cookie.
        buf.push_u8(0)?;

        // Cipher suites, we only support the one selected by the trait.
        buf.push_u16_be(2)?;
        buf.push_u16_be(CipherSuite::CODE_POINT)?;

        // Compression methods, select none.
        buf.push_u8(1)?;
        buf.push_u8(0)?;

        // List of extensions.
        let content_start = buf.len();
        let extensions_length_allocation = buf.alloc_u16()?;

        ClientExtensions::PskKeyExchangeModes(PskKeyExchangeModes {
            ke_modes: Vec::from_slice(&[PskKeyExchangeMode::PskDheKe]).unwrap(),
        })
        .encode(buf)?;

        ClientExtensions::KeyShare(KeyShareEntry {
            group: NamedGroup::X25519,
            opaque: PublicKey::from(&self.secret).as_bytes(),
        })
        .encode(buf)?;

        // IMPORTANT: Pre-shared key extension must come last.
        let binders_allocation = ClientExtensions::PreSharedKey(OfferedPsks {
            identities: self.config.psk_identities,
            hash_size: <CipherSuite::Hash as OutputSizeUser>::output_size(),
        })
        .encode(buf)?
        // TODO: better error?
        .ok_or(())?;

        // Fill in the length of extensions.
        let content_length = (content_start - buf.len()) as u16;
        extensions_length_allocation.set(buf, content_length);

        Ok(binders_allocation)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for ClientHello {
    fn format(&self, f: defmt::Formatter) {
        // format the bitfields of the register as struct fields
        defmt::write!(
            f,
            "ClientHello {{ random: {:02x}, secret: <REDACTED> }}",
            &self.random,
        )
    }
}

/// Finished payload in an DTlsHandshake.
#[derive(Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Finished<const HASH_LEN: usize> {
    pub verify: [u8; HASH_LEN],
    // pub hash: Option<[u8; 1]>,
}
impl<const HASH_LEN: usize> Finished<HASH_LEN> {
    /// Encode a Finished payload in an Handshake.
    pub fn encode(&self, buf: &mut impl DTlsBuffer) -> Result<(), ()> {
        buf.extend_from_slice(&self.verify)
    }
}
