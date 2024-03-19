//! Extensions we probably want:
//!
//! * psk_key_exchange_modes
//! * key_share
//! * heartbeat
//! * pre_shared_key
//!
//! embedded-tls has these as well:
//!
//! * signature_algorithms
//! * supported_groups
//! * server_name
//! * supported_versions, not needed it turns out
//!
//! All this is defined in RFC 8446 (TLS 1.3) at Page 37.

use heapless::Vec;

use crate::buffer::{AllocSliceHandle, DTlsBuffer};

#[derive(Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ClientExtensions<'a> {
    PskKeyExchangeModes(PskKeyExchangeModes),
    KeyShare(KeyShareEntry<'a>),
    PreSharedKey(OfferedPsks<'a>),
    // ServerName { // Not sure we need this.
    //     server_name: &'a str,
    // },
    // Heartbeat { // Not sure we need this.
    //     mode: HeartbeatMode,
    // },
    // SupportedGroups {
    //     supported_groups: Vec<NamedGroup, 16>,
    // },
    // SupportedVersions {
    //     versions: ProtocolVersions,
    // },
    // SignatureAlgorithms {
    //     supported_signature_algorithms: Vec<SignatureScheme, 16>,
    // },
    // SignatureAlgorithmsCert {
    //     supported_signature_algorithms: Vec<SignatureScheme, 16>,
    // },
    // MaxFragmentLength(MaxFragmentLength),
}

impl<'a> ClientExtensions<'a> {
    /// Encode a client extension.
    /// Encode the offered pre-shared keys. Returns a handle to write the binders if needed.
    pub fn encode(&self, buf: &mut impl DTlsBuffer) -> Result<Option<AllocSliceHandle>, ()> {
        buf.push_u8(self.extension_type() as u8)?;

        let content_start = buf.len();
        let extension_length_allocation = buf.alloc_u16()?;

        let r = match self {
            ClientExtensions::PskKeyExchangeModes(psk_exchange) => {
                psk_exchange.encode(buf).map(|_| None)
            }
            ClientExtensions::KeyShare(key_share) => key_share.encode(buf).map(|_| None),
            ClientExtensions::PreSharedKey(offered) => offered.encode(buf).map(|alloc| Some(alloc)),
        };

        // Fill in the length of this extension.
        let content_length = (content_start - buf.len()) as u16;
        extension_length_allocation.set(buf, content_length);

        r
    }

    fn extension_type(&self) -> ExtensionType {
        match self {
            ClientExtensions::PskKeyExchangeModes { .. } => ExtensionType::PskKeyExchangeModes,
            ClientExtensions::KeyShare(_) => ExtensionType::KeyShare,
            ClientExtensions::PreSharedKey(_) => ExtensionType::PreSharedKey,
        }
    }
}

/// Pre-Shared Key Exchange Modes.
#[derive(Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PskKeyExchangeModes {
    pub ke_modes: Vec<PskKeyExchangeMode, 4>,
}

impl PskKeyExchangeModes {
    /// Encode a `psk_key_exchange_modes` extension.
    pub fn encode(&self, buf: &mut impl DTlsBuffer) -> Result<(), ()> {
        buf.push_u8(self.ke_modes.len() as u8)?;
        for mode in &self.ke_modes {
            buf.push_u8(*mode as u8)?;
        }

        Ok(())
    }
}

/// The `key_share` extension contains the endpoint’s cryptographic parameters.
#[derive(Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct KeyShareEntry<'a> {
    pub group: NamedGroup,
    pub opaque: &'a [u8],
}

impl<'a> KeyShareEntry<'a> {
    /// Encode a `key_share` extension.
    pub fn encode(&self, buf: &mut impl DTlsBuffer) -> Result<(), ()> {
        buf.push_u16_be(2 + 2 + self.opaque.len() as u16)?;

        // one key-share
        buf.push_u16_be(self.group as u16)?;
        buf.push_u16_be(self.opaque.len() as u16)?;
        buf.extend_from_slice(self.opaque)
    }
}

/// The pre-shared keys the client can offer to use.
#[derive(Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OfferedPsks<'a> {
    /// List of identities that can be used. Ticket age is set to 0.
    pub identities: &'a [PskIdentity<'a>],
    /// Size of the binder hash.
    pub hash_size: usize,
}

impl<'a> OfferedPsks<'a> {
    /// Encode the offered pre-shared keys. Returns a handle to write the binders.
    pub fn encode(&self, buf: &mut impl DTlsBuffer) -> Result<AllocSliceHandle, ()> {
        let ident_len = self
            .identities
            .iter()
            .map(|ident| ident.identity.len() + 4 + 2)
            .sum::<usize>();

        // Length.
        buf.push_u16_be(ident_len as u16)?;

        // Each identity.
        for identity in self.identities {
            identity.encode(buf)?;
        }

        // Allocate space for binders and return it for future use.
        let binders_len = (1 + self.hash_size) * self.identities.len();
        buf.alloc_slice(binders_len)
    }
}

/// Pre-shared key identity payload.
#[derive(Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PskIdentity<'a> {
    /// A label for a key. For instance, a ticket (as defined in Appendix B.3.4) or a label
    /// for a pre-shared key established externally.
    pub identity: &'a [u8],
}

impl<'a> PskIdentity<'a> {
    /// Encode a pre-shared key identity into the buffer.
    pub fn encode(&self, buf: &mut impl DTlsBuffer) -> Result<(), ()> {
        // Encode length.
        buf.push_u16_be(self.identity.len() as u16)?;

        // Encode identity.
        buf.extend_from_slice(self.identity)?;

        // Encode ticket age.
        buf.push_u32_be(0)
    }
}

/// Heartbeat mode.
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HeartbeatMode {
    PeerAllowedToSend = 1,
    PeerNotAllowedToSend = 2,
}

/// Pre-Shared Key Exchange Modes (RFC 8446, 4.2.9)
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
pub enum PskKeyExchangeMode {
    ///  PSK-only key establishment. In this mode, the server MUST NOT supply a `key_share` value.
    PskKe = 0,
    /// PSK with (EC)DHE key establishment. In this mode, the client and server MUST supply
    /// `key_share` values.
    PskDheKe = 1,
}

/// Named groups which the client supports for key exchange.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
pub enum NamedGroup {
    // Elliptic Curve Groups (ECDHE)
    Secp256r1 = 0x0017,
    Secp384r1 = 0x0018,
    Secp521r1 = 0x0019,
    X25519 = 0x001D, // For now we only support X25519.
    X448 = 0x001E,

    // Finite Field Groups (DHE)
    Ffdhe2048 = 0x0100,
    Ffdhe3072 = 0x0101,
    Ffdhe4096 = 0x0102,
    Ffdhe6144 = 0x0103,
    Ffdhe8192 = 0x0104,
}

impl NamedGroup {
    pub fn of(num: u16) -> Option<NamedGroup> {
        match num {
            0x0017 => Some(Self::Secp256r1),
            0x0018 => Some(Self::Secp384r1),
            0x0019 => Some(Self::Secp521r1),
            0x001D => Some(Self::X25519),
            0x001E => Some(Self::X448),
            0x0100 => Some(Self::Ffdhe2048),
            0x0101 => Some(Self::Ffdhe3072),
            0x0102 => Some(Self::Ffdhe4096),
            0x0103 => Some(Self::Ffdhe6144),
            0x0104 => Some(Self::Ffdhe8192),
            _ => None,
        }
    }
}

/// TLS ExtensionType Values registry.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
pub enum ExtensionType {
    ServerName = 0,
    MaxFragmentLength = 1,
    StatusRequest = 5,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    Heatbeat = 15,
    ApplicationLayerProtocolNegotiation = 16,
    SignedCertificateTimestamp = 18,
    ClientCertificateType = 19,
    ServerCertificateType = 20,
    Padding = 21,
    PreSharedKey = 41,
    EarlyData = 42,
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OidFilters = 48,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,
}
