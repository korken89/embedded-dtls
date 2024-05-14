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

use crate::buffer::{AllocSliceHandle, EncodingBuffer, ParseBuffer};
use num_enum::TryFromPrimitive;

/// Version numbers.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DtlsVersions {
    /// DTLS v1.0
    V1_0 = 0xfeff,
    /// DTLS v1.2
    V1_2 = 0xfefd,
    /// DTLS v1.3
    V1_3 = 0xfefc,
}

/// Helper to parse extensions.
pub struct ParseExtension<'a> {
    pub extension_type: ExtensionType,
    pub extension_data: &'a [u8],
}

impl<'a> ParseExtension<'a> {
    /// Parse an extension.
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<Self> {
        let extension_type = ExtensionType::try_from(buf.pop_u8()?).ok()?;
        let data_len = buf.pop_u16_be()?;
        let extension_data = buf.pop_slice(data_len as usize)?;

        Some(Self {
            extension_type,
            extension_data,
        })
    }
}

#[derive(Clone, Default, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ClientExtensions<'a> {
    pub psk_key_exchange_modes: Option<PskKeyExchangeModes>,
    pub key_share: Option<KeyShareEntry<'a>>,
    pub supported_versions: Option<ClientSupportedVersions>,
    pub pre_shared_key: Option<OfferedPsks<'a>>,
}

impl<'a> ClientExtensions<'a> {
    /// Encode client extensions.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<Option<AllocSliceHandle>, ()> {
        if let Some(supported_version) = &self.supported_versions {
            buf.push_u8(ExtensionType::SupportedVersions as u8)?;
            encode_extension(buf, |buf| supported_version.encode(buf))??;
        }
        if let Some(pkem) = &self.psk_key_exchange_modes {
            buf.push_u8(ExtensionType::PskKeyExchangeModes as u8)?;
            encode_extension(buf, |buf| pkem.encode(buf))??;
        }
        if let Some(key_share) = &self.key_share {
            buf.push_u8(ExtensionType::KeyShare as u8)?;
            encode_extension(buf, |buf| key_share.encode(buf))??;
        }

        if let Some(psk) = &self.pre_shared_key {
            buf.push_u8(ExtensionType::PreSharedKey as u8)?;
            Ok(Some(encode_extension(buf, |buf| psk.encode(buf))??))
        } else {
            Ok(None)
        }
    }

    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<(Self, Option<usize>)> {
        let mut ret = ClientExtensions::default();
        let mut binders_start = None;

        let extensions_length = buf.pop_u16_be()?;
        let mut extensions = ParseBuffer::new(buf.pop_slice(extensions_length as usize)?);

        while let Some(extension) = ParseExtension::parse(&mut extensions) {
            if ret.pre_shared_key.is_some() {
                l0g::error!("Got more extensions after PreSharedKey!");
                return None;
            }

            match extension.extension_type {
                ExtensionType::SupportedVersions => {
                    let Some(v) = ClientSupportedVersions::parse(&mut ParseBuffer::new(
                        extension.extension_data,
                    )) else {
                        l0g::error!("Failed to parse supported version");
                        return None;
                    };

                    if ret.supported_versions.is_some() {
                        l0g::error!("Supported version extension already parsed!");
                        return None;
                    }

                    ret.supported_versions = Some(v);
                }
                ExtensionType::PskKeyExchangeModes => {
                    let Some(v) =
                        PskKeyExchangeModes::parse(&mut ParseBuffer::new(extension.extension_data))
                    else {
                        l0g::error!("Failed to parse PskKeyExchange");
                        return None;
                    };

                    if ret.psk_key_exchange_modes.is_some() {
                        l0g::error!("PskKeyExchangeModes extension already parsed!");
                        return None;
                    }

                    ret.psk_key_exchange_modes = Some(v);
                }
                ExtensionType::KeyShare => {
                    let Some(v) =
                        KeyShareEntry::parse(&mut ParseBuffer::new(extension.extension_data))
                    else {
                        l0g::error!("Failed to parse PskKeyExchange");
                        return None;
                    };

                    if ret.key_share.is_some() {
                        l0g::error!("Keyshare extension already parsed!");
                        return None;
                    }

                    ret.key_share = Some(v);
                }
                ExtensionType::PreSharedKey => {
                    let Some((psk, binders_start_pos)) =
                        OfferedPreSharedKey::parse(&mut ParseBuffer::new(extension.extension_data))
                    else {
                        l0g::error!("Failed to parse PreSharedKey");
                        return None;
                    };

                    if ret.pre_shared_key.is_some() {
                        l0g::error!("PreSharedKey extension already parsed!");
                        return None;
                    }

                    binders_start = Some(binders_start_pos);
                    ret.pre_shared_key = Some(psk);
                }
                _ => {
                    l0g::error!("Got more extensions than what's supported!");
                    return None;
                }
            }
        }

        Some((ret, binders_start))
    }
}

/// Helper to parse server extensions.
#[derive(Debug, Default)]
pub struct NewServerExtensions<'a> {
    pub selected_supported_version: Option<ServerSupportedVersion>,
    pub key_share: Option<KeyShareEntry<'a>>,
    pub pre_shared_key: Option<SelectedPsk>,
}

impl<'a> NewServerExtensions<'a> {
    /// Encode server extensions.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), ()> {
        if let Some(supported_version) = &self.selected_supported_version {
            buf.push_u8(ExtensionType::SupportedVersions as u8)?;
            encode_extension(buf, |buf| supported_version.encode(buf))??;
        }
        if let Some(key_share) = &self.key_share {
            buf.push_u8(ExtensionType::KeyShare as u8)?;
            encode_extension(buf, |buf| key_share.encode(buf))??;
        }

        if let Some(psk) = &self.pre_shared_key {
            buf.push_u8(ExtensionType::PreSharedKey as u8)?;
            encode_extension(buf, |buf| psk.encode(buf))??;
        }

        Ok(())
    }

    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<Self> {
        let mut ret = NewServerExtensions::default();

        let extensions_length = buf.pop_u16_be()?;
        let mut extensions = ParseBuffer::new(buf.pop_slice(extensions_length as usize)?);

        while let Some(extension) = ParseExtension::parse(&mut extensions) {
            match extension.extension_type {
                ExtensionType::KeyShare => {
                    let Some(v) =
                        KeyShareEntry::parse(&mut ParseBuffer::new(extension.extension_data))
                    else {
                        l0g::error!("Failed to parse PskKeyExchange");
                        return None;
                    };

                    if ret.key_share.is_some() {
                        l0g::error!("Keyshare extension already parsed!");
                        return None;
                    }

                    ret.key_share = Some(v);
                }
                ExtensionType::SupportedVersions => {
                    let Some(v) = ServerSupportedVersion::parse(&mut ParseBuffer::new(
                        extension.extension_data,
                    )) else {
                        l0g::error!("Failed to parse ServerSelectedVersion");
                        return None;
                    };

                    if ret.selected_supported_version.is_some() {
                        l0g::error!("Keyshare extension already parsed!");
                        return None;
                    }

                    ret.selected_supported_version = Some(v);
                }
                ExtensionType::PreSharedKey => {
                    let Some(v) =
                        SelectedPsk::parse(&mut ParseBuffer::new(extension.extension_data))
                    else {
                        l0g::error!("Failed to parse SelectedPsk");
                        return None;
                    };

                    if ret.pre_shared_key.is_some() {
                        l0g::error!("Keyshare extension already parsed!");
                        return None;
                    }

                    ret.pre_shared_key = Some(v);
                }
                _ => {
                    l0g::error!("Got more extensions than what's supported!");
                    return None;
                }
            }
        }

        Some(ret)
    }
}

fn encode_extension<R, F: FnOnce(&mut EncodingBuffer) -> R>(
    buf: &mut EncodingBuffer,
    f: F,
) -> Result<R, ()> {
    let extension_length_allocation = buf.alloc_u16()?;
    let content_start = buf.len();

    let r = f(buf);

    // Fill in the length of this extension.
    let content_length = (buf.len() - content_start) as u16;
    extension_length_allocation.set(buf, content_length);

    Ok(r)
}

#[derive(Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ServerExtensions<'a> {
    KeyShare(KeyShareEntry<'a>),
    SelectedSupportedVersion(ServerSupportedVersion),
    PreSharedKey(SelectedPsk),
}

impl<'a> ServerExtensions<'a> {
    /// Encode a server extension.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), ()> {
        buf.push_u8(self.extension_type() as u8)?;

        let extension_length_allocation = buf.alloc_u16()?;
        let content_start = buf.len();

        match self {
            ServerExtensions::KeyShare(key_share) => key_share.encode(buf)?,
            ServerExtensions::SelectedSupportedVersion(versions) => versions.encode(buf)?,
            ServerExtensions::PreSharedKey(offered) => offered.encode(buf)?,
        };

        // Fill in the length of this extension.
        let content_length = (buf.len() - content_start) as u16;
        extension_length_allocation.set(buf, content_length);

        Ok(())
    }

    fn extension_type(&self) -> ExtensionType {
        match self {
            ServerExtensions::KeyShare(_) => ExtensionType::KeyShare,
            ServerExtensions::SelectedSupportedVersion(_) => ExtensionType::SupportedVersions,
            ServerExtensions::PreSharedKey(_) => ExtensionType::PreSharedKey,
        }
    }
}

/// Helper to parse server extensions.
#[derive(Debug, Default)]
pub struct ParseServerExtensions<'a> {
    pub selected_supported_version: Option<ServerSupportedVersion>,
    pub key_share: Option<KeyShareEntry<'a>>,
    pub pre_shared_key: Option<SelectedPsk>,
}

impl<'a> ParseServerExtensions<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<Self> {
        let mut ret = ParseServerExtensions::default();

        let extensions_length = buf.pop_u16_be()?;
        let mut extensions = ParseBuffer::new(buf.pop_slice(extensions_length as usize)?);

        while let Some(extension) = ParseExtension::parse(&mut extensions) {
            match extension.extension_type {
                ExtensionType::KeyShare => {
                    let Some(v) =
                        KeyShareEntry::parse(&mut ParseBuffer::new(extension.extension_data))
                    else {
                        l0g::error!("Failed to parse PskKeyExchange");
                        return None;
                    };

                    if ret.key_share.is_some() {
                        l0g::error!("Keyshare extension already parsed!");
                        return None;
                    }

                    ret.key_share = Some(v);
                }
                ExtensionType::SupportedVersions => {
                    let Some(v) = ServerSupportedVersion::parse(&mut ParseBuffer::new(
                        extension.extension_data,
                    )) else {
                        l0g::error!("Failed to parse ServerSelectedVersion");
                        return None;
                    };

                    if ret.selected_supported_version.is_some() {
                        l0g::error!("Keyshare extension already parsed!");
                        return None;
                    }

                    ret.selected_supported_version = Some(v);
                }
                ExtensionType::PreSharedKey => {
                    let Some(v) =
                        SelectedPsk::parse(&mut ParseBuffer::new(extension.extension_data))
                    else {
                        l0g::error!("Failed to parse SelectedPsk");
                        return None;
                    };

                    if ret.pre_shared_key.is_some() {
                        l0g::error!("Keyshare extension already parsed!");
                        return None;
                    }

                    ret.pre_shared_key = Some(v);
                }
                _ => {
                    l0g::error!("Got more extensions than what's supported!");
                    return None;
                }
            }
        }

        Some(ret)
    }
}

/// Pre-Shared Key Exchange Modes.
#[derive(Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PskKeyExchangeModes {
    pub ke_modes: PskKeyExchangeMode,
}

impl PskKeyExchangeModes {
    /// Encode a `psk_key_exchange_modes` extension.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), ()> {
        buf.push_u8(1 as u8)?;
        buf.push_u8(self.ke_modes as u8)?;

        Ok(())
    }

    // Parse a `psk_key_exchange_modes` extension.
    pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
        if buf.pop_u8()? != 1 {
            return None;
        }

        let ke_modes = buf.pop_u8()?.try_into().ok()?;

        Some(PskKeyExchangeModes { ke_modes })
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
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), ()> {
        buf.push_u16_be(2 + 2 + self.opaque.len() as u16)?;

        // one key-share
        buf.push_u16_be(self.group as u16)?;
        buf.push_u16_be(self.opaque.len() as u16)?;
        buf.extend_from_slice(self.opaque)
    }

    /// Parse a keyshare entry.
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<Self> {
        let size = buf.pop_u16_be()?;
        let group = NamedGroup::try_from(buf.pop_u16_be()?).ok()?;
        let key_length = buf.pop_u16_be()?;

        // TODO: We only support one key for now.
        // This can be a list of supported keyshares in the future.
        let expected_size = key_length + 2 + 2;
        if expected_size != size {
            l0g::error!("The keyshare size does not match only one key, expected {size} got {expected_size}");
            return None;
        }

        let key = buf.pop_slice(key_length as usize)?;

        Some(KeyShareEntry { group, opaque: key })
    }
}

/// The supported_versions payload.
#[derive(Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ClientSupportedVersions {
    pub version: DtlsVersions,
}

impl ClientSupportedVersions {
    /// Encode a `supported_versions` extension. We only support DTLS 1.3.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), ()> {
        buf.push_u8(2)?;

        // DTLS 1.3, RFC 9147, section 5.3
        buf.push_u16_be(self.version as u16)
    }
    pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
        let size = buf.pop_u8()?;

        if size != 2 {
            // Only one version for now
            return None;
        }

        let version = buf.pop_u16_be()?.try_into().ok()?;

        Some(ClientSupportedVersions { version })
    }
}

/// The supported_versions payload, the one selected by the server.
#[derive(Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ServerSupportedVersion {
    pub version: DtlsVersions,
}

impl ServerSupportedVersion {
    /// Encode a `supported_versions` extension. We only support DTLS 1.3.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), ()> {
        // DTLS 1.3, RFC 8446, section 4.2.1 (pointed to from RFC 9147, section 5.4)
        buf.push_u16_be(self.version as u16)
    }

    /// Parse a selected supported version.
    pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
        Some(Self {
            version: DtlsVersions::try_from(buf.pop_u16_be()?).ok()?,
        })
    }
}

/// The pre-shared keys the client can offer to use.
#[derive(Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OfferedPsks<'a> {
    /// List of identities that can be used. Ticket age is set to 0.
    pub identities: &'a [Psk<'a>],

    // pub ser: &'a [Psk<'a>],
    // pub deser: PskIter<'a>,
    /// Size of the binder hash.
    pub hash_size: usize,
}

impl<'a> OfferedPsks<'a> {
    /// Encode the offered pre-shared keys. Returns a handle to write the binders.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<AllocSliceHandle, ()> {
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

        // Binders length.
        buf.push_u16_be(binders_len as u16)?;
        buf.alloc_slice(binders_len)
    }
}

/// An offered pre-shared key that can be parsed.
#[derive(Debug)]
pub struct OfferedPreSharedKey<'a> {
    pub identity: &'a [u8],
    pub binder: &'a [u8],
}

impl<'a> OfferedPreSharedKey<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<(Self, usize)> {
        // Identity part
        let identity_size = buf.pop_u16_be()?;
        let identity_length = buf.pop_u16_be()?;

        // TODO: For now we only support one identity.
        let expected_identity_size = identity_length + 4 + 2; // +4 for the ticket, +2 for size
        if identity_size != expected_identity_size {
            l0g::error!(
                "Identity size failure, expected {expected_identity_size}, got {identity_size}"
            );

            return None;
        }

        let identity = buf.pop_slice(identity_length as usize)?;
        let _ticket_age = buf.pop_u32_be()?;

        // Binders part
        let binders_size = buf.pop_u16_be()?;
        let binders_start_pos = buf.current_pos_ptr();
        let binder_length = buf.pop_u8()?;

        let expected_binders_size = binder_length as u16 + 1;
        if binders_size != expected_binders_size {
            l0g::error!(
                "Binders size failure, expected {expected_binders_size}, got {binders_size}"
            );

            return None;
        }

        let binder = buf.pop_slice(binder_length as usize)?;

        Some((
            OfferedPreSharedKey {
                identity: identity,
                binder: binder,
            },
            binders_start_pos,
        ))
    }
}

/// Pre-shared key entry.
#[derive(Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Psk<'a> {
    /// A label for the key. For instance, a ticket (as defined in Appendix B.3.4) or a label
    /// for a pre-shared key established externally.
    pub identity: &'a [u8],
    /// The pre-shared key.
    pub key: &'a [u8],
}

impl<'a> Psk<'a> {
    /// Encode a pre-shared key identity into the buffer.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), ()> {
        // Encode length.
        buf.push_u16_be(self.identity.len() as u16)?;

        // Encode identity.
        buf.extend_from_slice(self.identity)?;

        // Encode ticket age.
        buf.push_u32_be(0)
    }
}

/// The pre-shared keys the server has selected.
#[derive(Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SelectedPsk {
    /// List of identities that can be used. Ticket age is set to 0.
    pub selected_identity: u16,
}

impl SelectedPsk {
    /// Encode the selected pre-shared key.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), ()> {
        buf.push_u16_be(self.selected_identity)
    }

    /// Parse a selected pre-shared key identity.
    pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
        Some(Self {
            selected_identity: buf.pop_u16_be()?,
        })
    }
}

/// Heartbeat mode.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum HeartbeatMode {
    PeerAllowedToSend = 1,
    PeerNotAllowedToSend = 2,
}

/// Pre-Shared Key Exchange Modes (RFC 8446, 4.2.9)
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq, TryFromPrimitive)]
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
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq, TryFromPrimitive)]
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

/// TLS ExtensionType Values registry.
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq, TryFromPrimitive)]
#[repr(u8)]
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
