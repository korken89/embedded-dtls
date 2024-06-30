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

use crate::{
    buffer::{AllocSliceHandle, EncodingBuffer, OutOfMemory, ParseBuffer},
    record::EncodeOrParse,
};
use defmt_or_log::{derive_format_or_debug, error};
use num_enum::TryFromPrimitive;

/// Version numbers.
#[repr(u16)]
#[derive_format_or_debug]
#[derive(Copy, Clone, PartialOrd, PartialEq, TryFromPrimitive)]
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

#[derive_format_or_debug]
#[derive(Clone, Default, PartialEq)]
pub struct ClientExtensions<'a> {
    pub psk_key_exchange_modes: Option<PskKeyExchangeModes>,
    pub key_share: Option<KeyShareEntry<'a>>,
    pub supported_versions: Option<ClientSupportedVersions>,
    pub heartbeat: Option<HeartbeatExtension>,
    pub pre_shared_key: Option<OfferedPsks<'a>>,
}

impl<'a> ClientExtensions<'a> {
    /// Encode client extensions.
    pub fn encode(
        &self,
        buf: &mut EncodingBuffer,
    ) -> Result<Option<AllocSliceHandle>, OutOfMemory> {
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
        if let Some(heartbeat) = &self.heartbeat {
            buf.push_u8(ExtensionType::Heartbeat as u8)?;
            encode_extension(buf, |buf| heartbeat.encode(buf))??;
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
                error!("Got more extensions after PreSharedKey!");
                return None;
            }

            match extension.extension_type {
                ExtensionType::SupportedVersions => {
                    let Some(v) = ClientSupportedVersions::parse(&mut ParseBuffer::new(
                        extension.extension_data,
                    )) else {
                        error!("Failed to parse supported version");
                        return None;
                    };

                    if ret.supported_versions.is_some() {
                        error!("Supported version extension already parsed!");
                        return None;
                    }

                    ret.supported_versions = Some(v);
                }
                ExtensionType::PskKeyExchangeModes => {
                    let Some(v) =
                        PskKeyExchangeModes::parse(&mut ParseBuffer::new(extension.extension_data))
                    else {
                        error!("Failed to parse PskKeyExchange");
                        return None;
                    };

                    if ret.psk_key_exchange_modes.is_some() {
                        error!("PskKeyExchangeModes extension already parsed!");
                        return None;
                    }

                    ret.psk_key_exchange_modes = Some(v);
                }
                ExtensionType::KeyShare => {
                    let Some(v) =
                        KeyShareEntry::parse(&mut ParseBuffer::new(extension.extension_data))
                    else {
                        error!("Failed to parse PskKeyExchange");
                        return None;
                    };

                    if ret.key_share.is_some() {
                        error!("Keyshare extension already parsed!");
                        return None;
                    }

                    ret.key_share = Some(v);
                }
                ExtensionType::Heartbeat => {
                    let Some(v) =
                        HeartbeatExtension::parse(&mut ParseBuffer::new(extension.extension_data))
                    else {
                        error!("Failed to parse HeartbeatExtension");
                        return None;
                    };

                    if ret.heartbeat.is_some() {
                        error!("Heartbeat extension already parsed!");
                        return None;
                    }

                    ret.heartbeat = Some(v);
                }
                ExtensionType::PreSharedKey => {
                    let Some((psk, binders_start_pos)) =
                        OfferedPsks::parse(&mut ParseBuffer::new(extension.extension_data))
                    else {
                        error!("Failed to parse PreSharedKey");
                        return None;
                    };

                    if ret.pre_shared_key.is_some() {
                        error!("PreSharedKey extension already parsed!");
                        return None;
                    }

                    binders_start = Some(binders_start_pos);
                    ret.pre_shared_key = Some(psk);
                }
                _ => {
                    error!("Got more extensions than what's supported!");
                    return None;
                }
            }
        }

        Some((ret, binders_start))
    }
}

/// Helper to parse server extensions.
#[derive_format_or_debug]
#[derive(Default)]
pub struct ServerExtensions<'a> {
    pub selected_supported_version: Option<ServerSupportedVersion>,
    pub key_share: Option<KeyShareEntry<'a>>,
    pub heartbeat: Option<HeartbeatExtension>,
    pub pre_shared_key: Option<SelectedPsk>,
}

impl<'a> ServerExtensions<'a> {
    /// Encode server extensions.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), OutOfMemory> {
        if let Some(supported_version) = &self.selected_supported_version {
            buf.push_u8(ExtensionType::SupportedVersions as u8)?;
            encode_extension(buf, |buf| supported_version.encode(buf))??;
        }
        if let Some(key_share) = &self.key_share {
            buf.push_u8(ExtensionType::KeyShare as u8)?;
            encode_extension(buf, |buf| key_share.encode(buf))??;
        }
        if let Some(heartbeat) = &self.heartbeat {
            buf.push_u8(ExtensionType::Heartbeat as u8)?;
            encode_extension(buf, |buf| heartbeat.encode(buf))??;
        }

        if let Some(psk) = &self.pre_shared_key {
            buf.push_u8(ExtensionType::PreSharedKey as u8)?;
            encode_extension(buf, |buf| psk.encode(buf))??;
        }

        Ok(())
    }

    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<Self> {
        let mut ret = ServerExtensions::default();

        let extensions_length = buf.pop_u16_be()?;
        let mut extensions = ParseBuffer::new(buf.pop_slice(extensions_length as usize)?);

        while let Some(extension) = ParseExtension::parse(&mut extensions) {
            match extension.extension_type {
                ExtensionType::KeyShare => {
                    let Some(v) =
                        KeyShareEntry::parse(&mut ParseBuffer::new(extension.extension_data))
                    else {
                        error!("Failed to parse PskKeyExchange");
                        return None;
                    };

                    if ret.key_share.is_some() {
                        error!("Keyshare extension already parsed!");
                        return None;
                    }

                    ret.key_share = Some(v);
                }
                ExtensionType::SupportedVersions => {
                    let Some(v) = ServerSupportedVersion::parse(&mut ParseBuffer::new(
                        extension.extension_data,
                    )) else {
                        error!("Failed to parse ServerSelectedVersion");
                        return None;
                    };

                    if ret.selected_supported_version.is_some() {
                        error!("Keyshare extension already parsed!");
                        return None;
                    }

                    ret.selected_supported_version = Some(v);
                }
                ExtensionType::Heartbeat => {
                    let Some(v) =
                        HeartbeatExtension::parse(&mut ParseBuffer::new(extension.extension_data))
                    else {
                        error!("Failed to parse HeartbeatExtension");
                        return None;
                    };

                    if ret.heartbeat.is_some() {
                        error!("Heartbeat extension already parsed!");
                        return None;
                    }

                    ret.heartbeat = Some(v);
                }
                ExtensionType::PreSharedKey => {
                    let Some(v) =
                        SelectedPsk::parse(&mut ParseBuffer::new(extension.extension_data))
                    else {
                        error!("Failed to parse SelectedPsk");
                        return None;
                    };

                    if ret.pre_shared_key.is_some() {
                        error!("Keyshare extension already parsed!");
                        return None;
                    }

                    ret.pre_shared_key = Some(v);
                }
                _ => {
                    error!("Got more extensions than what's supported!");
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
) -> Result<R, OutOfMemory> {
    let extension_length_allocation = buf.alloc_u16()?;
    let content_start = buf.len();

    let r = f(buf);

    // Fill in the length of this extension.
    let content_length = (buf.len() - content_start) as u16;
    extension_length_allocation.set(buf, content_length);

    Ok(r)
}

/// Pre-Shared Key Exchange Modes.
#[derive_format_or_debug]
#[derive(Clone, PartialOrd, PartialEq)]
pub struct PskKeyExchangeModes {
    pub ke_modes: PskKeyExchangeMode,
}

impl PskKeyExchangeModes {
    /// Encode a `psk_key_exchange_modes` extension.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), OutOfMemory> {
        buf.push_u8(1)?;
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
#[derive_format_or_debug]
#[derive(Clone, PartialOrd, PartialEq)]
pub struct KeyShareEntry<'a> {
    pub group: NamedGroup,
    pub opaque: &'a [u8],
}

impl<'a> KeyShareEntry<'a> {
    /// Encode a `key_share` extension.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), OutOfMemory> {
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
            error!(
                "The keyshare size does not match only one key, expected {} got {}",
                size, expected_size
            );
            return None;
        }

        let key = buf.pop_slice(key_length as usize)?;

        Some(KeyShareEntry { group, opaque: key })
    }
}

/// The supported_versions payload.
#[derive_format_or_debug]
#[derive(Clone, PartialOrd, PartialEq)]
pub struct ClientSupportedVersions {
    pub version: DtlsVersions,
}

impl ClientSupportedVersions {
    /// Encode a `supported_versions` extension. We only support DTLS 1.3.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), OutOfMemory> {
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
#[derive_format_or_debug]
#[derive(Clone, PartialOrd, PartialEq)]
pub struct ServerSupportedVersion {
    pub version: DtlsVersions,
}

impl ServerSupportedVersion {
    /// Encode a `supported_versions` extension. We only support DTLS 1.3.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), OutOfMemory> {
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
#[derive_format_or_debug]
#[derive(Clone, PartialEq)]
pub struct OfferedPsks<'a> {
    /// List of identities that can be used. Ticket age is set to 0.
    pub identities: EncodeOrParse<&'a [Psk<'a>], PskIter<'a>>,

    /// Size of the binder hash
    pub hash_size: EncodeOrParse<usize, ()>,
}

impl<'a> OfferedPsks<'a> {
    /// Encode the offered pre-shared keys. Returns a handle to write the binders.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<AllocSliceHandle, OutOfMemory> {
        let (EncodeOrParse::Encode(identities), EncodeOrParse::Encode(hash_size)) =
            (&self.identities, self.hash_size)
        else {
            panic!("Internal error, PSK was in decode during encode");
        };

        let ident_len = identities
            .iter()
            .map(|ident| ident.identity.len() + 4 + 2)
            .sum::<usize>();

        // Length.
        buf.push_u16_be(ident_len as u16)?;

        // Each identity.
        for identity in *identities {
            identity.encode(buf)?;
        }

        // Allocate space for binders and return it for future use.
        let binders_len = (1 + hash_size) * identities.len();

        // Binders length.
        buf.push_u16_be(binders_len as u16)?;
        buf.alloc_slice(binders_len)
    }

    /// Parse offered pre-share-keys.
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<(Self, usize)> {
        let (iter, binders_pos) = PskIter::parse(buf)?;

        Some((
            Self {
                identities: EncodeOrParse::Parse(iter),
                hash_size: EncodeOrParse::Parse(()),
            },
            binders_pos,
        ))
    }
}

/// An offered pre-shared key that can be parsed.
#[derive_format_or_debug]
pub struct OfferedPreSharedKey<'a> {
    pub identity: &'a [u8],
    pub binder: &'a [u8],
}

/// This iterator gives an identity and its associated binder for each iteration.
#[derive_format_or_debug]
#[derive(Clone, PartialEq)]
pub struct PskIter<'a> {
    /// The entire identities slice, including size and length headers.
    identities: ParseBuffer<'a>,
    /// The entire binders slice, including size and length headers.
    binders: ParseBuffer<'a>,
}

impl<'a> Iterator for PskIter<'a> {
    type Item = OfferedPreSharedKey<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let identity = {
            let identity_length = self.identities.pop_u16_be()?;
            let identity = self
                .identities
                .pop_slice(identity_length as usize)
                .expect("UNREACHABLE");
            let _ticket_age = self.identities.pop_u32_be().expect("UNREACHABLE");

            identity
        };

        let binder = {
            let binder_length = self.binders.pop_u8()?;
            let binder = self
                .binders
                .pop_slice(binder_length as usize)
                .expect("UNREACHABLE");

            binder
        };

        Some(OfferedPreSharedKey { identity, binder })
    }
}

impl<'a> PskIter<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<(Self, usize)> {
        // Identity part
        let identity_size = buf.pop_u16_be()?;
        let identities = buf.pop_slice(identity_size as usize)?;

        // Binders part
        let binders_size = buf.pop_u16_be()?;
        let binders_start_pos = buf.current_pos_ptr();
        let binders = buf.pop_slice(binders_size as usize)?;

        // Traverse the slices and make sure all sizes do add up, else return error.
        // This so the iterator itself does not start giving out values with broken data until
        // the error is hit.

        // Check that the identities makes sense.
        {
            let mut buf = ParseBuffer::new(identities);

            while !buf.is_empty() {
                let identity_length = buf.pop_u16_be()?;
                let _identity = buf.pop_slice(identity_length as usize)?;
                let _ticket_age = buf.pop_u32_be()?;
            }
        }

        // Check that the binders makes sense.
        {
            let mut buf = ParseBuffer::new(binders);

            while !buf.is_empty() {
                let binder_length = buf.pop_u8()?;
                let _binder = buf.pop_slice(binder_length as usize)?;
            }
        }

        Some((
            PskIter {
                identities: ParseBuffer::new(identities),
                binders: ParseBuffer::new(binders),
            },
            binders_start_pos,
        ))
    }
}

/// Pre-shared key entry.
#[derive(Clone, PartialOrd, PartialEq)]
pub struct Psk<'a> {
    /// A label for the key. For instance, a ticket (as defined in Appendix B.3.4) or a label
    /// for a pre-shared key established externally.
    pub identity: &'a [u8],
    /// The pre-shared key.
    pub key: &'a [u8],
}

impl<'a> core::fmt::Debug for Psk<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Psk")
            .field("identity", &self.identity)
            .field("key", &"REDACTED")
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl<'a> defmt::Format for Psk<'a> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(
            f,
            "Psk {{ identity: {:x}, psk: <REDACTED> }}",
            self.identity
        )
    }
}

impl<'a> Psk<'a> {
    /// Encode a pre-shared key identity into the buffer.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), OutOfMemory> {
        // Encode length.
        buf.push_u16_be(self.identity.len() as u16)?;

        // Encode identity.
        buf.extend_from_slice(self.identity)?;

        // Encode ticket age.
        buf.push_u32_be(0)
    }
}

/// The pre-shared keys the server has selected.
#[derive_format_or_debug]
#[derive(Clone, PartialOrd, PartialEq)]
pub struct SelectedPsk {
    /// List of identities that can be used. Ticket age is set to 0.
    pub selected_identity: u16,
}

impl SelectedPsk {
    /// Encode the selected pre-shared key.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), OutOfMemory> {
        buf.push_u16_be(self.selected_identity)
    }

    /// Parse a selected pre-shared key identity.
    pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
        Some(Self {
            selected_identity: buf.pop_u16_be()?,
        })
    }
}

/// The heartbeat extension.
///
/// From Section 2, RFC6520.
#[derive_format_or_debug]
#[derive(Clone, PartialOrd, PartialEq)]
pub struct HeartbeatExtension {
    /// Supported heartbeat mode.
    pub mode: HeartbeatMode,
}

impl HeartbeatExtension {
    /// Encode a `heartbeat` extension.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), OutOfMemory> {
        buf.push_u8(self.mode as u8)
    }

    /// Parse a supported heartbeat.
    pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
        Some(Self {
            mode: HeartbeatMode::try_from(buf.pop_u8()?).ok()?,
        })
    }
}

/// Heartbeat mode.
///
/// From Section 2, RFC6520.
#[repr(u8)]
#[derive_format_or_debug]
#[derive(Copy, Clone, PartialOrd, PartialEq, TryFromPrimitive)]
pub enum HeartbeatMode {
    PeerAllowedToSend = 1,
    PeerNotAllowedToSend = 2,
}

/// Pre-Shared Key Exchange Modes (RFC 8446, 4.2.9)
#[repr(u8)]
#[derive_format_or_debug]
#[derive(Copy, Clone, PartialOrd, PartialEq, TryFromPrimitive)]
pub enum PskKeyExchangeMode {
    ///  PSK-only key establishment. In this mode, the server MUST NOT supply a `key_share` value.
    PskKe = 0,
    /// PSK with (EC)DHE key establishment. In this mode, the client and server MUST supply
    /// `key_share` values.
    PskDheKe = 1,
}

/// Named groups which the client supports for key exchange.
#[repr(u16)]
#[derive_format_or_debug]
#[derive(Copy, Clone, PartialOrd, PartialEq, TryFromPrimitive)]
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
#[derive_format_or_debug]
#[derive(Copy, Clone, PartialOrd, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum ExtensionType {
    ServerName = 0,
    MaxFragmentLength = 1,
    StatusRequest = 5,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    Heartbeat = 15,
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
