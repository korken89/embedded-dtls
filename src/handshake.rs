use self::extensions::{ClientExtensions, DtlsVersions, NamedGroup, NewServerExtensions};
use crate::{
    buffer::{AllocSliceHandle, AllocU16Handle, AllocU24Handle, EncodingBuffer, ParseBuffer},
    cipher_suites::DtlsCipherSuite,
    handshake::extensions::PskKeyExchangeMode,
    integers::U24,
    key_schedule::KeySchedule,
    record::{EncodeOrParse, ProtocolVersion, RecordPayloadPositions, LEGACY_DTLS_VERSION},
    server::ServerKeySchedule,
    server_config::{Identity, ServerConfig},
};
use digest::{core_api::BufferKindUser, Digest};
use num_enum::TryFromPrimitive;
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::PublicKey;

pub mod extensions;

/// The random bytes in a handshake.
pub type Random = [u8; 32];

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ClientHandshake<'a> {
    ClientHello(ClientHello<'a>),
    ClientFinished(Finished<'a>),
}

impl<'a> ClientHandshake<'a> {
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<Option<usize>, ()> {
        // Encode client handshake.
        let header = HandshakeHeader::encode(self.handshake_type(), buf)?;

        // TODO: How to support fragmentation so we can ship this over e.g. IEEE802.15.4 radio that
        // only has payload of 60-100 bytes?
        // For now just assume everything goes into one `Handshake`.

        let content_start = buf.len();

        let binders = match self {
            ClientHandshake::ClientHello(hello) => hello.encode(buf)?,
            ClientHandshake::ClientFinished(finished) => {
                finished.encode(buf)?;
                None
            }
        };

        let binders_position = if let Some(binders) = binders {
            let binders_start = binders.start_pos_ptr(buf);
            binders.fill(buf, 0);
            Some(binders_start)
        } else {
            None
        };

        let content_length = (buf.len() - content_start) as u32;

        header.length.set(buf, content_length.into());
        header.message_seq.set(buf, 1); // TODO: This should probably be something else than 1
        header.fragment_offset.set(buf, 0.into());
        header.fragment_length.set(buf, content_length.into());

        // // The Handshake is finished, ready for transcript hash and binders.
        // if let Some(binders) = binders {
        //     // Update the transcript with everything up until the binder itself.
        //     transcript_hasher.update(binders.slice_up_until(buf));

        //     // Calculate the binder entry.
        //     let binder_entry = key_schedule
        //         .create_binder(&transcript_hasher.clone().finalize())
        //         .expect("Unable to generate binder");

        //     // Save the binder entry to the correct location.
        //     // TODO: For each binder.
        //     let buf = binders.into_buffer(buf);
        //     buf[0] = binder_entry.len() as u8;
        //     buf[1..].copy_from_slice(&binder_entry);

        //     // Add the binder entry to the transcript.
        //     transcript_hasher.update(&buf);
        // } else {
        //     transcript_hasher.update(buf);
        // }

        Ok(binders_position.flatten())
    }

    /// Parse a handshake message.
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<(Self, Option<usize>)> {
        let handshake_header = HandshakeHeader::parse(buf)?;

        if handshake_header.length != handshake_header.fragment_length {
            l0g::error!("We don't support fragmented handshakes yet.");
            return None;
        }

        let handshake_payload = buf.pop_slice(handshake_header.fragment_length.get() as usize)?;

        l0g::trace!("Got handshake: {:?}", handshake_header);

        match handshake_header.msg_type {
            HandshakeType::ClientHello => {
                let mut buf = ParseBuffer::new(handshake_payload);
                let (client_hello, binders_pos) = ClientHello::parse(&mut buf)?;

                l0g::trace!("Got client hello: {:02x?}", client_hello);

                Some((Self::ClientHello(client_hello), binders_pos))
            }
            HandshakeType::Finished => {
                let client_finished = Finished::parse(&mut ParseBuffer::new(handshake_payload));

                l0g::trace!("Got client finished: {:02x?}", client_finished);

                Some((Self::ClientFinished(client_finished), None))
            }
            HandshakeType::KeyUpdate => todo!(),
            _ => None,
        }
    }

    fn handshake_type(&self) -> HandshakeType {
        match self {
            ClientHandshake::ClientHello(_) => HandshakeType::ClientHello,
            ClientHandshake::ClientFinished(_) => HandshakeType::Finished,
        }
    }
}
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ServerHandshake<'a> {
    ServerHello(ServerHello<'a>),
    ServerFinished(Finished<'a>),
}

impl<'a> ServerHandshake<'a> {
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), ()> {
        // Encode client handshake.
        let header = HandshakeHeader::encode(self.handshake_type(), buf)?;

        // TODO: How to support fragmentation so we can ship this over e.g. IEEE802.15.4 radio that
        // only has payload of 60-100 bytes?
        // For now just assume everything goes into one `Handshake`.

        let content_start = buf.len();

        match self {
            ServerHandshake::ServerHello(hello) => hello.encode(buf)?,
            ServerHandshake::ServerFinished(finished) => {
                finished.encode(buf)?;
            }
        };

        let content_length = (buf.len() - content_start) as u32;

        header.length.set(buf, content_length.into());
        header.message_seq.set(buf, 1); // TODO: This should probably be something else than 1
        header.fragment_offset.set(buf, 0.into());
        header.fragment_length.set(buf, content_length.into());

        Ok(())
    }

    /// Parse a handshake message.
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<Self> {
        let handshake_header = HandshakeHeader::parse(buf)?;

        if handshake_header.length != handshake_header.fragment_length {
            l0g::error!("We don't support fragmented handshakes yet.");
            return None;
        }

        let handshake_payload = buf.pop_slice(handshake_header.fragment_length.get() as usize)?;

        l0g::trace!("Got handshake: {:?}", handshake_header);

        match handshake_header.msg_type {
            HandshakeType::ServerHello => {
                let server_hello = ServerHello::parse(&mut ParseBuffer::new(handshake_payload))?;

                l0g::trace!("Got server hello: {:02x?}", server_hello);

                Some(Self::ServerHello(server_hello))
            }
            HandshakeType::Finished => {
                let server_finished = Finished::parse(&mut ParseBuffer::new(handshake_payload));

                l0g::trace!("Got server finished: {:02x?}", server_finished);

                Some(Self::ServerFinished(server_finished))
            }
            HandshakeType::KeyUpdate => todo!(),
            _ => None,
        }
    }

    fn handshake_type(&self) -> HandshakeType {
        match self {
            ServerHandshake::ServerHello(_) => HandshakeType::ServerHello,
            ServerHandshake::ServerFinished(_) => HandshakeType::Finished,
        }
    }
}

// --------------------------------------------------------------------------
//
// TODO: This below should be its own files most likely. This will get large.
//
// --------------------------------------------------------------------------

#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialOrd, PartialEq, TryFromPrimitive)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    pub msg_type: HandshakeType,
    pub length: U24,
    pub message_seq: u16,
    pub fragment_offset: U24,
    pub fragment_length: U24,
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
    pub fn encode(
        msg_type: HandshakeType,
        buf: &mut EncodingBuffer,
    ) -> Result<HandshakeHeaderAllocations, ()> {
        buf.push_u8(msg_type as u8)?;

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

    /// Parse a handshake header.
    pub fn parse(buf: &mut ParseBuffer) -> Option<Self> {
        Some(Self {
            msg_type: HandshakeType::try_from(buf.pop_u8()?).ok()?,
            length: buf.pop_u24_be()?,
            message_seq: buf.pop_u16_be()?,
            fragment_offset: buf.pop_u24_be()?,
            fragment_length: buf.pop_u24_be()?,
        })
    }
}

/// ClientHello payload in a Handshake.
#[derive(Debug)]
pub struct ClientHello<'a> {
    pub version: ProtocolVersion,
    pub legacy_session_id: &'a [u8],
    pub cipher_suites: &'a [u8],
    pub random: &'a [u8],
    pub extensions: ClientExtensions<'a>,
}

impl<'a> ClientHello<'a> {
    /// Encode a client hello payload in a Handshake. RFC 9147 section 5.3.
    ///
    /// Returns the allocated position for binders.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<Option<AllocSliceHandle>, ()> {
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
        if self.random.len() != 32 {
            return Err(());
        }
        buf.extend_from_slice(&self.random)?;

        // Legacy Session ID.
        buf.push_u8(0)?;

        // Legacy cookie.
        buf.push_u8(0)?;

        // Cipher suites, we only support the one selected by the trait.
        buf.push_u16_be(self.cipher_suites.len() as u16)?;
        buf.extend_from_slice(self.cipher_suites)?;

        // Compression methods, select none.
        buf.push_u8(1)?;
        buf.push_u8(0)?;

        // List of extensions.
        let extensions_length_allocation = buf.alloc_u16()?;
        let content_start = buf.len();

        let binders_allocation = self.extensions.encode(buf)?;

        // Fill in the length of extensions.
        let content_length = (buf.len() - content_start) as u16;
        extensions_length_allocation.set(buf, content_length);

        Ok(binders_allocation)
    }

    /// Parse a ClientHello.
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<(Self, Option<usize>)> {
        let version = buf.pop_u16_be()?.to_be_bytes();
        let random = buf.pop_slice(32)?;

        //     opaque legacy_session_id<0..32>;
        //     opaque legacy_cookie<0..2^8-1>;                  // DTLS
        let legacy_session_id_len = buf.pop_u8()?;
        let legacy_session_id = buf.pop_slice(legacy_session_id_len as usize)?;

        let legacy_cookie = buf.pop_u8()?;
        if legacy_cookie != 0 {
            l0g::trace!("Legacy cookie is non-zero");
            return None;
        }

        let cipher_suites = {
            let num_cipher_suites_bytes = buf.pop_u16_be()?;

            if num_cipher_suites_bytes % 2 != 0 {
                // Not an even amount of bytes (each cipher suite needs 2 bytes)
                return None;
            }

            buf.pop_slice(num_cipher_suites_bytes as usize)?
        };

        let legacy_compression_methods_len = buf.pop_u8()?;
        let legacy_compression_methods = buf.pop_u8()?;
        if legacy_compression_methods_len != 1 || legacy_compression_methods != 0 {
            l0g::trace!("Legacy compression methods is non-zero");
            return None;
        }

        let (extensions, binders_start) = ClientExtensions::parse(buf)?;

        Some((
            Self {
                version,
                legacy_session_id,
                cipher_suites,
                random,
                extensions,
            },
            binders_start,
        ))
    }

    /// Check a client hello if it is valid, perform binder verification and setup the key
    /// schedule.
    pub fn validate_and_initialize_keyschedule(
        &self,
        key_schedule: &mut ServerKeySchedule,
        server_config: &ServerConfig,
        binders_hash: &[u8],
    ) -> Result<PublicKey, ()> {
        debug_assert!(key_schedule.is_uninitialized());

        if self.version != LEGACY_DTLS_VERSION {
            l0g::error!(
                "ClientHello version is not legacy DTLS version: {:02x?}",
                self.version
            );
            return Err(());
        }

        l0g::trace!("DTLS legacy version OK");

        // Are all the expexted extensions there? By this we enforce that the PSK key exchange
        // is ECDHE.
        // Verify with RFC8446, section 9.2
        let (
            Some(psk_key_exchange_modes),
            Some(supported_versions),
            Some(key_share),
            Some(pre_shared_key),
        ) = (
            &self.extensions.psk_key_exchange_modes,
            &self.extensions.supported_versions,
            &self.extensions.key_share,
            &self.extensions.pre_shared_key,
        )
        else {
            // TODO: For now we expect these specific extensions.
            l0g::error!("ClientHello: Not all expected extensions are provided {self:02x?}");
            return Err(());
        };

        l0g::trace!("All required extensions are present");

        if supported_versions.version != DtlsVersions::V1_3 {
            // We only support DTLS 1.3.
            l0g::error!("Not DTLS 1.3");
            return Err(());
        }
        l0g::trace!("DTLS version OK: {:?}", supported_versions.version);

        if key_share.group != NamedGroup::X25519 && key_share.opaque.len() == 32 {
            l0g::error!(
                    "ClientHello: The keyshare named group is unsupported or wrong key length: {:?}, len = {}",
                    key_share.group,
                    key_share.opaque.len()
                );
            return Err(());
        }
        l0g::trace!("Keyshare is OK: {:?}", key_share.group);

        if psk_key_exchange_modes.ke_modes != PskKeyExchangeMode::PskDheKe {
            l0g::error!(
                "ClientHello: The PskKeyExchangeMode is unsupported: {:?}",
                key_share.group
            );
            return Err(());
        }
        l0g::trace!(
            "Psk key exchange mode is OK: {:?}",
            psk_key_exchange_modes.ke_modes
        );

        // Find the PSK.
        {
            let EncodeOrParse::Parse(psk_iter) = &pre_shared_key.identities else {
                l0g::error!("ClientHello: Expected parse, got encoded PSK");
                return Err(());
            };

            // TODO: We only support a single PSK for now.

            let pre_shared_key = psk_iter.clone().next().ok_or(())?;

            let psk_identity = Identity::from(pre_shared_key.identity);
            let Some(psk) = server_config.psk.get(&psk_identity) else {
                l0g::error!("ClientHello: Psk unknown identity: {psk_identity:?}");
                return Err(());
            };
            l0g::trace!("Psk identity '{:?}' is AVAILABLE", psk_identity);

            // Perform PSK -> Early Secret with Key Schedule
            key_schedule.initialize_early_secret(Some((&psk_identity, psk)));

            // Verify binders with Early Secret
            let binder = key_schedule.create_binders(binders_hash);

            if binder != pre_shared_key.binder {
                l0g::error!("ClientHello: Psk binder mismatch");
                return Err(());
            }
            l0g::trace!("Psk binders MATCH");
        }

        let their_public_key =
            PublicKey::from(TryInto::<[u8; 32]>::try_into(key_share.opaque).unwrap());

        l0g::trace!("ClientHello VALID");

        Ok(their_public_key)
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

#[derive(Debug)]
pub struct ServerHello<'a> {
    pub version: ProtocolVersion,
    pub legacy_session_id_echo: &'a [u8],
    pub cipher_suite_index: u16,
    pub extensions: NewServerExtensions<'a>,
}

impl<'a> ServerHello<'a> {
    /// Encode a server hello payload in a Handshake. RFC 8446 section 4.1.3.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), ()> {
        // struct {
        //     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
        //     Random random;
        //     opaque legacy_session_id_echo<0..32>;
        //     CipherSuite cipher_suite;
        //     uint8 legacy_compression_method = 0;
        //     Extension extensions<6..2^16-1>;
        // } ServerHello;

        // Legacy version.
        buf.extend_from_slice(&LEGACY_DTLS_VERSION)?;

        // Random.
        buf.extend_from_slice(&rand::random::<Random>())?;

        // Legacy Session ID echo.
        buf.push_u8(self.legacy_session_id_echo.len() as u8)?;
        buf.extend_from_slice(&self.legacy_session_id_echo)?;

        // Selected cipher suite.
        buf.push_u16_be(self.cipher_suite_index)?;

        // Legacy compression methods.
        buf.push_u8(0)?;

        // List of extensions.
        let extensions_length_allocation = buf.alloc_u16()?;
        let content_start = buf.len();

        self.extensions.encode(buf)?;

        // Fill in the length of extensions.
        let content_length = (buf.len() - content_start) as u16;
        extensions_length_allocation.set(buf, content_length);

        Ok(())
    }

    pub fn parse(buf: &mut ParseBuffer<'a>) -> Option<Self> {
        let version = buf.pop_u16_be()?.to_be_bytes();
        let _random = buf.pop_slice(32)?;
        let legacy_session_id_len = buf.pop_u8()?;
        let legacy_session_id_echo = buf.pop_slice(legacy_session_id_len as usize)?;

        let cipher_suite_index = buf.pop_u16_be()?;

        let _legacy_compression_method = buf.pop_u8()?;

        // Extensions
        let extensions = NewServerExtensions::parse(buf)?;

        Some(Self {
            version,
            legacy_session_id_echo,
            cipher_suite_index,
            extensions,
        })
    }

    /// Validate the server hello.
    pub fn validate(&self) -> Result<PublicKey, ()> {
        if self.version != LEGACY_DTLS_VERSION {
            l0g::error!(
                "ServerHello version is not legacy DTLS version: {:02x?}",
                self.version
            );
            return Err(());
        }

        if !self.legacy_session_id_echo.is_empty() {
            l0g::error!("ServerHello legacy session id echo is not empty");
            return Err(());
        }

        // TODO: We only support one today, maybe more in the future.
        if self.cipher_suite_index != 0 {
            l0g::error!(
                "ServerHello cipher suite mismatch, got {:04x}",
                self.cipher_suite_index
            );
            return Err(());
        }

        // Are all the expexted extensions there? By this we enforce that the PSK key exchange
        // is ECDHE.
        // Verify with RFC8446, section 9.2
        let (Some(selected_supported_version), Some(key_share), Some(selected_psk)) = (
            &self.extensions.selected_supported_version,
            &self.extensions.key_share,
            &self.extensions.pre_shared_key,
        ) else {
            // TODO: For now we expect these specific extensions.
            l0g::error!("ServerHello: Not all expected extensions are provided {self:02x?}");
            return Err(());
        };

        if selected_supported_version.version != DtlsVersions::V1_3 {
            // We only support DTLS 1.3.
            l0g::error!("Not DTLS 1.3");
            return Err(());
        }
        l0g::trace!("DTLS version OK: {:?}", selected_supported_version);

        if key_share.group != NamedGroup::X25519 && key_share.opaque.len() == 32 {
            l0g::error!(
                    "ClientHello: The keyshare named group is unsupported or wrong key length: {:?}, len = {}",
                    key_share.group,
                    key_share.opaque.len()
                );
            return Err(());
        }
        l0g::trace!("Keyshare is OK: {:?}", key_share.group);

        // TODO: We currently use the assumption that there is one PSK by looking for idx 0.
        if selected_psk.selected_identity != 0 {
            l0g::error!("ServerHello: Unknown selected Psk: {selected_psk:?}");
            return Err(());
        };
        l0g::trace!("Selected Psk identity OK");

        let their_public_key =
            PublicKey::from(TryInto::<[u8; 32]>::try_into(key_share.opaque).unwrap());

        l0g::trace!("ServerHello VALID");

        Ok(their_public_key)
    }
}

/// Finished payload in an Handshake.
#[derive(Clone, Debug, PartialOrd, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Finished<'a> {
    pub verify: &'a [u8],
}

impl<'a> Finished<'a> {
    /// Encode a Finished payload in an Handshake.
    pub fn encode(&self, buf: &mut EncodingBuffer) -> Result<(), ()> {
        buf.extend_from_slice(&self.verify)
    }

    /// Parse a finished message.
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Self {
        Self {
            verify: buf.pop_rest(),
        }
    }
}
