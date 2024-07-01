pub use crate::handshake::extensions::Psk;
use defmt_or_log::derive_format_or_debug;

/// Client configuration.
#[derive_format_or_debug]
pub struct ClientConfig<'a> {
    /// Preshared key.
    /// TODO: Support a list of PSKs. Needs work in how to calculate binders and track all the
    /// necessary early secrets derived from the PSKs until the server selects one PSK.
    pub psk: Psk<'a>,
}
