use defmt_or_log::{derive_format_or_debug, maybe_derive_format};

/// Pre-shared key identity.
#[maybe_derive_format]
#[derive(PartialEq, Eq, Hash)]
pub struct Identity<'a>(&'a [u8]);

impl<'a, T> From<&'a T> for Identity<'a>
where
    T: AsRef<[u8]>,
{
    fn from(value: &'a T) -> Self {
        Self(value.as_ref())
    }
}

impl<'a> Identity<'a> {
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.0
    }
}

impl<'a> core::fmt::Debug for Identity<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match core::str::from_utf8(self.0) {
            Ok(string) => f.write_str(string),
            Err(_) => {
                for b in self.0 {
                    write!(f, "{:02x}", b)?;
                }

                Ok(())
            }
        }
    }
}

/// Pre-shared key value.
#[derive_format_or_debug]
pub struct Key<'a>(&'a [u8]);

impl<'a, T> From<&'a T> for Key<'a>
where
    T: AsRef<[u8]>,
{
    fn from(value: &'a T) -> Self {
        Self(value.as_ref())
    }
}

impl<'a> Key<'a> {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// Server configuration.
pub struct ServerConfig<'a, 'b> {
    /// A list of allowed pre-shared keys.
    ///
    /// The key is the identity and the value is the key.
    pub psk: &'b [(Identity<'a>, Key<'a>)],
}
