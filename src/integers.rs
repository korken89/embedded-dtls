use core::ops::{Add, AddAssign};
use defmt_or_log::maybe_derive_format;

/// Represents a `uint24` in TLS.
#[maybe_derive_format]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U24(u32);

impl U24 {
    const MASK: u32 = (1 << 24) - 1;

    /// Create a new U24. This truncates the inputted `u32`.
    pub const fn new(val: u32) -> Self {
        Self(val & Self::MASK)
    }

    /// Convert to big-endian bytes.
    #[inline(always)]
    pub fn to_be_bytes(self) -> [u8; 3] {
        self.0.to_be_bytes()[1..].try_into().unwrap()
    }

    /// Create from big-endian bytes.
    #[inline(always)]
    pub fn from_be_bytes(bytes: [u8; 3]) -> Self {
        Self(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
    }

    /// Get the underlying value.
    pub fn get(self) -> u32 {
        self.0
    }
}

/// Represents a `uint48` in TLS.
#[maybe_derive_format]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct U48(u64);

impl U48 {
    const MASK: u64 = (1 << 48) - 1;

    /// Create a new U48. This truncates the inputted `u64`.
    pub const fn new(val: u64) -> Self {
        Self(val & Self::MASK)
    }

    /// Convert to big-endian bytes.
    #[inline(always)]
    pub fn to_be_bytes(self) -> [u8; 6] {
        self.0.to_be_bytes()[2..].try_into().unwrap()
    }

    /// Create from big-endian bytes.
    #[inline(always)]
    pub fn from_be_bytes(bytes: [u8; 6]) -> Self {
        Self(u64::from_be_bytes([
            0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
        ]))
    }

    /// Get the underlying value.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl Add for U24 {
    type Output = U24;

    fn add(self, rhs: Self) -> Self::Output {
        Self((self.0 + rhs.0) & Self::MASK)
    }
}

impl From<u32> for U24 {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl Add<u32> for U24 {
    type Output = U24;

    fn add(self, rhs: u32) -> Self::Output {
        Self((self.0 + rhs) & Self::MASK)
    }
}

impl AddAssign for U24 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl AddAssign<u32> for U24 {
    fn add_assign(&mut self, rhs: u32) {
        *self = *self + rhs;
    }
}

impl From<u64> for U48 {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl Add for U48 {
    type Output = U48;

    fn add(self, rhs: Self) -> Self::Output {
        Self((self.0 + rhs.0) & Self::MASK)
    }
}

impl Add<u64> for U48 {
    type Output = U48;

    fn add(self, rhs: u64) -> Self::Output {
        Self((self.0 + rhs) & Self::MASK)
    }
}

impl AddAssign for U48 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl AddAssign<u64> for U48 {
    fn add_assign(&mut self, rhs: u64) {
        *self = *self + rhs;
    }
}
