use core::ops::{Add, AddAssign};

/// Represents a `uint24` in TLS.
#[derive(Copy, Clone, Debug, defmt::Format, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
}

/// Represents a `uint48` in TLS.
#[derive(Copy, Clone, Debug, defmt::Format, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
