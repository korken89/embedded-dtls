use crate::integers::{U24, U48};
use core::{
    fmt,
    ops::{Deref, DerefMut},
};

/// A buffer handler wrapping a mutable slice.
pub struct SliceBuffer<'a> {
    buf: &'a mut [u8],
    idx: usize,
    start: usize,
}

impl<'a> fmt::Debug for SliceBuffer<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SliceBuffer (start = {}, idx = {}, capacity = {}) {:?}",
            self.start,
            self.idx,
            self.buf.len(),
            &self.buf[..self.idx]
        )
    }
}

impl<'a> SliceBuffer<'a> {
    /// Create new buffer from a slice.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            idx: 0,
            start: 0,
        }
    }

    /// Current length of the buffer.
    pub fn len(&self) -> usize {
        self.idx - self.start
    }

    /// Capacity of the buffer.
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Current index of the buffer.
    pub fn index(&self) -> usize {
        self.idx
    }

    /// Extend with a slice.
    pub fn extend_from_slice(&mut self, slice: &[u8]) -> Result<(), ()> {
        self.buf
            .get_mut(self.idx..self.idx + slice.len())
            .ok_or(())?
            .copy_from_slice(slice);
        self.idx += slice.len();

        Ok(())
    }

    /// Push a u8.
    pub fn push_u8(&mut self, val: u8) -> Result<(), ()> {
        *self.buf.get_mut(self.idx).ok_or(())? = val;
        self.idx += 1;

        Ok(())
    }

    /// Move the start to the current index.
    pub fn forward_start(&mut self) {
        self.start = self.idx;
    }

    /// Reset start to 0.
    pub fn reset_start(&mut self) {
        self.start = 0;
    }

    /// Push a u16 in big-endian.
    pub fn push_u16_be(&mut self, val: u16) -> Result<(), ()> {
        self.extend_from_slice(&val.to_be_bytes())
    }

    /// Push a u24 in big-endian.
    pub fn push_u24_be(&mut self, val: U24) -> Result<(), ()> {
        self.extend_from_slice(&val.to_be_bytes())
    }

    /// Push a u32 in big-endian.
    pub fn push_u32_be(&mut self, val: u32) -> Result<(), ()> {
        self.extend_from_slice(&val.to_be_bytes())
    }

    /// Push a u48 in big-endian.
    pub fn push_u48_be(&mut self, val: U48) -> Result<(), ()> {
        self.extend_from_slice(&val.to_be_bytes())
    }

    /// Allocate the space for a `u8` for later updating.
    pub fn alloc_u8(&mut self) -> Result<AllocU8Handle, ()> {
        let index = self.index();
        self.push_u8(0)?;

        Ok(AllocU8Handle { index })
    }

    /// Allocate the space for a `u16` for later updating.
    pub fn alloc_u16(&mut self) -> Result<AllocU16Handle, ()> {
        let index = self.index();
        self.push_u16_be(0)?;

        Ok(AllocU16Handle { index })
    }

    /// Allocate the space for a `u24` for later updating.
    pub fn alloc_u24(&mut self) -> Result<AllocU24Handle, ()> {
        let index = self.index();
        self.push_u24_be(U24::new(0))?;

        Ok(AllocU24Handle { index })
    }

    /// Allocate the space for a `u48` for later updating.
    pub fn alloc_u48(&mut self) -> Result<AllocU48Handle, ()> {
        let index = self.index();
        self.push_u48_be(U48::new(0))?;

        Ok(AllocU48Handle { index })
    }

    /// Allocate space for a slice for later updating.
    pub fn alloc_slice(&mut self, len: usize) -> Result<AllocSliceHandle, ()> {
        let index = self.index();

        for _ in 0..len {
            self.push_u8(0)?;
        }

        Ok(AllocSliceHandle { index, len })
    }
}

impl<'a> Deref for SliceBuffer<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.buf.get(self.start..self.idx).unwrap_or(&[])
    }
}

impl<'a> DerefMut for SliceBuffer<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf.get_mut(self.start..self.idx).unwrap_or(&mut [])
    }
}

impl<'a> AsRef<[u8]> for SliceBuffer<'a> {
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

/// Handle to an allocated `u8` spot in a `DTlsBuffer`.
#[derive(Debug)]
#[must_use]
pub struct AllocU8Handle {
    index: usize,
}

impl AllocU8Handle {
    /// Set the value.
    pub fn set(self, buf: &mut SliceBuffer, val: u8) {
        buf.buf[self.index] = val;
        core::mem::forget(self);
    }
}

impl Drop for AllocU8Handle {
    fn drop(&mut self) {
        panic!("Alloc handle dropped without being used!");
    }
}

/// Handle to an allocated `u16` spot in a `DTlsBuffer`.
#[derive(Debug)]
#[must_use]
pub struct AllocU16Handle {
    index: usize,
}

impl AllocU16Handle {
    /// Set the value.
    pub fn set(self, buf: &mut SliceBuffer, val: u16) {
        buf.buf[self.index..self.index + 2].copy_from_slice(&val.to_be_bytes());
        core::mem::forget(self);
    }
}

impl Drop for AllocU16Handle {
    fn drop(&mut self) {
        panic!("Alloc handle dropped without being used!");
    }
}

/// Handle to an allocated `u24` spot in a `DTlsBuffer`.
#[derive(Debug)]
#[must_use]
pub struct AllocU24Handle {
    index: usize,
}

impl AllocU24Handle {
    /// Set the value.
    pub fn set(self, buf: &mut SliceBuffer, val: U24) {
        buf.buf[self.index..self.index + 3].copy_from_slice(&val.to_be_bytes());
        core::mem::forget(self);
    }
}

impl Drop for AllocU24Handle {
    fn drop(&mut self) {
        panic!("Alloc handle dropped without being used!");
    }
}

/// Handle to an allocated `u48` spot in a `DTlsBuffer`.
#[derive(Debug)]
#[must_use]
pub struct AllocU48Handle {
    index: usize,
}

impl AllocU48Handle {
    /// Set the value.
    pub fn set(self, buf: &mut SliceBuffer, val: U48) {
        buf.buf[self.index..self.index + 6].copy_from_slice(&val.to_be_bytes());
        core::mem::forget(self);
    }
}

impl Drop for AllocU48Handle {
    fn drop(&mut self) {
        panic!("Alloc handle dropped without being used!");
    }
}

/// Handle to an allocated slice in a `DTlsBuffer`.
#[derive(Debug)]
#[must_use]
pub struct AllocSliceHandle {
    index: usize,
    len: usize,
}

impl AllocSliceHandle {
    /// The the slice from buffer that is everything up until this allocation starts.
    pub fn slice_up_until<'a>(&'a self, buf: &'a SliceBuffer) -> &'a [u8] {
        buf.buf.get(buf.start..self.index).unwrap_or(&[])
    }

    /// Set the value.
    pub fn set(self, buf: &mut SliceBuffer, val: &[u8]) {
        buf.buf
            .get_mut(self.index..self.index + self.len)
            .unwrap_or(&mut [])
            .copy_from_slice(val);
        core::mem::forget(self);
    }

    /// Get the underlying buffer and manually set it.
    pub fn into_buffer<'a>(self, buf: &'a mut SliceBuffer) -> &'a mut [u8] {
        let r = buf
            .buf
            .get_mut(self.index..self.index + self.len)
            .unwrap_or(&mut []);
        core::mem::forget(self);

        r
    }
}

impl Drop for AllocSliceHandle {
    fn drop(&mut self) {
        panic!("Alloc handle dropped without being used!");
    }
}

#[cfg(test)]
mod tests {
    use super::SliceBuffer;

    #[test]
    fn push() {
        let mut buf = [0; 128];
        let mut buf = SliceBuffer::new(&mut buf);

        assert_eq!(buf.len(), 0);

        buf.push_u8(11).unwrap();
        buf.push_u8(12).unwrap();
        buf.push_u8(13).unwrap();
        assert_eq!(buf[0], 11);
        assert_eq!(buf[1], 12);
        assert_eq!(buf[2], 13);

        buf.forward_start();

        assert_eq!(buf.len(), 0);

        println!("buf: {buf:?}");
        buf.push_u8(14).unwrap();
        println!("buf: {buf:?}");
        assert_eq!(buf[0], 14);

        buf.reset_start();

        assert_eq!(buf[0], 11);
        assert_eq!(buf[1], 12);
        assert_eq!(buf[2], 13);
        assert_eq!(buf[3], 14);

        buf.forward_start();

        buf.extend_from_slice(&[1, 2, 3, 4]).unwrap();
        assert_eq!(buf[..4], [1, 2, 3, 4]);

        buf.reset_start();
        assert_eq!(buf[..], [11, 12, 13, 14, 1, 2, 3, 4]);
    }

    #[test]
    fn alloc() {
        let mut buf = [0; 128];
        let mut buf = SliceBuffer::new(&mut buf);

        let a1 = buf.alloc_u8().unwrap();
        let a2 = buf.alloc_slice(5).unwrap();

        assert_eq!(buf.len(), 6);

        a1.set(&mut buf, 1);
        a2.set(&mut buf, &[1, 2, 3, 4, 5]);

        assert_eq!(buf[..], [1, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn slice_until() {
        let mut buf = [0; 128];
        let mut buf = SliceBuffer::new(&mut buf);

        buf.extend_from_slice(&[1, 2, 3, 4, 5]).unwrap();
        let a = buf.alloc_slice(3).unwrap();

        assert_eq!(a.slice_up_until(&buf), [1, 2, 3, 4, 5]);
        assert_eq!(buf.len(), 8);

        a.set(&mut buf, &[1, 2, 3]);

        println!("buf: {buf:?}");
        assert_eq!(buf[..], [1, 2, 3, 4, 5, 1, 2, 3]);

        buf.forward_start();
        println!("buf: {buf:?}");
        let a = buf.alloc_slice(3).unwrap();
        println!("a: {a:?}");
        assert_eq!(a.slice_up_until(&buf), []);

        a.set(&mut buf, &[4, 5, 6]);
    }
}
