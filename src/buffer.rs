use crate::integers::{U24, U48};
use core::ops::{Deref, DerefMut};

/// Buffer.
#[must_use]
pub struct Buffer<'a> {
    buf: &'a mut [u8],
    write_back: Option<&'a mut usize>,
    len: usize,
}

struct WriteBack<'a> {
    len: Option<&'a mut usize>,
    prev: Option<&'a mut WriteBack<'a>>,
}

impl<'a> Buffer<'a> {
    /// Create a new buffer.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            write_back: None,
            len: 0,
        }
    }

    /// Length of the current buffer.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Length of the current buffer.
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Create a buffer with its cursor at the current buffer's length.
    pub fn forward<'b>(&'b mut self) -> Buffer<'b> {
        Buffer {
            buf: &mut self.buf[self.len..],
            write_back: Some(&mut self.len),
            len: 0,
        }
    }

    /// Allocate a slice in the buffer.
    fn alloc_slice_inner<'b>(&'b mut self, size: usize) -> Result<(&'b mut [u8], Buffer<'b>), ()> {
        // No `try_split_at_mut` 😢
        if self.len + size > self.buf.len() {
            return Err(());
        }
        let (s, rem) = self.buf.split_at_mut(self.len + size);
        self.len += size;

        Ok((
            s,
            Buffer {
                buf: rem,
                write_back: Some(&mut self.len),
                len: 0,
            },
        ))
    }

    /// Allocate the space for a `u8` for later updating.
    pub fn alloc_slice<'b>(
        &'b mut self,
        size: usize,
    ) -> Result<(AllocSliceHandle<'b>, Buffer<'b>), ()> {
        let (buf, rem) = self.alloc_slice_inner(size)?;

        Ok((AllocSliceHandle { buf }, rem))
    }

    /// Allocate the space for a `u8` for later updating.
    pub fn alloc_u8<'b>(&'b mut self) -> Result<(AllocU8Handle<'b>, Buffer<'b>), ()> {
        let (buf, rem) = self.alloc_slice_inner(1)?;

        Ok((AllocU8Handle { buf: &mut buf[0] }, rem))
    }

    /// Allocate the space for a `u16` for later updating.
    pub fn alloc_u16<'b>(&'b mut self) -> Result<(AllocU16Handle<'b>, Buffer<'b>), ()> {
        let (buf, rem) = self.alloc_slice_inner(2)?;

        Ok((
            AllocU16Handle {
                buf: buf.try_into().unwrap(),
            },
            rem,
        ))
    }

    /// Allocate the space for a `u24` for later updating.
    pub fn alloc_u24<'b>(&'b mut self) -> Result<(AllocU24Handle<'b>, Buffer<'b>), ()> {
        let (buf, rem) = self.alloc_slice_inner(3)?;

        Ok((
            AllocU24Handle {
                buf: buf.try_into().unwrap(),
            },
            rem,
        ))
    }

    /// Allocate the space for a `u48` for later updating.
    pub fn alloc_u48<'b>(&'b mut self) -> Result<(AllocU48Handle<'b>, Buffer<'b>), ()> {
        let (buf, rem) = self.alloc_slice_inner(6)?;

        Ok((
            AllocU48Handle {
                buf: buf.try_into().unwrap(),
            },
            rem,
        ))
    }

    /// Push a slice.
    pub fn extend_from_slice(&mut self, slice: &[u8]) -> Result<(), ()> {
        self.buf
            .get_mut(self.len..self.len + slice.len())
            .ok_or(())?
            .copy_from_slice(slice);
        self.len += slice.len();

        Ok(())
    }

    /// Push a byte.
    pub fn push_u8(&mut self, val: u8) -> Result<(), ()> {
        *self.buf.get_mut(self.len).ok_or(())? = val;
        self.len += 1;

        Ok(())
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
}

impl<'a> Drop for Buffer<'a> {
    fn drop(&mut self) {
        if let Some(write_back) = self.write_back.take() {
            *write_back += self.len;
        }
    }
}

impl<'a> Deref for Buffer<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buf[..self.len]
    }
}

impl<'a> DerefMut for Buffer<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf[..self.len]
    }
}

/// Handle to an allocated `u8` spot in a `DTlsBuffer`.
#[must_use]
pub struct AllocU8Handle<'a> {
    buf: &'a mut u8,
}

impl<'a> AllocU8Handle<'a> {
    /// Set the value.
    pub fn set(self, val: u8) {
        *self.buf = val;
        core::mem::forget(self);
    }
}

impl<'a> Drop for AllocU8Handle<'a> {
    fn drop(&mut self) {
        panic!("Alloc handle dropped without being used!");
    }
}

/// Handle to an allocated `u16` spot in a `DTlsBuffer`.
#[must_use]
pub struct AllocU16Handle<'a> {
    buf: &'a mut [u8; 2],
}

impl<'a> AllocU16Handle<'a> {
    /// Set the value.
    pub fn set(self, val: u16) {
        self.buf.copy_from_slice(&val.to_be_bytes());
        core::mem::forget(self);
    }
}

impl<'a> Drop for AllocU16Handle<'a> {
    fn drop(&mut self) {
        panic!("Alloc handle dropped without being used!");
    }
}

/// Handle to an allocated `u24` spot in a `DTlsBuffer`.
#[must_use]
pub struct AllocU24Handle<'a> {
    buf: &'a mut [u8; 3],
}

impl<'a> AllocU24Handle<'a> {
    /// Set the value.
    pub fn set(self, val: U24) {
        self.buf.copy_from_slice(&val.to_be_bytes());
        core::mem::forget(self);
    }
}

impl<'a> Drop for AllocU24Handle<'a> {
    fn drop(&mut self) {
        panic!("Alloc handle dropped without being used!");
    }
}

/// Handle to an allocated `u48` spot in a `DTlsBuffer`.
#[must_use]
pub struct AllocU48Handle<'a> {
    buf: &'a mut [u8; 6],
}

impl<'a> AllocU48Handle<'a> {
    /// Set the value.
    pub fn set(self, val: U48) {
        self.buf.copy_from_slice(&val.to_be_bytes());
        core::mem::forget(self);
    }
}

impl<'a> Drop for AllocU48Handle<'a> {
    fn drop(&mut self) {
        panic!("Alloc handle dropped without being used!");
    }
}

/// Handle to an allocated slice in a `DTlsBuffer`.
#[must_use]
pub struct AllocSliceHandle<'a> {
    buf: &'a mut [u8],
}

impl<'a> AllocSliceHandle<'a> {
    /// Set the value.
    pub fn set(self, val: &[u8]) {
        self.buf.copy_from_slice(val);
        core::mem::forget(self);
    }
}

impl<'a> Drop for AllocSliceHandle<'a> {
    fn drop(&mut self) {
        panic!("Alloc handle dropped without being used!");
    }
}

#[cfg(test)]
mod tests {
    use super::Buffer;

    // #[test]
    // fn push() {
    //     let mut buf = [0; 128];
    //     let mut buf = Buffer::new(&mut buf);

    //     assert_eq!(buf.len(), 0);

    //     buf.push_u8(11).unwrap();
    //     buf.push_u8(12).unwrap();
    //     buf.push_u8(13).unwrap();
    //     assert_eq!(buf[0], 11);
    //     assert_eq!(buf[1], 12);
    //     assert_eq!(buf[2], 13);

    //     buf.forward_start();

    //     assert_eq!(buf.len(), 0);

    //     buf.push_u8(14).unwrap();
    //     assert_eq!(buf[0], 14);

    //     buf.reset_start();

    //     assert_eq!(buf[0], 11);
    //     assert_eq!(buf[1], 12);
    //     assert_eq!(buf[2], 13);
    //     assert_eq!(buf[3], 14);

    //     buf.forward_start();

    //     buf.extend_from_slice(&[1, 2, 3, 4]).unwrap();
    //     assert_eq!(buf[..4], [1, 2, 3, 4]);

    //     buf.reset_start();
    //     assert_eq!(buf[..], [11, 12, 13, 14, 1, 2, 3, 4]);
    // }

    #[test]
    fn alloc() {
        let mut buf = [0; 128];
        let mut buf = Buffer::new(&mut buf);

        {
            let (a1, mut buf) = buf.alloc_u8().unwrap();
            let (a2, mut buf) = buf.alloc_slice(5).unwrap();

            a1.set(1);
            a2.set(&[1, 2, 3, 4, 5]);
        }

        assert_eq!(buf.len(), 6);
        assert_eq!(buf[..], [1, 1, 2, 3, 4, 5]);
    }
}
