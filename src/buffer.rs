use crate::integers::{U24, U48};
use core::ops::{Deref, DerefMut};

// pub mod embedded {
//     use core::ops::{Deref, DerefMut};

//     use heapless::Vec;

//     use super::DTlsBuffer;

//     /// A buffer handler wrapping a mutable slice.
//     ///
//     /// It allows for building DTLS records with look back for writing lengths.
//     pub struct HeaplessTlsBuffer {
//         buf: Vec<u8, 1024>,
//         offset: usize,
//     }

//     impl HeaplessTlsBuffer {
//         /// Create a new buffer wrapper.
//         #[inline]
//         pub fn new() -> Self {
//             Self {
//                 buf: Vec::new(),
//                 offset: 0,
//             }
//         }
//     }
// }

pub mod slice_buffer {
    use super::DTlsBuffer;
    use core::ops::{Deref, DerefMut};

    /// A buffer handler wrapping a mutable slice.
    pub struct SliceBuffer<'a> {
        buf: &'a mut [u8],
        idx: usize,
        start: usize,
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
    }

    impl<'a> Deref for SliceBuffer<'a> {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            &self.buf[self.start..self.idx]
        }
    }

    impl<'a> DerefMut for SliceBuffer<'a> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.buf[self.start..self.idx]
        }
    }

    impl<'a> DTlsBuffer for SliceBuffer<'a> {
        fn len(&self) -> usize {
            self.idx - self.start
        }

        fn index(&self) -> usize {
            self.idx
        }

        fn extend_from_slice(&mut self, slice: &[u8]) -> Result<(), ()> {
            self.buf
                .get_mut(self.idx..self.idx + slice.len())
                .ok_or(())?
                .copy_from_slice(slice);
            self.idx += slice.len();

            Ok(())
        }

        fn push_u8(&mut self, val: u8) -> Result<(), ()> {
            *self.buf.get_mut(self.idx).ok_or(())? = val;
            self.idx += 1;

            Ok(())
        }

        fn forward_start(&mut self) {
            self.start = self.idx;
        }

        fn reset_start(&mut self) {
            self.start = 0;
        }
    }
}

pub mod array_buffer {
    use digest::generic_array::{ArrayLength, GenericArray};

    use super::DTlsBuffer;
    use core::ops::{Deref, DerefMut};

    /// A buffer handler wrapping a mutable slice.
    // TODO: We can use `MaybeUninit` if we want to optimize.
    pub struct ArrayBuffer<N: ArrayLength<u8>> {
        buf: GenericArray<u8, N>,
        idx: usize,
    }

    impl<N> ArrayBuffer<N>
    where
        N: ArrayLength<u8>,
    {
        /// Create new buffer from a slice.
        pub fn new() -> Self {
            Self {
                buf: GenericArray::default(),
                idx: 0,
            }
        }

        /// Capacity of the buffer.
        pub fn capacity(&self) -> usize {
            N::to_usize()
        }
    }

    impl<N> Deref for ArrayBuffer<N>
    where
        N: ArrayLength<u8>,
    {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            &self.buf[..self.idx]
        }
    }

    impl<N> DerefMut for ArrayBuffer<N>
    where
        N: ArrayLength<u8>,
    {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.buf[..self.idx]
        }
    }

    impl<N> DTlsBuffer for ArrayBuffer<N>
    where
        N: ArrayLength<u8>,
    {
        fn len(&self) -> usize {
            self.idx
        }

        fn index(&self) -> usize {
            self.idx
        }

        fn extend_from_slice(&mut self, slice: &[u8]) -> Result<(), ()> {
            self.buf
                .get_mut(self.idx..self.idx + slice.len())
                .ok_or(())?
                .copy_from_slice(slice);

            Ok(())
        }

        fn push_u8(&mut self, val: u8) -> Result<(), ()> {
            *self.buf.get_mut(self.idx).ok_or(())? = val;
            self.idx += 1;

            Ok(())
        }

        fn forward_start(&mut self) {
            todo!()
        }

        fn reset_start(&mut self) {
            todo!()
        }
    }
}

pub mod std {
    // TODO
}

pub trait DTlsBuffer: Deref<Target = [u8]> + DerefMut {
    /// The current length.
    fn len(&self) -> usize;

    /// The current index.
    fn index(&self) -> usize;

    /// The the current index of the buffer to index 0.
    fn forward_start(&mut self);

    /// Reset the start index of the buffer to 0.
    fn reset_start(&mut self);

    /// Extend from a slice.
    fn extend_from_slice(&mut self, slice: &[u8]) -> Result<(), ()>;

    /// Push a byte.
    fn push_u8(&mut self, val: u8) -> Result<(), ()>;

    /// Push a u16 in big-endian.
    fn push_u16_be(&mut self, val: u16) -> Result<(), ()> {
        DTlsBuffer::extend_from_slice(self, &val.to_be_bytes())
    }
    /// Push a u24 in big-endian.
    fn push_u24_be(&mut self, val: U24) -> Result<(), ()> {
        DTlsBuffer::extend_from_slice(self, &val.to_be_bytes())
    }

    /// Push a u32 in big-endian.
    fn push_u32_be(&mut self, val: u32) -> Result<(), ()> {
        DTlsBuffer::extend_from_slice(self, &val.to_be_bytes())
    }

    /// Push a u48 in big-endian.
    fn push_u48_be(&mut self, val: U48) -> Result<(), ()> {
        DTlsBuffer::extend_from_slice(self, &val.to_be_bytes())
    }

    /// Allocate the space for a `u8` for later updating.
    fn alloc_u8(&mut self) -> Result<AllocU8Handle, ()> {
        let index = DTlsBuffer::index(self);
        DTlsBuffer::push_u8(self, 0)?;

        Ok(AllocU8Handle { index })
    }

    /// Allocate the space for a `u16` for later updating.
    fn alloc_u16(&mut self) -> Result<AllocU16Handle, ()> {
        let index = DTlsBuffer::index(self);
        DTlsBuffer::push_u16_be(self, 0)?;

        Ok(AllocU16Handle { index })
    }

    /// Allocate the space for a `u24` for later updating.
    fn alloc_u24(&mut self) -> Result<AllocU24Handle, ()> {
        let index = DTlsBuffer::index(self);
        DTlsBuffer::push_u24_be(self, U24::new(0))?;

        Ok(AllocU24Handle { index })
    }

    /// Allocate the space for a `u48` for later updating.
    fn alloc_u48(&mut self) -> Result<AllocU48Handle, ()> {
        let index = DTlsBuffer::index(self);
        DTlsBuffer::push_u48_be(self, U48::new(0))?;

        Ok(AllocU48Handle { index })
    }

    /// Allocate space for a slice for later updating.
    fn alloc_slice(&mut self, len: usize) -> Result<AllocSliceHandle, ()> {
        let index = DTlsBuffer::index(self);

        for _ in 0..len {
            DTlsBuffer::push_u8(self, 0)?;
        }

        Ok(AllocSliceHandle { index, len })
    }
}

/// Handle to an allocated `u8` spot in a `DTlsBuffer`.
#[must_use]
pub struct AllocU8Handle {
    index: usize,
}

impl AllocU8Handle {
    /// Set the value.
    pub fn set(self, buf: &mut impl DTlsBuffer, val: u8) {
        buf[self.index] = val;
        core::mem::forget(self);
    }
}

impl Drop for AllocU8Handle {
    fn drop(&mut self) {
        panic!("Alloc handle dropped without being used!");
    }
}

/// Handle to an allocated `u16` spot in a `DTlsBuffer`.
#[must_use]
pub struct AllocU16Handle {
    index: usize,
}

impl AllocU16Handle {
    /// Set the value.
    pub fn set(self, buf: &mut impl DTlsBuffer, val: u16) {
        buf[self.index..self.index + 2].copy_from_slice(&val.to_be_bytes());
        core::mem::forget(self);
    }
}

impl Drop for AllocU16Handle {
    fn drop(&mut self) {
        panic!("Alloc handle dropped without being used!");
    }
}

/// Handle to an allocated `u24` spot in a `DTlsBuffer`.
#[must_use]
pub struct AllocU24Handle {
    index: usize,
}

impl AllocU24Handle {
    /// Set the value.
    pub fn set(self, buf: &mut impl DTlsBuffer, val: U24) {
        buf[self.index..self.index + 3].copy_from_slice(&val.to_be_bytes());
        core::mem::forget(self);
    }
}

impl Drop for AllocU24Handle {
    fn drop(&mut self) {
        panic!("Alloc handle dropped without being used!");
    }
}

/// Handle to an allocated `u48` spot in a `DTlsBuffer`.
#[must_use]
pub struct AllocU48Handle {
    index: usize,
}

impl AllocU48Handle {
    /// Set the value.
    pub fn set(self, buf: &mut impl DTlsBuffer, val: U48) {
        buf[self.index..self.index + 6].copy_from_slice(&val.to_be_bytes());
        core::mem::forget(self);
    }
}

impl Drop for AllocU48Handle {
    fn drop(&mut self) {
        panic!("Alloc handle dropped without being used!");
    }
}

/// Handle to an allocated slice in a `DTlsBuffer`.
#[must_use]
pub struct AllocSliceHandle {
    index: usize,
    len: usize,
}

impl AllocSliceHandle {
    /// Set the value.
    pub fn set(self, buf: &mut impl DTlsBuffer, val: &[u8]) {
        buf[self.index..self.index + self.len].copy_from_slice(val);
        core::mem::forget(self);
    }
}

impl Drop for AllocSliceHandle {
    fn drop(&mut self) {
        panic!("Alloc handle dropped without being used!");
    }
}

#[cfg(test)]
mod tests {
    use super::slice_buffer::SliceBuffer;
    use crate::buffer::DTlsBuffer;

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

        buf.push_u8(14).unwrap();
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
}
