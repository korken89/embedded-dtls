pub use crypto_buffer::*;
pub use encoding_buffer::*;
pub use parse_buffer::*;

mod crypto_buffer {
    use aead::{Buffer, Error};
    use defmt_or_log::derive_format_or_debug;

    /// Buffer for encrypting and decrypting records that implements `aead::Buffer`, so it works
    /// with existing AEAD traits.
    #[derive_format_or_debug]
    #[derive(PartialEq, Eq)]
    pub struct CryptoBuffer<'a> {
        data: &'a mut [u8],
        idx: usize,
    }

    impl<'a> CryptoBuffer<'a> {
        /// Create a new crypt buffer.
        pub fn new(buf: &'a mut [u8]) -> Self {
            let idx = buf.len();
            Self { data: buf, idx }
        }
    }

    impl<'a> AsRef<[u8]> for CryptoBuffer<'a> {
        #[inline(always)]
        fn as_ref(&self) -> &[u8] {
            &self.data[..self.idx]
        }
    }

    impl<'a> AsMut<[u8]> for CryptoBuffer<'a> {
        #[inline(always)]
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.data[..self.idx]
        }
    }

    impl<'a> Buffer for CryptoBuffer<'a> {
        fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
            self.data
                .get_mut(self.idx..self.idx + other.len())
                .ok_or(Error)?
                .copy_from_slice(other);
            self.idx += other.len();

            Ok(())
        }

        fn truncate(&mut self, len: usize) {
            self.idx = len;
        }
    }
}

mod parse_buffer {
    use crate::integers::{U24, U48};
    use defmt_or_log::derive_format_or_debug;

    /// Buffer for helping parsing of records.
    #[derive_format_or_debug]
    #[derive(Clone, PartialEq, Eq)]
    pub struct ParseBuffer<'a> {
        data: &'a [u8],
    }

    impl<'a> AsRef<[u8]> for ParseBuffer<'a> {
        fn as_ref(&self) -> &[u8] {
            self.data
        }
    }

    impl<'a> ParseBuffer<'a> {
        /// Get the length of the data.
        pub fn len(&self) -> usize {
            self.data.len()
        }

        /// Get the current position as a pointer without popping.
        pub fn current_pos_ptr(&self) -> usize {
            self.data.as_ptr() as usize
        }

        /// Create a new parse buffer.
        pub fn new(data: &'a [u8]) -> Self {
            Self { data }
        }

        /// Check if the parse buffer is empty.
        pub fn is_empty(&self) -> bool {
            self.data.is_empty()
        }

        /// Pop the rest of the buffer.
        pub fn pop_rest(&mut self) -> &'a [u8] {
            let r = self.data;
            self.data = &[];
            r
        }

        /// Pop a byte.
        pub fn pop_u8(&mut self) -> Option<u8> {
            let r = *self.data.first()?;
            self.data = &self.data[1..];
            Some(r)
        }

        /// Pop a big-endian u16.
        pub fn pop_u16_be(&mut self) -> Option<u16> {
            let r = u16::from_be_bytes(self.data.get(0..2)?.try_into().unwrap());
            self.data = &self.data[2..];
            Some(r)
        }

        /// Pop a big-endian u24.
        pub fn pop_u24_be(&mut self) -> Option<U24> {
            let r = U24::from_be_bytes(self.data.get(0..3)?.try_into().unwrap());
            self.data = &self.data[3..];
            Some(r)
        }

        /// Pop a big-endian u32.
        pub fn pop_u32_be(&mut self) -> Option<u32> {
            let r = u32::from_be_bytes(self.data.get(0..4)?.try_into().unwrap());
            self.data = &self.data[4..];
            Some(r)
        }

        /// Pop a big-endian u48.
        pub fn pop_u48_be(&mut self) -> Option<U48> {
            let r = U48::from_be_bytes(self.data.get(0..6)?.try_into().unwrap());
            self.data = &self.data[6..];
            Some(r)
        }

        /// Pop a big-endian u64.
        pub fn pop_u64_be(&mut self) -> Option<u64> {
            let r = u64::from_be_bytes(self.data.get(0..8)?.try_into().unwrap());
            self.data = &self.data[8..];
            Some(r)
        }

        /// Pop a slice.
        pub fn pop_slice(&mut self, size: usize) -> Option<&'a [u8]> {
            let r = &self.data.get(..size)?;
            self.data = &self.data[size..];
            Some(r)
        }
    }

    #[cfg(test)]
    mod test {
        use super::ParseBuffer;
        use crate::integers::{U24, U48};
        use defmt_or_log::unwrap;

        #[test]
        fn pop() {
            let data = &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
            ];

            let mut pb = ParseBuffer::new(data);

            assert_eq!(unwrap!(pb.pop_u8()), 0);
            assert_eq!(unwrap!(pb.pop_u16_be()), 0x0102);
            assert_eq!(unwrap!(pb.pop_u24_be()), U24::new(0x030405));
            assert_eq!(unwrap!(pb.pop_u32_be()), 0x06070809);
            assert_eq!(unwrap!(pb.pop_u48_be()), U48::new(0x0a0b0c0d0e0f));
            assert_eq!(unwrap!(pb.pop_slice(3)), &[16, 17, 18]);
            assert_eq!(pb.pop_rest(), &[19, 20, 21]);
        }
    }
}

mod encoding_buffer {
    use crate::integers::{U24, U48};
    use core::{
        fmt,
        ops::{Deref, DerefMut, Range},
    };
    use defmt_or_log::derive_format_or_debug;

    /// Out of memory error.
    #[derive_format_or_debug]
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub struct OutOfMemory;

    /// A buffer handler wrapping a mutable slice.
    pub struct EncodingBuffer<'a> {
        buf: &'a mut [u8],
        idx: usize,
        write_back: Option<&'a mut usize>,
    }

    impl<'a> fmt::Debug for EncodingBuffer<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "EncodingBuffer (idx = {}, capacity = {}) {:02x?}",
                self.idx,
                self.buf.len(),
                &self.buf[..self.idx]
            )
        }
    }

    impl<'a> Drop for EncodingBuffer<'a> {
        fn drop(&mut self) {
            if let Some(write_back) = self.write_back.take() {
                *write_back += self.idx;
            }
        }
    }

    impl<'a> EncodingBuffer<'a> {
        /// Create new buffer from a slice.
        pub fn new(buf: &'a mut [u8]) -> Self {
            Self {
                buf,
                idx: 0,
                write_back: None,
            }
        }

        /// Create a new buffer from an existing one, borrowing the rest of the buffer.
        ///
        /// When this is dropped the original buffer can be used again.
        pub fn new_from_existing(&mut self) -> EncodingBuffer {
            EncodingBuffer {
                buf: &mut self.buf[self.idx..],
                idx: 0,
                write_back: Some(&mut self.idx),
            }
        }

        /// Reset the state of the buffer
        pub fn reset(&mut self) {
            self.idx = 0;
        }

        /// Current length of the buffer.
        pub fn len(&self) -> usize {
            self.idx
        }

        /// Capacity of the buffer.
        pub fn capacity(&self) -> usize {
            self.buf.len()
        }

        /// Get the space left in the buffer.
        pub fn space_left(&self) -> usize {
            self.capacity() - self.len()
        }

        /// Current index of the buffer.
        pub fn index(&self) -> usize {
            self.idx
        }

        /// Get the current position as a pointer without popping.
        pub fn current_pos_ptr(&self) -> usize {
            self.buf.as_ptr() as usize + self.idx
        }

        /// Extend with a slice.
        pub fn extend_from_slice(&mut self, slice: &[u8]) -> Result<(), OutOfMemory> {
            self.buf
                .get_mut(self.idx..self.idx + slice.len())
                .ok_or(OutOfMemory)?
                .copy_from_slice(slice);
            self.idx += slice.len();

            Ok(())
        }

        /// Push a u8.
        pub fn push_u8(&mut self, val: u8) -> Result<(), OutOfMemory> {
            *self.buf.get_mut(self.idx).ok_or(OutOfMemory)? = val;
            self.idx += 1;

            Ok(())
        }

        /// Push a u16 in big-endian.
        pub fn push_u16_be(&mut self, val: u16) -> Result<(), OutOfMemory> {
            self.extend_from_slice(&val.to_be_bytes())
        }

        /// Push a u24 in big-endian.
        pub fn push_u24_be(&mut self, val: U24) -> Result<(), OutOfMemory> {
            self.extend_from_slice(&val.to_be_bytes())
        }

        /// Push a u32 in big-endian.
        pub fn push_u32_be(&mut self, val: u32) -> Result<(), OutOfMemory> {
            self.extend_from_slice(&val.to_be_bytes())
        }

        /// Push a u48 in big-endian.
        pub fn push_u48_be(&mut self, val: U48) -> Result<(), OutOfMemory> {
            self.extend_from_slice(&val.to_be_bytes())
        }

        /// Push a u64 in big-endian.
        pub fn push_u64_be(&mut self, val: u64) -> Result<(), OutOfMemory> {
            self.extend_from_slice(&val.to_be_bytes())
        }

        /// Allocate the space for a `u8` for later updating.
        pub fn alloc_u8(&mut self) -> Result<AllocU8Handle, OutOfMemory> {
            let index = self.index();
            self.push_u8(0)?;

            Ok(AllocU8Handle { index })
        }

        /// Allocate the space for a `u16` for later updating.
        pub fn alloc_u16(&mut self) -> Result<AllocU16Handle, OutOfMemory> {
            let index = self.index();
            self.push_u16_be(0)?;

            Ok(AllocU16Handle { index })
        }

        /// Allocate the space for a `u24` for later updating.
        pub fn alloc_u24(&mut self) -> Result<AllocU24Handle, OutOfMemory> {
            let index = self.index();
            self.push_u24_be(U24::new(0))?;

            Ok(AllocU24Handle { index })
        }

        /// Allocate the space for a `u48` for later updating.
        pub fn alloc_u48(&mut self) -> Result<AllocU48Handle, OutOfMemory> {
            let index = self.index();
            self.push_u48_be(U48::new(0))?;

            Ok(AllocU48Handle { index })
        }

        /// Allocate space for a slice for later updating.
        pub fn alloc_slice(&mut self, len: usize) -> Result<AllocSliceHandle, OutOfMemory> {
            let index = self.index();

            for _ in 0..len {
                self.push_u8(0)?;
            }

            Ok(AllocSliceHandle { index, len })
        }
    }

    impl<'a> Deref for EncodingBuffer<'a> {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            self.buf.get(..self.idx).unwrap_or(&[])
        }
    }

    impl<'a> DerefMut for EncodingBuffer<'a> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            self.buf.get_mut(..self.idx).unwrap_or(&mut [])
        }
    }

    impl<'a> AsRef<[u8]> for EncodingBuffer<'a> {
        fn as_ref(&self) -> &[u8] {
            self.deref()
        }
    }

    /// Handle to an allocated `u8` spot in a `Buffer`.
    #[derive_format_or_debug]
    #[must_use]
    pub struct AllocU8Handle {
        index: usize,
    }

    impl AllocU8Handle {
        /// Set the value.
        pub fn set(self, buf: &mut EncodingBuffer, val: u8) {
            buf.buf[self.index] = val;
            core::mem::forget(self);
        }

        /// The position of the data in the encoding buffer.
        pub fn at(&self) -> Range<usize> {
            let start = self.index;
            start..start + 1
        }
    }

    impl Drop for AllocU8Handle {
        fn drop(&mut self) {
            panic!("Alloc handle dropped without being used!");
        }
    }

    /// Handle to an allocated `u16` spot in a `Buffer`.
    #[derive_format_or_debug]
    #[must_use]
    pub struct AllocU16Handle {
        index: usize,
    }

    impl AllocU16Handle {
        /// Set the value.
        pub fn set(self, buf: &mut EncodingBuffer, val: u16) {
            buf.buf[self.index..self.index + 2].copy_from_slice(&val.to_be_bytes());
            core::mem::forget(self);
        }

        /// The position of the data in the encoding buffer.
        pub fn at(&self) -> Range<usize> {
            let start = self.index;
            start..start + 2
        }
    }

    impl Drop for AllocU16Handle {
        fn drop(&mut self) {
            panic!("Alloc handle dropped without being used!");
        }
    }

    /// Handle to an allocated `u24` spot in a `Buffer`.
    #[derive_format_or_debug]
    #[must_use]
    pub struct AllocU24Handle {
        index: usize,
    }

    impl AllocU24Handle {
        /// Set the value.
        pub fn set(self, buf: &mut EncodingBuffer, val: U24) {
            buf.buf[self.index..self.index + 3].copy_from_slice(&val.to_be_bytes());
            core::mem::forget(self);
        }

        /// The position of the data in the encoding buffer.
        pub fn at(&self) -> Range<usize> {
            let start = self.index;
            start..start + 3
        }
    }

    impl Drop for AllocU24Handle {
        fn drop(&mut self) {
            panic!("Alloc handle dropped without being used!");
        }
    }

    /// Handle to an allocated `u48` spot in a `Buffer`.
    #[derive_format_or_debug]
    #[must_use]
    pub struct AllocU48Handle {
        index: usize,
    }

    impl AllocU48Handle {
        /// Set the value.
        pub fn set(self, buf: &mut EncodingBuffer, val: U48) {
            buf.buf[self.index..self.index + 6].copy_from_slice(&val.to_be_bytes());
            core::mem::forget(self);
        }

        /// The position of the data in the encoding buffer.
        pub fn at(&self) -> Range<usize> {
            let start = self.index;
            start..start + 6
        }
    }

    impl Drop for AllocU48Handle {
        fn drop(&mut self) {
            panic!("Alloc handle dropped without being used!");
        }
    }

    /// Handle to an allocated slice in a `Buffer`.
    #[derive_format_or_debug]
    #[must_use]
    pub struct AllocSliceHandle {
        index: usize,
        len: usize,
    }

    impl AllocSliceHandle {
        /// The the slice from buffer that is everything up until this allocation starts.
        pub fn slice_up_until<'a>(&'a self, buf: &'a EncodingBuffer) -> &'a [u8] {
            buf.buf.get(..self.index).unwrap_or(&[])
        }

        /// Set the value.
        pub fn set(self, buf: &mut EncodingBuffer, val: &[u8]) {
            buf.buf
                .get_mut(self.index..self.index + self.len)
                .unwrap_or(&mut [])
                .copy_from_slice(val);
            core::mem::forget(self);
        }

        /// Fill the slice with the value.
        pub fn fill(self, buf: &mut EncodingBuffer, val: u8) {
            buf.buf
                .get_mut(self.index..self.index + self.len)
                .unwrap_or(&mut [])
                .fill(val);
            core::mem::forget(self);
        }

        /// Get the underlying buffer and manually set it.
        pub fn into_buffer<'a>(self, buf: &'a mut EncodingBuffer) -> &'a mut [u8] {
            let r = buf
                .buf
                .get_mut(self.index..self.index + self.len)
                .unwrap_or(&mut []);
            core::mem::forget(self);

            r
        }

        /// The position of the data in the encoding buffer.
        pub fn at(&self) -> Range<usize> {
            let start = self.index;
            start..start + self.len
        }

        /// Get the start position as a pointer.
        pub fn start_pos_ptr(&self, buf: &mut EncodingBuffer) -> Option<usize> {
            Some(buf.buf.get_mut(self.index)? as *mut u8 as usize)
        }
    }

    impl Drop for AllocSliceHandle {
        fn drop(&mut self) {
            panic!("Alloc handle dropped without being used!");
        }
    }

    #[cfg(test)]
    mod tests {
        use super::EncodingBuffer;

        #[test]
        fn push() {
            let mut buf = [0; 128];
            let mut buf = EncodingBuffer::new(&mut buf);

            assert_eq!(buf.len(), 0);

            buf.push_u8(11).unwrap();
            buf.push_u8(12).unwrap();
            buf.push_u8(13).unwrap();
            assert_eq!(buf[0], 11);
            assert_eq!(buf[1], 12);
            assert_eq!(buf[2], 13);

            {
                let mut buf2 = buf.new_from_existing();

                assert_eq!(buf2.len(), 0);

                println!("buf: {buf2:?}");
                buf2.push_u8(14).unwrap();
                println!("buf: {buf2:?}");
                assert_eq!(buf2[0], 14);

                drop(buf2);
            }

            assert_eq!(buf[0], 11);
            assert_eq!(buf[1], 12);
            assert_eq!(buf[2], 13);
            assert_eq!(buf[3], 14);

            {
                let mut buf2 = buf.new_from_existing();

                buf2.extend_from_slice(&[1, 2, 3, 4]).unwrap();
                assert_eq!(buf2[..4], [1, 2, 3, 4]);

                drop(buf2);
            }
            assert_eq!(buf[..], [11, 12, 13, 14, 1, 2, 3, 4]);
        }

        #[test]
        fn alloc() {
            let mut buf = [0; 128];
            let mut buf = EncodingBuffer::new(&mut buf);

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
            let mut buf = EncodingBuffer::new(&mut buf);

            buf.extend_from_slice(&[1, 2, 3, 4, 5]).unwrap();
            let a = buf.alloc_slice(3).unwrap();

            assert_eq!(a.slice_up_until(&buf), [1, 2, 3, 4, 5]);
            assert_eq!(buf.len(), 8);

            a.set(&mut buf, &[1, 2, 3]);

            println!("buf: {buf:?}");
            assert_eq!(buf[..], [1, 2, 3, 4, 5, 1, 2, 3]);

            {
                let mut buf2 = buf.new_from_existing();
                println!("buf: {buf2:?}");
                let a = buf2.alloc_slice(3).unwrap();
                println!("a: {a:?}");
                assert_eq!(a.slice_up_until(&buf2), []);

                a.set(&mut buf2, &[4, 5, 6]);
            }
        }
    }
}
