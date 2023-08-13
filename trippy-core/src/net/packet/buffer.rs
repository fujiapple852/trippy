/// A byte buffer that holds a mutable or immutable byte slice.
#[derive(Debug)]
pub enum Buffer<'a> {
    Immutable(&'a [u8]),
    Mutable(&'a mut [u8]),
}

impl<'a> Buffer<'a> {
    /// access the buffer as an immutable slice of bytes.
    pub fn as_slice(&self) -> &[u8] {
        match &self {
            Buffer::Immutable(packet) => packet,
            Buffer::Mutable(packet) => packet,
        }
    }

    /// Get N bytes from the packet at a given byte offset.
    pub fn get_bytes<const N: usize>(&self, offset: usize) -> [u8; N] {
        core::array::from_fn(|i| self.read(offset + i))
    }

    /// Set N bytes in the packet at a given offset.
    pub fn set_bytes<const N: usize>(&mut self, offset: usize, bytes: [u8; N]) {
        for (i, b) in bytes.into_iter().enumerate() {
            *self.write(offset + i) = b;
        }
    }

    /// Get the value at a given offset.
    pub fn read(&self, offset: usize) -> u8 {
        match &self {
            Buffer::Immutable(packet) => packet[offset],
            Buffer::Mutable(packet) => packet[offset],
        }
    }

    /// Set the value at a given offset.
    pub fn write(&mut self, offset: usize) -> &mut u8 {
        match self {
            Buffer::Immutable(_) => panic!("write operation called on readonly buffer"),
            Buffer::Mutable(packet) => &mut packet[offset],
        }
    }

    /// access the buffer as a mutable slice of bytes.
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        match self {
            Buffer::Immutable(_) => panic!("write operation called on readonly buffer"),
            Buffer::Mutable(packet) => packet,
        }
    }
}
