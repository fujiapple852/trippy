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

    /// Get 16 bytes from the packet at a given byte offset.
    pub fn get_bytes_16(&self, offset: usize) -> [u8; 16] {
        [
            self.read(offset),
            self.read(offset + 1),
            self.read(offset + 2),
            self.read(offset + 3),
            self.read(offset + 4),
            self.read(offset + 5),
            self.read(offset + 6),
            self.read(offset + 7),
            self.read(offset + 8),
            self.read(offset + 9),
            self.read(offset + 10),
            self.read(offset + 11),
            self.read(offset + 12),
            self.read(offset + 13),
            self.read(offset + 14),
            self.read(offset + 15),
        ]
    }

    /// Get two bytes from the packet at a given byte offset.
    pub fn get_bytes_two(&self, offset: usize) -> [u8; 2] {
        [self.read(offset), self.read(offset + 1)]
    }

    /// Get four bytes from the packet at a given byte offset.
    pub fn get_bytes_four(&self, offset: usize) -> [u8; 4] {
        [
            self.read(offset),
            self.read(offset + 1),
            self.read(offset + 2),
            self.read(offset + 3),
        ]
    }

    /// Set two bytes in the packet at a given offset.
    pub fn set_bytes_two(&mut self, offset: usize, bytes: [u8; 2]) {
        *self.write(offset) = bytes[0];
        *self.write(offset + 1) = bytes[1];
    }

    /// Set four bytes in the packet at a given offset.
    pub fn set_bytes_four(&mut self, offset: usize, bytes: [u8; 4]) {
        *self.write(offset) = bytes[0];
        *self.write(offset + 1) = bytes[1];
        *self.write(offset + 2) = bytes[2];
        *self.write(offset + 3) = bytes[3];
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
