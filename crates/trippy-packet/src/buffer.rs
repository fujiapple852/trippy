use bytemuck::{Pod, Zeroable};

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

#[cfg(test)]
mod tests {
    use super::*;
    use bytemuck::{Pod, Zeroable};

    #[derive(Debug, Copy, Clone, Pod, Zeroable)]
    #[repr(C)]
    struct TestStruct {
        a: u8,
        b: u16,
        c: u32,
    }

    #[test]
    fn test_immutable_buffer() {
        let buf = [0_u8; 5];
        let buffer = Buffer::Immutable(&buf);
        assert_eq!(buf.as_slice(), buffer.as_slice());
        assert_eq!(buf, buffer.get_bytes(0));
        assert_eq!(0_u8, buffer.read(0));
    }

    #[test]
    fn test_mutable_buffer() {
        let mut buf = [0_u8; 5];
        let mut buffer = Buffer::Mutable(&mut buf);
        assert_eq!(&[0_u8; 5], buffer.as_slice());
        assert_eq!([0_u8; 5], buffer.get_bytes(0));
        assert_eq!(0_u8, buffer.read(0));
        buffer.set_bytes(1, [1_u8; 4]);
        assert_eq!([1_u8; 4], buffer.get_bytes(1));
        *buffer.write(0) = 2;
        assert_eq!(2_u8, buffer.read(0));
        buffer.as_slice_mut().copy_from_slice(&[3_u8; 5]);
        assert_eq!(&[3_u8; 5], buffer.as_slice());
    }

    #[test]
    fn test_debug() {
        let buf = [0_u8; 5];
        let buffer = Buffer::Immutable(&buf);
        assert_eq!(
            String::from("Immutable([0, 0, 0, 0, 0])"),
            format!("{buffer:?}")
        );
        let mut buf = [0_u8; 5];
        let buffer = Buffer::Mutable(&mut buf);
        assert_eq!(
            String::from("Mutable([0, 0, 0, 0, 0])"),
            format!("{buffer:?}")
        );
    }

    #[test]
    #[should_panic(expected = "write operation called on readonly buffer")]
    fn test_immutable_buffer_cannot_write() {
        let buf = [0_u8; 5];
        let mut buffer = Buffer::Immutable(&buf);
        buffer.set_bytes(0, [1_u8; 5]);
    }

    #[test]
    #[should_panic(expected = "write operation called on readonly buffer")]
    fn test_immutable_buffer_cannot_mut_slice() {
        let buf = [0_u8; 5];
        let mut buffer = Buffer::Immutable(&buf);
        buffer.as_slice_mut();
    }

    #[test]
    fn test_pod_struct() {
        let mut buf = [0_u8; 7];
        let mut buffer = Buffer::Mutable(&mut buf);
        let test_struct = TestStruct { a: 1, b: 2, c: 3 };
        buffer.set_bytes(0, bytemuck::cast(test_struct));
        let read_struct: TestStruct = bytemuck::cast(buffer.get_bytes(0));
        assert_eq!(test_struct, read_struct);
    }
}
