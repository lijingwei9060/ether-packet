#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct U16 {
    octets: [u8; 2],
}

impl U16 {
    pub const fn new(a: u8, b: u8) -> Self {
        Self { octets: [a, b] }
    }

    /// Converts an U16 into a `u16` representation using native byte order.
    ///
    /// Although U16 are big-endian, the `u16` value will use the target platform's
    /// native byte order. That is, the `u16` value is an integer.
    #[inline]
    pub const fn to_bits(self) -> u16 {
        u16::from_be_bytes(self.octets)
    }

    /// Converts a native byte order `u16` into an U16.
    #[inline]
    pub const fn from_bits(bits: u16) -> U16 {
        U16 {
            octets: bits.to_be_bytes(),
        }
    }

    /// Returns the two eight-bit integers.
    #[inline]
    pub const fn octets(&self) -> [u8; 2] {
        self.octets
    }
}

impl From<u16> for U16 {
    fn from(value: u16) -> Self {
        Self::from_bits(value)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct U32 {
    octets: [u8; 4],
}

impl U32 {
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self {
            octets: [a, b, c, d],
        }
    }

    /// Converts an U32 into a `u32` representation using native byte order.
    ///
    /// Although U32 are big-endian, the `u32` value will use the target platform's
    /// native byte order. That is, the `u32` value is an integer.
    #[inline]
    pub const fn to_bits(self) -> u32 {
        u32::from_be_bytes(self.octets)
    }

    /// Converts a native byte order `u32` into an U32.
    #[inline]
    pub const fn from_bits(bits: u32) -> U32 {
        U32 {
            octets: bits.to_be_bytes(),
        }
    }

    /// Returns the four eight-bit integers.
    #[inline]
    pub const fn octets(&self) -> [u8; 4] {
        self.octets
    }
}

impl From<u32> for U32 {
    fn from(value: u32) -> Self {
        Self::from_bits(value)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Default)]
pub struct U64 {
    octets: [u8; 8],
}

impl U64 {
    pub const fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8, g: u8, h: u8) -> Self {
        Self {
            octets: [a, b, c, d, e, f, g, g],
        }
    }

    /// Converts an U64 into a `u64` representation using native byte order.
    ///
    /// Although U64 are big-endian, the `u64` value will use the target platform's
    /// native byte order. That is, the `u64` value is an integer.
    #[inline]
    pub const fn to_bits(self) -> u64 {
        u64::from_be_bytes(self.octets)
    }

    /// Converts a native byte order `u64` into an U64.
    #[inline]
    pub const fn from_bits(bits: u64) -> U64 {
        U64 {
            octets: bits.to_be_bytes(),
        }
    }

    /// Returns the eight eight-bit integers.
    #[inline(always)]
    pub const fn octets(&self) -> [u8; 8] {
        self.octets
    }
}

impl From<u64> for U64 {
    fn from(value: u64) -> Self {
        Self::from_bits(value)
    }
}
