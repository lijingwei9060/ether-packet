use core::mem;

use crate::{bitfield::BitfieldUnit, types::U16};

/// Protocol which is encapsulated in the payload of the Ethernet frame.
///
/// According [EtherType](https://en.wikipedia.org/wiki/EtherType)
#[repr(u16)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum EtherType {
    Loop = 0x0060,
    Ipv4 = 0x0800,
    Arp = 0x0806,
    /// wake on lan
    WakeOnLan = 0x0842,
    /// Cisco Discovery Protocol
    CDP = 0x2000,
    /// Stream Reservation Protocol
    SRP = 0x22EA,
    /// Audio Video Transport Protocol
    AVTP = 0x22F0,
    /// IETF TRILL Protocol
    TRILL = 0x22F3,
    /// DEC MOP RC
    MOP = 0x6002,
    /// DECnet Phase IV, DNA Routing
    DECnet = 0x6003,
    DECLAT = 0x6004,
    /// Reverse Address Resolution Protocol
    RARP = 0x8035,
    AppleTalk = 0x809B,
    /// AppleTalk Address Resolution Protocol
    AARP = 0x80F3,
    /// VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility
    VLAN = 0x8100,
    /// Simple Loop Prevention Protocol
    SLPP = 0x8102,
    /// Virtual Link Aggregation Control Protocol
    VLACP = 0x8103,
    /// Internet Protocol Version 6
    Ipv6 = 0x86DD,
    MPLSUnicast = 0x8847,
    MPLSMulticast = 0x8848,
    /// Ethernet Slow Protocols such as the Link Aggregation Control Protocol (LACP)
    LACP = 0x8809,
    /// Service VLAN tag identifier (S-Tag) on Q-in-Q tunnel
    QinQ = 0x88A8,
    /// Link Layer Discovery Protocol
    LLDP = 0x88CC,
    FibreChannel = 0x8906,
    /// RDMA over Converged Ethernet (RoCE)
    RoCE = 0x8915,
    LoopbackIeee8023 = 0x9000,
}

impl TryFrom<u16> for EtherType {
    type Error = ();
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0060 => Ok(EtherType::Loop),
            0x0800 => Ok(EtherType::Ipv4),
            0x0806 => Ok(EtherType::Arp),
            0x0842 => Ok(EtherType::WakeOnLan),
            0x2000 => Ok(EtherType::CDP),
            0x22EA => Ok(EtherType::SRP),
            0x22F0 => Ok(EtherType::AVTP),
            0x22F3 => Ok(EtherType::TRILL),
            0x6002 => Ok(EtherType::MOP),
            0x6003 => Ok(EtherType::DECnet),
            0x6004 => Ok(EtherType::DECLAT),
            0x8035 => Ok(EtherType::RARP),
            0x809B => Ok(EtherType::AppleTalk),
            0x80F3 => Ok(EtherType::AARP),
            0x8100 => Ok(EtherType::VLAN),
            0x8102 => Ok(EtherType::SLPP),
            0x8103 => Ok(EtherType::VLACP),
            0x86DD => Ok(EtherType::Ipv6),
            0x8847 => Ok(EtherType::MPLSUnicast),
            0x8848 => Ok(EtherType::MPLSMulticast),
            0x8809 => Ok(EtherType::LACP),
            0x88A8 => Ok(EtherType::QinQ),
            0x88CC => Ok(EtherType::LLDP),
            0x8906 => Ok(EtherType::FibreChannel),
            0x8915 => Ok(EtherType::RoCE),
            0x9000 => Ok(EtherType::LoopbackIeee8023),
            _ => Err(()),
        }
    }
}

impl Default  for EtherType{
    fn default() -> Self {
        EtherType::Ipv4
    }
}

impl TryFrom<U16> for EtherType{
    type Error = ();
    fn try_from(value: U16) -> Result<Self, Self::Error> {
        Self::try_from(value.to_bits())
    }
}

impl EtherType{
    pub fn is_vlan(&self) -> bool{
        self == &EtherType::VLAN || self == &EtherType::QinQ
    }
}


/// Ethernet header, which is present at the beginning of every Ethernet frame.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct EthHdr {
    /// Destination MAC address.
    pub dst_addr: [u8; 6],
    /// Source MAC address.
    pub src_addr: [u8; 6],
    /// Protocol which is encapsulated in the payload of the frame.
    pub ether_type: U16,
}

impl EthHdr {
    pub const LEN: usize = mem::size_of::<EthHdr>();
}


/// QinQHdr Ethernet header, which is present at the beginning of every Ethernet frame.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QinQHdr {
    /// Destination MAC address.
    pub dst_addr: [u8; 6],
    /// Source MAC address.
    pub src_addr: [u8; 6],
    pub service_tpid: u16,
    pub _bitfield_0: BitfieldUnit<[u8; 2usize]>,
    pub tpid: u16,
    pub _bitfield_1: BitfieldUnit<[u8; 2usize]>,
    /// Protocol which is encapsulated in the payload of the frame.
    pub ether_type: EtherType,
}

impl QinQHdr {
  pub const LEN: usize = mem::size_of::<QinQHdr>();
}

/// Vlan Ethernet header, which is present at the beginning of every Ethernet frame.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct VlanHdr {
    pub _bitfield_align_1: [u8; 0],
    /// tag control information
    pub tci: BitfieldUnit<[u8; 2usize]>,
    /// Protocol which is encapsulated in the payload of the frame.
    pub ether_type: EtherType,
}

impl VlanHdr {
    pub const LEN: usize = mem::size_of::<VlanHdr>();
    /// VLAN ID (VID), indicating the VLAN to which a frame belongs.
    ///
    /// 12bits
    ///
    /// The VLAN ID is in the range from 0 to 4095. The values 0 and 4095 are reserved, and therefore available VLAN IDs are in the range from 1 to 4094.
    #[inline]
    pub fn vid(&self) -> u16 {
        unsafe { mem::transmute(self.tci.get(0usize, 12u8) as u16) }
    }

    #[inline]
    pub fn set_vid(&mut self, val: u16) {
        unsafe {
            let val: u16 = mem::transmute(val);
            self.tci.set(0usize, 12u8, val as u64)
        }
    }

    /// Canonical Format Indicator (CFI), indicating whether a MAC address is encapsulated in canonical format over different transmission media.
    /// CFI is used to ensure compatibility between Ethernet and token ring networks.
    ///
    /// 1bit
    ///
    /// The value 0 indicates that the MAC address is encapsulated in canonical format,
    /// and the value 1 indicates that the MAC address is encapsulated in non-canonical format.
    /// The CFI field has a fixed value of 0 on Ethernet networks.
    #[inline]
    pub fn cfi(&self) -> u8 {
        unsafe { mem::transmute(self.tci.get(12usize, 1u8) as u8) }
    }

    #[inline]
    pub fn set_cfi(&mut self, val: u8) {
        unsafe {
            let val: u8 = mem::transmute(val);
            self.tci.set(12usize, 1u8, val as u64)
        }
    }

    /// Priority code point (PCP), indicating the 802.1p priority of a frame.
    ///
    /// 3bits
    ///
    /// The value is in the range from 0 to 7. A larger value indicates a higher priority.
    /// If congestion occurs, the switch sends packets with the highest priority first.
    #[inline]
    pub fn pcp(&self) -> u8 {
        unsafe { mem::transmute(self.tci.get(13usize, 3u8) as u8) }
    }

    #[inline]
    pub fn set_pcp(&mut self, val: u8) {
        unsafe {
            let val: u8 = mem::transmute(val);
            self.tci.set(13usize, 3u8, val as u64)
        }
    }
}

#[cfg(test)]
mod test {
    use core::mem;

    use super::EtherType;
    use super::EthHdr;

    #[test]
    fn validate_etherheader() {
        // 模拟一个以太网数据流
        let data_stream = [
            0xFF_u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 目标 MAC 地址
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // 源 MAC 地址
            0x08, 0x00, // 协议类型 (IPv4, 大端字节序)
        ];

        let ethhdr: EthHdr = unsafe {
            mem::transmute::<[u8; EthHdr::LEN], _>(data_stream.try_into().unwrap())
        };

        assert_eq!(ethhdr.ether_type.to_bits(), EtherType::Ipv4 as u16);
        assert_eq!(ethhdr.dst_addr, [0xFF_u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(ethhdr.src_addr, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }
}
