use core::mem;

use crate::ne::NetEndian;

/// Ethernet header, which is present at the beginning of every Ethernet frame.
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct EthHdr {
    /// Destination MAC address.
    pub dst_addr: [u8; 6],
    /// Source MAC address.
    pub src_addr: [u8; 6],
    /// Protocol which is encapsulated in the payload of the frame.
    pub ether_type: NetEndian<u16>,
}

impl EthHdr {
    pub const LEN: usize = mem::size_of::<EthHdr>();
}

#[cfg(test)]
mod test {
    use core::mem;

    use crate::EtherType;

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

        assert_eq!(ethhdr.ether_type.get(), EtherType::Ipv4 as u16);
        assert_eq!(ethhdr.dst_addr, [0xFF_u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(ethhdr.src_addr, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }
}
