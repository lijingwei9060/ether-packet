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
