use core::{mem, net::Ipv6Addr};

use crate::{bitfield::BitfieldUnit, types::U16};

use super::IpProto;


#[repr(C, packed)]
#[derive(Copy, Clone)]
#[cfg_attr(features = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Ipv6Hdr {
    pub _bitfield_align_1: [u8; 0],
    /// Version (4-bits): Indicates version of Internet Protocol which contains bit sequence 0110.
    /// Traffic Class (8-bits): The Traffic Class field indicates class or priority of IPv6 packet which is similar to Service Field in IPv4 packet.
    /// It helps routers to handle the traffic based on the priority of the packet. If congestion occurs on the router then packets with the least priority will be discarded.
    /// As of now, only 4-bits are being used (and the remaining bits are under research), in which 0 to 7 are assigned to Congestion controlled traffic and 8 to 15 are assigned to Uncontrolled traffic.
    pub _bitfield_1: BitfieldUnit<[u8; 1usize]>,
    /// Flow Label (20-bits): Flow Label field is used by a source to label the packets belonging to the same flow
    /// in order to request special handling by intermediate IPv6 routers, such as non-default quality of service or
    /// real-time service. In order to distinguish the flow, an intermediate router can use the source address,
    /// a destination address, and flow label of the packets. Between a source and destination, multiple flows
    /// may exist because many processes might be running at the same time. Routers or Host that does not support the
    /// functionality of flow label field and for default router handling, flow label field is set to 0. While setting up
    /// the flow label, the source is also supposed to specify the lifetime of the flow.
    pub flow_label: [u8; 3usize],
    /// Payload Length (16-bits): It is a 16-bit (unsigned integer) field, indicates the total size of the payload which
    /// tells routers about the amount of information a particular packet contains in its payload. The payload Length field
    /// includes extension headers(if any) and an upper-layer packet. In case the length of the payload is greater
    /// than 65,535 bytes (payload up to 65,535 bytes can be indicated with 16-bits), then the payload length field
    /// will be set to 0 and the jumbo payload option is used in the Hop-by-Hop options extension header.
    pub payload_len: U16,
    /// Next Header (8-bits): Next Header indicates the type of extension header(if present) immediately following the IPv6
    /// header. Whereas In some cases it indicates the protocols contained within upper-layer packets, such as TCP, UDP.
    pub next_hdr: IpProto,
    /// Hop Limit (8-bits): Hop Limit field is the same as TTL in IPv4 packets. It indicates the maximum number of intermediate
    /// nodes IPv6 packet is allowed to travel. Its value gets decremented by one, by each node that forwards the packet and the
    /// packet is discarded if the value decrements to 0. This is used to discard the packets that are stuck in an infinite loop
    /// because of some routing error.
    pub hop_limit: u8,
    /// Source Address (128-bits): Source Address is the 128-bit IPv6 address of the original source of the packet.
    pub src_addr: Ipv6Addr,
    /// Destination Address (128-bits): The destination Address field indicates the IPv6 address of the final destination(in most cases).
    /// All the intermediate nodes can use this information in order to correctly route the packet.
    pub dst_addr: Ipv6Addr,
    // Extension Headers: In order to rectify the limitations of the IPv4 Option Field, Extension Headers are introduced in IP version 6.
    // The extension header mechanism is a very important part of the IPv6 architecture. The next Header field of IPv6 fixed header points
    // to the first Extension Header and this first extension header points to the second extension header and so on.
}

impl Ipv6Hdr {
    pub const LEN: usize = mem::size_of::<Ipv6Hdr>();

    #[inline]
    pub fn priority(&self) -> u8 {
        unsafe { mem::transmute(self._bitfield_1.get(0usize, 4u8) as u8) }
    }

    #[inline]
    pub fn set_priority(&mut self, val: u8) {
        unsafe {
            let val: u8 = mem::transmute(val);
            self._bitfield_1.set(0usize, 4u8, val as u64)
        }
    }

    #[inline]
    pub fn version(&self) -> u8 {
        unsafe { mem::transmute(self._bitfield_1.get(4usize, 4u8) as u8) }
    }

    #[inline]
    pub fn set_version(&mut self, val: u8) {
        unsafe {
            let val: u8 = mem::transmute(val);
            self._bitfield_1.set(4usize, 4u8, val as u64)
        }
    }

    #[inline]
    pub fn new_bitfield_1(priority: u8, version: u8) -> BitfieldUnit<[u8; 1usize]> {
        let mut bitfield_unit: BitfieldUnit<[u8; 1usize]> = Default::default();
        bitfield_unit.set(0usize, 4u8, {
            let priority: u8 = unsafe { mem::transmute(priority) };
            priority as u64
        });
        bitfield_unit.set(4usize, 4u8, {
            let version: u8 = unsafe { mem::transmute(version) };
            version as u64
        });
        bitfield_unit
    }
}


#[cfg(test)]
mod test{
  
  #[test]
  fn test_v6() {
      use core::mem;
      use core::net::Ipv6Addr;

      use crate::ip::Ipv6Hdr;

      let expected_header_bytes = [
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
      ];

      let ipv6_header: Ipv6Hdr = unsafe {
          mem::transmute::<[u8; Ipv6Hdr::LEN], _>(expected_header_bytes.try_into().unwrap())
      };
      assert_eq!(ipv6_header.src_addr, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
      assert_eq!(ipv6_header.dst_addr, Ipv6Addr::new(2, 0, 0, 0, 0, 0, 0, 1));

      let mut header_bytes = [0u8; 40];
      let ipv6_header: *mut Ipv6Hdr = &mut header_bytes as *mut _ as *mut _;
      unsafe {
          (*ipv6_header).src_addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
          (*ipv6_header).dst_addr = Ipv6Addr::new(2, 0, 0, 0, 0, 0, 0, 1);
      }

      let ipv6_header: Ipv6Hdr =
          unsafe { mem::transmute::<[u8; Ipv6Hdr::LEN], _>(header_bytes.try_into().unwrap()) };
      assert_eq!(ipv6_header.src_addr, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
      assert_eq!(ipv6_header.dst_addr, Ipv6Addr::new(2, 0, 0, 0, 0, 0, 0, 1));

      assert_eq!(expected_header_bytes, header_bytes);
  }

}