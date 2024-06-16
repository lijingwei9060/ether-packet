use core::{mem, net::Ipv4Addr};

use crate::{bitfield::BitfieldUnit, types::U16};

use super::IpProto;

/// IPv4 header, which is present after the Ethernet header.
///
/// [INTERNET PROTOCOL](https://datatracker.ietf.org/doc/html/rfc791)
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Version|  IHL  |Type of Service|          Total Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Identification        |Flags|      Fragment Offset    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Time to Live |    Protocol   |         Header Checksum       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Source Address                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Destination Address                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Options                    |    Padding    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Ipv4Hdr {
    /// **Version**:  4 bits
    ///
    /// The Version field indicates the format of the internet header.  This
    /// document describes version 4.  Only IPv4 uses this header so you will
    /// always find decimal value 4 here.
    ///
    /// **IHL**:  4 bits
    ///
    /// Internet Header Length is the length of the internet header in 32
    /// bit words, and thus points to the beginning of the data.  Note that
    /// the minimum value for a correct header is 5. The minimum length of
    /// an IP header is 20 bytes so with 32 bit increments, you would see
    /// value of 5 here. The maximum value we can create with 4 bits is 15
    /// so with 32 bit increments, that would be a header length of 60 bytes.
    pub _bitfield_1: BitfieldUnit<[u8; 1usize]>,

    /// **Type of Service**:  8 bits, this is used for QoS (Quality of Service).
    ///
    /// The Type of Service provides an indication of the abstract
    /// parameters of the quality of service desired.  These parameters are
    /// to be used to guide the selection of the actual service parameters
    /// when transmitting a datagram through a particular network.  Several
    /// networks offer service precedence, which somehow treats high
    /// precedence traffic as more important than other traffic (generally
    /// by accepting only traffic above a certain precedence at time of high
    /// load).  The major choice is a three way tradeoff between low-delay,
    /// high-reliability, and high-throughput.
    /// ```text
    /// Bits 0-2:  Precedence.
    /// Bit    3:  0 = Normal Delay,      1 = Low Delay.
    /// Bits   4:  0 = Normal Throughput, 1 = High Throughput.
    /// Bits   5:  0 = Normal Relibility, 1 = High Relibility.
    /// Bit  6-7:  Reserved for Future Use.
    ///
    ///    0     1     2     3     4     5     6     7
    ///  +-----+-----+-----+-----+-----+-----+-----+-----+
    ///  |                 |     |     |     |     |     |
    ///  |   PRECEDENCE    |  D  |  T  |  R  |  0  |  0  |
    ///  |                 |     |     |     |     |     |
    ///  +-----+-----+-----+-----+-----+-----+-----+-----+
    ///
    /// Precedence
    ///
    /// 111 - Network Control
    /// 110 - Internetwork Control
    /// 101 - CRITIC/ECP
    /// 100 - Flash Override
    /// 011 - Flash
    /// 010 - Immediate
    /// 001 - Priority
    /// 000 - Routine
    /// ```
    pub tos: u8,
    /// Total Length: this 16-bit field indicates the entire size of the IP packet (header and data) in bytes.
    /// The minimum size is 20 bytes (if you have no data) and the maximum size is 65,535 bytes, that’s the highest value you can create with 16 bits.
    pub tot_len: U16,
    /// Identification: If the IP packet is fragmented then each fragmented packet will use the same 16 bit identification number to identify to which IP packet they belong to.
    /// 如果数据包原始长度超过数据包所要经过的数据链路的最大传输单元（MTU），那么必须将数据包分段为更小的数据包。
    pub id: U16,
    /// ```text
    ///  +----+----+----+----------------------------------+
    ///  | RS | DF | MF | ...13 bits of fragment offset... |
    ///  +----+----+----+----------------------------------+
    ///  ```
    /// IP Flags: These 3 bits are used for fragmentation:
    /// - The first bit is always set to 0.
    /// - The second bit is called the DF (Don’t Fragment) bit and indicates that this packet should not be fragmented.
    /// 当DF位被设置为1时，表示路由器不能对数据包进行分段处理。如果数据包由于不能被分段而未能被转发，那么路由器将丢弃该数据包并向源点发送错误消息。
    /// 这一功能可以在网络上用于测试MTU值。可以使用Ping工具可以对DF位进行设置测试。
    /// - The third bit is called the MF (More Fragments) bit and is set on all fragmented packets except the last one.
    ///
    /// Fragment Offset: this 13 bit field specifies the position of the fragment in the original fragmented IP packet.
    /// 以8个八位组(64bit)为单位，用于指明分段起始点相对于报头起始点的偏移量。第一个片段的偏移量为0。
    pub frag_off: BitfieldUnit<[u8; 2usize]>,
    /// Time to Live: Everytime an IP packet passes through a router, the time to live field is decremented by 1.
    /// Once it hits 0 the router will drop the packet and sends an ICMP time exceeded message to the sender.
    /// The time to live field has 8 bits and is used to prevent packets from looping around forever (if you have a routing loop).
    /// Default to 64, measured in units of seconds.
    pub ttl: u8,
    /// Protocol: this 8 bit field tells us which protocol is enapsulated in the IP packet, for example TCP has value 6 and UDP has value 17.
    pub proto: IpProto,
    /// Header Checksum: this 16 bit field is used to store a checksum of the header. The receiver can use the checksum to check if there are any errors in the header.
    /// 针对IP报头的纠错字段， 校验和不计算被封装的数据。
    pub check: U16,
    /// Source Address: here you will find the 32 bit source IP address.
    pub src_addr: Ipv4Addr,
    /// Destination Address: and here’s the 32 bit destination IP address.
    pub dst_addr: Ipv4Addr,
    // IP Option: this field is not used often, is optional and has a variable length based on the options that were used.
    // When you use this field, the value in the header length field will increase.
    // An example of a possible option is “source route” where the sender requests for a certain routing path.
    // 松散源路由选择（Loose Source Routing）——它给出了一连串路由器接口的IP地址序列。数据包必须沿着IP地址序列传送，但是允许在相继的两个地址之间跳过多台路由器。
    // 严格源路由选择（Strict Source Routing）——它也给出了一系列路由器接口的IP地址序列。不同于松散源路由选择，数据包必要严格按照路由转发。如果下一跳不再列表中，那么将会发生错误。
    // 记录路由（Record Route）——当数据包离开时为每台路由器提供空间记录数据包的出站接口地址，以便保存数据包经过的所有路由器的记录。记录路由选项提供了类似于路由追踪的功能，但是不同点在于这里记录了双向路径上的出站接口信息。
    // 时间戳（Timestamp）——除了每台路由器还会记录一个时间戳之外，时间戳选项十分类似于记录路由选项，这样数据包不仅可以知道自己到过哪里，而且还可以记录到达的时间。
    // 还可以在Option 字段内使用Linux 内核模块 TOA，tcp option address ，用来传递记录源ip地址，多用在网关转发时（LB等SDN网关上）；
    // 填充（Padding）——该字段通过在可选项字段后面添加0来补足32位，这样保证报头长度是32位的倍数。
}

impl Ipv4Hdr {
    pub const LEN: usize = mem::size_of::<Ipv4Hdr>();

    #[inline]
    pub fn ihl(&self) -> u8 {
        self._bitfield_1.get(0usize, 4u8) as u8
    }

    #[inline]
    pub fn set_ihl(&mut self, val: u8) {
        self._bitfield_1.set(0usize, 4u8, val as u64)
    }

    /// Version: the first field tells us which IP version we are using, only IPv4 uses this header so you will always find decimal value 4 here.
    /// - 0100表示IP版本4（IPv4）
    /// - 0110表示IP版本6（IPv6）
    #[inline]
    pub fn version(&self) -> u8 {
        self._bitfield_1.get(4usize, 4u8) as u8
    }

    #[inline]
    pub fn set_version(&mut self, val: u8) {
        self._bitfield_1.set(4usize, 4u8, val as u64)
    }

    #[inline]
    pub fn new_bitfield_1(ihl: u8, version: u8) -> BitfieldUnit<[u8; 1usize]> {
        let mut bitfield_unit: BitfieldUnit<[u8; 1usize]> = Default::default();
        bitfield_unit.set(0usize, 4u8, ihl as u64);
        bitfield_unit.set(4usize, 4u8, version as u64);
        bitfield_unit
    }

    #[inline]
    pub fn hdrlen(&self) -> usize {
        self.ihl() as usize * 4
    }

    /// is **DONT_FRAGMENT** flag setted
    #[inline]
    pub fn dont_fragment(&self) -> bool {
        self.frag_off.get_bit(15)
    }
    /// is **MORE_FRAGMENTS** flag setted
    #[inline]
    pub fn more_fragments(&self) -> bool {
        self.frag_off.get_bit(14)
    }

    /// The frag_off portion of the header consists of:
    /// ```text
    ///  +----+----+----+----------------------------------+
    ///  | RS | DF | MF | ...13 bits of fragment offset... |
    ///  +----+----+----+----------------------------------+
    ///  ```
    ///  If "More fragments" or the offset is nonzero, then this is an IP
    ///  fragment (RFC791).
    #[inline]
    pub fn is_fragment(&self) -> bool {
        // 0x3FFF
        self.frag_off.get(0, 14) > 0
    }

    #[inline]
    pub fn is_not_first_fragment(&self) -> bool {
        /* Ignore "More fragments" bit to catch all fragments but the first */
        // 0x1FFF
        self.frag_off.get(0, 13) > 0
    }

    #[inline]
    pub fn has_l4_header(&self) -> bool {
        /* Simply a reverse of ipv4_is_not_first_fragment to avoid double negative. */
        !self.is_not_first_fragment()
    }
}

/// The option-type octet is viewed as having 3 fields:
/// ```text
///    1 bit   copied flag,
///    2 bits  option class,
///    5 bits  option number.
/// ```
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ipv4HdrOptionType {
    octets: BitfieldUnit<[u8; 1usize]>,
}

impl Ipv4HdrOptionType {
    pub fn new(value: u8) -> Ipv4HdrOptionType {
        Ipv4HdrOptionType {
            octets: BitfieldUnit::new([value]),
        }
    }

    /// The copied flag indicates that this option is copied into all
    /// fragments on fragmentation.
    /// - 0 = not copied
    /// - 1 = copied
    pub fn copied_flag(&self) -> bool {
        self.octets.get_bit(7)
    }

    /// The option classes are:
    /// ```text
    ///     0 = control
    ///     1 = reserved for future use
    ///     2 = debugging and measurement
    ///     3 = reserved for future use
    /// ```
    #[inline]
    pub fn option_class(&self) -> u8 {
        self.octets.get(5, 2) as u8
    }

    /// The following internet options are defined:
    /// ```test
    ///  CLASS NUMBER LENGTH DESCRIPTION
    ///  ----- ------ ------ -----------
    ///    0     0      -    End of Option list.  This option occupies only
    ///                      1 octet; it has no length octet.
    ///    0     1      -    No Operation.  This option occupies only 1
    ///                      octet; it has no length octet.
    ///    0     2     11    Security.  Used to carry Security,
    ///                      Compartmentation, User Group (TCC), and
    ///                      Handling Restriction Codes compatible with DOD
    ///                      requirements.
    ///    0     3     var.  Loose Source Routing.  Used to route the
    ///                      internet datagram based on information
    ///                      supplied by the source.
    ///    0     9     var.  Strict Source Routing.  Used to route the
    ///                      internet datagram based on information
    ///                      supplied by the source.
    ///    0     7     var.  Record Route.  Used to trace the route an
    ///                      internet datagram takes.
    ///    0     8      4    Stream ID.  Used to carry the stream
    ///                      identifier.
    ///    2     4     var.  Internet Timestamp.
    /// ```
    #[inline]
    pub fn option_number(&self) -> u8 {
        self.octets.get(0, 5) as u8
    }

    #[inline]
    pub fn is_end_of_option_list(&self) -> bool {
        self.option_number() == 0 && self.option_class() == 0
    }
    #[inline]
    pub fn is_no_operation(&self) -> bool {
        self.option_number() == 1 && self.option_class() == 0
    }
    #[inline]
    pub fn is_security(&self) -> bool {
        self.option_number() == 2 && self.option_class() == 0
    }
    #[inline]
    pub fn is_loose_source_routing(&self) -> bool {
        self.option_number() == 3 && self.option_class() == 0
    }
    #[inline]
    pub fn is_strict_source_routing(&self) -> bool {
        self.option_number() == 9 && self.option_class() == 0
    }
    #[inline]
    pub fn is_record_route(&self) -> bool {
        self.option_number() == 7 && self.option_class() == 0
    }
    #[inline]
    pub fn is_stream_id(&self) -> bool {
        self.option_number() == 8 && self.option_class() == 0
    }
    #[inline]
    pub fn is_internet_timestamp(&self) -> bool {
        self.option_number() == 4 && self.option_class() == 2
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_v4() {
        use core::mem;
        use core::net::Ipv4Addr;

        use crate::ip::Ipv4Hdr;

        let expected_header_bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1, 127, 0, 0, 2,
        ];

        let ipv4_header: Ipv4Hdr = unsafe {
            mem::transmute::<[u8; Ipv4Hdr::LEN], _>(expected_header_bytes.try_into().unwrap())
        };
        assert_eq!(ipv4_header.src_addr, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(ipv4_header.dst_addr, Ipv4Addr::new(127, 0, 0, 2));
    }
}
