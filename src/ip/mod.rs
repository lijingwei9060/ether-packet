use v4::Ipv4Hdr;
use v6::Ipv6Hdr;

pub mod v4;
pub mod v6;

/// IP headers, which are present after the Ethernet header.
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum IpHdr {
    V4(Ipv4Hdr),
    V6(Ipv6Hdr),
}


/// Protocol which is encapsulated in the IPv4 packet.
/// <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>
#[repr(u8)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(features = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum IpProto {
    /// IPv6 Hop-by-Hop Option
    HopOpt = 0,
    /// Internet Control Message
    Icmp = 1,
    /// Internet Group Management
    Igmp = 2,
    /// Gateway-to-Gateway
    Ggp = 3,
    /// IPv4 encapsulation
    Ipv4 = 4,
    /// Stream
    Stream = 5,
    /// Transmission Control
    Tcp = 6,
    /// CBT
    Cbt = 7,
    /// Exterior Gateway Protocol
    Egp = 8,
    /// Any private interior gateway (used by Cisco for their IGRP)
    Igp = 9,
    /// BBN RCC Monitoring
    BbnRccMon = 10,
    /// Network Voice Protocol
    NvpII = 11,
    /// PUP
    Pup = 12,
    /// ARGUS
    Argus = 13,
    /// EMCON
    Emcon = 14,
    /// Cross Net Debugger
    Xnet = 15,
    /// Chaos
    Chaos = 16,
    /// User Datagram
    Udp = 17,
    /// Multiplexing
    Mux = 18,
    /// DCN Measurement Subsystems
    DcnMeas = 19,
    /// Host Monitoring
    Hmp = 20,
    /// Packet Radio Measurement
    Prm = 21,
    /// XEROX NS IDP
    Idp = 22,
    /// Trunk-1
    Trunk1 = 23,
    /// Trunk-2
    Trunk2 = 24,
    /// Leaf-1
    Leaf1 = 25,
    /// Leaf-2
    Leaf2 = 26,
    /// Reliable Data Protocol
    Rdp = 27,
    /// Internet Reliable Transaction
    Irtp = 28,
    /// ISO Transport Protocol Class 4
    Tp4 = 29,
    /// Bulk Data Transfer Protocol
    Netblt = 30,
    /// MFE Network Services Protocol
    MfeNsp = 31,
    /// MERIT Internodal Protocol
    MeritInp = 32,
    /// Datagram Congestion Control Protocol
    Dccp = 33,
    /// Third Party Connect Protocol
    ThirdPartyConnect = 34,
    /// Inter-Domain Policy Routing Protocol
    Idpr = 35,
    /// XTP
    Xtp = 36,
    /// Datagram Delivery Protocol
    Ddp = 37,
    /// IDPR Control Message Transport Proto
    IdprCmtp = 38,
    /// TP++ Transport Protocol
    TpPlusPlus = 39,
    /// IL Transport Protocol
    Il = 40,
    /// IPv6 encapsulation
    Ipv6 = 41,
    /// Source Demand Routing Protocol
    Sdrp = 42,
    /// Routing Header for IPv6
    Ipv6Route = 43,
    /// Fragment Header for IPv6
    Ipv6Frag = 44,
    /// Inter-Domain Routing Protocol
    Idrp = 45,
    /// Reservation Protocol
    Rsvp = 46,
    /// General Routing Encapsulation
    Gre = 47,
    /// Dynamic Source Routing Protocol
    Dsr = 48,
    /// BNA
    Bna = 49,
    /// Encap Security Payload
    Esp = 50,
    /// Authentication Header
    Ah = 51,
    /// Integrated Net Layer Security TUBA
    Inlsp = 52,
    /// IP with Encryption
    Swipe = 53,
    /// NBMA Address Resolution Protocol
    Narp = 54,
    /// IP Mobility
    Mobile = 55,
    /// Transport Layer Security Protocol using Kryptonet key management
    Tlsp = 56,
    /// SKIP
    Skip = 57,
    /// Internet Control Message Protocol for IPv6
    Ipv6Icmp = 58,
    /// No Next Header for IPv6
    Ipv6NoNxt = 59,
    /// Destination Options for IPv6
    Ipv6Opts = 60,
    /// Any host internal protocol
    AnyHostInternal = 61,
    /// CFTP
    Cftp = 62,
    /// Any local network
    AnyLocalNetwork = 63,
    /// SATNET and Backroom EXPAK
    SatExpak = 64,
    /// Kryptolan
    Kryptolan = 65,
    /// MIT Remote Virtual Disk Protocol
    Rvd = 66,
    /// Internet Pluribus Packet Core
    Ippc = 67,
    /// Any distributed file system
    AnyDistributedFileSystem = 68,
    /// SATNET Monitoring
    SatMon = 69,
    /// VISA Protocol
    Visa = 70,
    /// Internet Packet Core Utility
    Ipcv = 71,
    /// Computer Protocol Network Executive
    Cpnx = 72,
    /// Computer Protocol Heart Beat
    Cphb = 73,
    /// Wang Span Network
    Wsn = 74,
    /// Packet Video Protocol
    Pvp = 75,
    /// Backroom SATNET Monitoring
    BrSatMon = 76,
    /// SUN ND PROTOCOL-Temporary
    SunNd = 77,
    /// WIDEBAND Monitoring
    WbMon = 78,
    /// WIDEBAND EXPAK
    WbExpak = 79,
    /// ISO Internet Protocol
    IsoIp = 80,
    /// VMTP
    Vmtp = 81,
    /// SECURE-VMTP
    SecureVmtp = 82,
    /// VINES
    Vines = 83,
    /// Transaction Transport Protocol
    Ttp = 84,
    /// NSFNET-IGP
    NsfnetIgp = 85,
    /// Dissimilar Gateway Protocol
    Dgp = 86,
    /// TCF
    Tcf = 87,
    /// EIGRP
    Eigrp = 88,
    /// OSPFIGP
    Ospfigp = 89,
    /// Sprite RPC Protocol
    SpriteRpc = 90,
    /// Locus Address Resolution Protocol
    Larp = 91,
    /// Multicast Transport Protocol
    Mtp = 92,
    /// AX.25 Frames
    Ax25 = 93,
    /// IP-within-IP Encapsulation Protocol
    Ipip = 94,
    /// Mobile Internetworking Control Pro.
    Micp = 95,
    /// Semaphore Communications Sec. Pro.
    SccSp = 96,
    /// Ethernet-within-IP Encapsulation
    Etherip = 97,
    /// Encapsulation Header
    Encap = 98,
    /// Any private encryption scheme
    AnyPrivateEncryptionScheme = 99,
    /// GMTP
    Gmtp = 100,
    /// Ipsilon Flow Management Protocol
    Ifmp = 101,
    /// PNNI over IP
    Pnni = 102,
    /// Protocol Independent Multicast
    Pim = 103,
    /// ARIS
    Aris = 104,
    /// SCPS
    Scps = 105,
    /// QNX
    Qnx = 106,
    /// Active Networks
    ActiveNetworks = 107,
    /// IP Payload Compression Protocol
    IpComp = 108,
    /// Sitara Networks Protocol
    Snp = 109,
    /// Compaq Peer Protocol
    CompaqPeer = 110,
    /// IPX in IP
    IpxInIp = 111,
    /// Virtual Router Redundancy Protocol
    Vrrp = 112,
    /// PGM Reliable Transport Protocol
    Pgm = 113,
    /// Any 0-hop protocol
    AnyZeroHopProtocol = 114,
    /// Layer Two Tunneling Protocol
    L2tp = 115,
    /// D-II Data Exchange (DDX)
    Ddx = 116,
    /// Interactive Agent Transfer Protocol
    Iatp = 117,
    /// Schedule Transfer Protocol
    Stp = 118,
    /// SpectraLink Radio Protocol
    Srp = 119,
    /// UTI
    Uti = 120,
    /// Simple Message Protocol
    Smp = 121,
    /// Simple Multicast Protocol
    Sm = 122,
    /// Performance Transparency Protocol
    Ptp = 123,
    /// ISIS over IPv4
    IsisOverIpv4 = 124,
    /// FIRE
    Fire = 125,
    /// Combat Radio Transport Protocol
    Crtp = 126,
    /// Combat Radio User Datagram
    Crudp = 127,
    /// SSCOPMCE
    Sscopmce = 128,
    /// IPLT
    Iplt = 129,
    /// Secure Packet Shield
    Sps = 130,
    /// Private IP Encapsulation within IP
    Pipe = 131,
    /// Stream Control Transmission Protocol
    Sctp = 132,
    /// Fibre Channel
    Fc = 133,
    /// RSVP-E2E-IGNORE
    RsvpE2eIgnore = 134,
    /// Mobility Header
    MobilityHeader = 135,
    /// Lightweight User Datagram Protocol
    UdpLite = 136,
    /// MPLS-in-IP
    Mpls = 137,
    /// MANET Protocols
    Manet = 138,
    /// Host Identity Protocol
    Hip = 139,
    /// Shim6 Protocol
    Shim6 = 140,
    /// Wrapped Encapsulating Security Payload
    Wesp = 141,
    /// Robust Header Compression
    Rohc = 142,
    /// Ethernet in IPv4
    EthernetInIpv4 = 143,
    /// AGGFRAG encapsulation payload for ESP
    Aggfrag = 144,
    /// Use for experimentation and testing
    Test1 = 253,
    /// Use for experimentation and testing
    Test2 = 254,
    /// Reserved
    Reserved = 255,
}