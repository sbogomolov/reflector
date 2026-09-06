//! Parse a captured frame into a [`Packet`]: strip the link header, then the IP and
//! UDP headers, yielding the endpoints, TTL, and a borrowed payload.
//!
//! The parse is zero-copy: a [`Packet`] borrows the capture buffer, valid only until
//! the next read. The kernel filter already restricts capture to IP/UDP, so the
//! validation here is defense in depth: a malformed frame yields a [`ParseError`] to
//! log and skip, never a panic or partial packet.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use thiserror::Error;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
use super::DLT_NULL_HEADER_SIZE;
use super::mac::MacAddr;
use super::{
    ETHERNET_HEADER_SIZE, IP_PROTO_UDP, IPV4_HEADER_SIZE, IPV6_HEADER_SIZE, LinkType,
    UDP_HEADER_SIZE,
};

/// A parsed UDP datagram: the endpoints, the captured TTL/hop-limit, the L2 addresses
/// (for filtering), and the payload borrowed from the capture buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Packet<'a> {
    pub(crate) source: SocketAddr,
    pub(crate) dest: SocketAddr,
    /// IPv4 TTL or IPv6 hop limit, as captured.
    pub(crate) ttl: u8,
    /// Ethernet destination/source MAC, or `None` on `DLT_NULL` (loopback/tunnel, no L2).
    pub(crate) dst_mac: Option<MacAddr>,
    pub(crate) src_mac: Option<MacAddr>,
    pub(crate) payload: &'a [u8],
}

impl Packet<'_> {
    /// Whether the datagram is an IPv4 broadcast. On a link with MACs the frame says: it went to
    /// the all-ones MAC, which carries a directed broadcast of any subnet on the link as well as the
    /// limited one. A link without MACs (`DLT_NULL`, a tunnel or a loopback) leaves the address:
    /// the limited broadcast, or `directed_broadcast`, the link's own subnet's.
    pub(crate) fn is_broadcast(&self, directed_broadcast: Option<Ipv4Addr>) -> bool {
        match (self.dest.ip(), self.dst_mac) {
            (IpAddr::V4(v4), Some(mac)) => !v4.is_multicast() && mac == MacAddr::broadcast(),
            (IpAddr::V4(v4), None) => v4.is_broadcast() || Some(v4) == directed_broadcast,
            (IpAddr::V6(_), _) => false,
        }
    }
}

/// Why a captured frame could not be parsed into a [`Packet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ParseError {
    /// The frame is shorter than a header it must contain.
    #[error("frame is truncated")]
    Truncated,
    /// The IP version nibble is neither 4 nor 6.
    #[error("unsupported IP version {0}")]
    BadIpVersion(u8),
    /// An IPv4 fragment (we reflect only whole datagrams).
    #[error("IPv4 fragment")]
    Fragmented,
    /// The L4 protocol (IPv4) or next header (IPv6) is not UDP.
    #[error("not a UDP datagram (IP protocol {0})")]
    NotUdp(u8),
    /// A declared length field is inconsistent with the captured bytes.
    #[error("inconsistent length field")]
    BadLength,
}

impl<'a> Packet<'a> {
    /// Parse one captured `frame` (framed as `link_type`) into a [`Packet`].
    ///
    /// # Errors
    /// Returns a [`ParseError`] if the frame is truncated, not IPv4/IPv6 UDP, an IPv4
    /// fragment, or carries an inconsistent length field.
    pub(crate) fn parse(link_type: LinkType, frame: &'a [u8]) -> Result<Self, ParseError> {
        let link = parse_link_header(link_type, frame)?;
        // Dispatch on the IP version nibble, not the link-layer ethertype or address
        // family: the nibble governs the header layout we parse.
        let &first = link.l3.first().ok_or(ParseError::Truncated)?;
        match first >> 4 {
            4 => parse_ipv4(link),
            6 => parse_ipv6(link),
            version => Err(ParseError::BadIpVersion(version)),
        }
    }
}

/// A frame's link header: its L2 addresses (absent on `DLT_NULL`) and the L3 bytes
/// that follow.
#[derive(Clone, Copy)]
struct LinkHeader<'a> {
    dst_mac: Option<MacAddr>,
    src_mac: Option<MacAddr>,
    l3: &'a [u8],
}

/// Parse the `link_type` link header into its L2 addresses and the L3 bytes that follow.
fn parse_link_header(link_type: LinkType, frame: &[u8]) -> Result<LinkHeader<'_>, ParseError> {
    match link_type {
        LinkType::Ethernet => {
            let l3 = frame
                .get(ETHERNET_HEADER_SIZE..)
                .ok_or(ParseError::Truncated)?;
            // The Ethernet header is dst MAC(6) + src MAC(6) + ethertype(2); the L3
            // slice above proves the frame holds all 14, so the MAC reads are in range.
            Ok(LinkHeader {
                dst_mac: Some(read_mac(&frame[0..6])?),
                src_mac: Some(read_mac(&frame[6..12])?),
                l3,
            })
        }
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        LinkType::DltNull => Ok(LinkHeader {
            dst_mac: None,
            src_mac: None,
            l3: frame
                .get(DLT_NULL_HEADER_SIZE..)
                .ok_or(ParseError::Truncated)?,
        }),
    }
}

/// Parse an IPv4 datagram (header, options, then UDP) from `link`'s L3 bytes, carrying
/// its L2 addresses onto the [`Packet`].
fn parse_ipv4(link: LinkHeader<'_>) -> Result<Packet<'_>, ParseError> {
    let l3 = link.l3;
    if l3.len() < IPV4_HEADER_SIZE {
        return Err(ParseError::Truncated);
    }

    // IHL counts 32-bit words and covers any options; it bounds where L4 begins.
    let header_len = usize::from(l3[0] & 0x0f) * 4;
    if header_len < IPV4_HEADER_SIZE || header_len > l3.len() {
        return Err(ParseError::BadLength);
    }

    // Reject fragments: the More-Fragments flag (bit 13) or any fragment offset (bits
    // 0-12) set. The Don't-Fragment flag (bit 14) is expected and ignored.
    if u16::from_be_bytes([l3[6], l3[7]]) & 0x3fff != 0 {
        return Err(ParseError::Fragmented);
    }

    if l3[9] != IP_PROTO_UDP {
        return Err(ParseError::NotUdp(l3[9]));
    }

    // The total length spans the IP header + datagram; trust it over the captured slice
    // so trailing link padding (Ethernet min-frame, capture slack) is trimmed off.
    let total_len = usize::from(u16::from_be_bytes([l3[2], l3[3]]));
    if total_len < header_len || total_len > l3.len() {
        return Err(ParseError::BadLength);
    }

    let src_ip = ipv4_addr(&l3[12..16])?;
    let dst_ip = ipv4_addr(&l3[16..20])?;
    let ttl = l3[8];
    let (src_port, dst_port, payload) = parse_udp(&l3[header_len..total_len])?;

    Ok(Packet {
        source: SocketAddr::new(IpAddr::V4(src_ip), src_port),
        dest: SocketAddr::new(IpAddr::V4(dst_ip), dst_port),
        ttl,
        dst_mac: link.dst_mac,
        src_mac: link.src_mac,
        payload,
    })
}

/// Parse an IPv6 datagram (fixed base header, then UDP) from `link`'s L3 bytes, carrying
/// its L2 addresses onto the [`Packet`]. Extension headers are unsupported: a next
/// header other than UDP is rejected.
fn parse_ipv6(link: LinkHeader<'_>) -> Result<Packet<'_>, ParseError> {
    let l3 = link.l3;
    if l3.len() < IPV6_HEADER_SIZE {
        return Err(ParseError::Truncated);
    }

    if l3[6] != IP_PROTO_UDP {
        return Err(ParseError::NotUdp(l3[6]));
    }

    let payload_len = usize::from(u16::from_be_bytes([l3[4], l3[5]]));
    let total_len = IPV6_HEADER_SIZE + payload_len;
    if total_len > l3.len() {
        return Err(ParseError::BadLength);
    }

    let src_ip = ipv6_addr(&l3[8..24])?;
    let dst_ip = ipv6_addr(&l3[24..40])?;
    let hop_limit = l3[7];
    let (src_port, dst_port, payload) = parse_udp(&l3[IPV6_HEADER_SIZE..total_len])?;

    Ok(Packet {
        source: SocketAddr::new(IpAddr::V6(src_ip), src_port),
        dest: SocketAddr::new(IpAddr::V6(dst_ip), dst_port),
        ttl: hop_limit,
        dst_mac: link.dst_mac,
        src_mac: link.src_mac,
        payload,
    })
}

/// Parse a UDP header from `l4`, returning the ports and the payload trimmed to the
/// datagram's declared length.
fn parse_udp(l4: &[u8]) -> Result<(u16, u16, &[u8]), ParseError> {
    if l4.len() < UDP_HEADER_SIZE {
        return Err(ParseError::Truncated);
    }
    let src_port = u16::from_be_bytes([l4[0], l4[1]]);
    let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
    let udp_len = usize::from(u16::from_be_bytes([l4[4], l4[5]]));
    if udp_len < UDP_HEADER_SIZE || udp_len > l4.len() {
        return Err(ParseError::BadLength);
    }
    Ok((src_port, dst_port, &l4[UDP_HEADER_SIZE..udp_len]))
}

/// `bytes` is a length-checked header slice, so the conversion never fails; mapping a
/// mismatch to `Truncated` keeps it panic-free regardless.
fn ipv4_addr(bytes: &[u8]) -> Result<Ipv4Addr, ParseError> {
    <[u8; 4]>::try_from(bytes)
        .map(Ipv4Addr::from)
        .map_err(|_| ParseError::Truncated)
}

/// Read a 16-byte IPv6 address field, the [`ipv4_addr`] counterpart.
fn ipv6_addr(bytes: &[u8]) -> Result<Ipv6Addr, ParseError> {
    <[u8; 16]>::try_from(bytes)
        .map(Ipv6Addr::from)
        .map_err(|_| ParseError::Truncated)
}

/// Read a 6-byte MAC field.
fn read_mac(bytes: &[u8]) -> Result<MacAddr, ParseError> {
    <[u8; 6]>::try_from(bytes)
        .map(MacAddr::from)
        .map_err(|_| ParseError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::frame;
    use crate::net::mac::MacAddr;
    use std::net::{SocketAddrV4, SocketAddrV6};

    // Round-trip: what the frame builder writes, the parser reads back. The two are
    // each other's inverse, so a single test exercises every header field.
    #[test]
    fn round_trips_ethernet_ipv4() {
        let src = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 10), 5353);
        let dst = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 20), 5354);
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let mut buf = [0u8; 64];
        // Distinct dst/src MACs so a swapped read would fail.
        let dst_mac = MacAddr::from([0x02, 0, 0, 0, 0, 0xaa]);
        let src_mac = MacAddr::from([0x02, 0, 0, 0, 0, 0xbb]);
        let n = frame::ethernet_ipv4_udp(dst_mac, src_mac, src, dst, 64, &payload, &mut buf)
            .unwrap()
            .len;

        let packet = Packet::parse(LinkType::Ethernet, &buf[..n]).unwrap();
        assert_eq!(packet.source, SocketAddr::V4(src));
        assert_eq!(packet.dest, SocketAddr::V4(dst));
        assert_eq!(packet.ttl, 64);
        assert_eq!(packet.dst_mac, Some(dst_mac));
        assert_eq!(packet.src_mac, Some(src_mac));
        assert_eq!(packet.payload, &payload);
    }

    #[test]
    fn round_trips_ethernet_ipv6() {
        let src = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5353, 0, 0);
        let dst = SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb), 5354, 0, 0);
        let payload = [0xaa, 0xbb, 0xcc];
        let mut buf = [0u8; 80];
        let dst_mac = MacAddr::from([0x33, 0x33, 0, 0, 0, 0xfb]);
        let src_mac = MacAddr::from([0x02, 0, 0, 0, 0, 0xbb]);
        let n = frame::ethernet_ipv6_udp(dst_mac, src_mac, src, dst, 255, &payload, &mut buf)
            .unwrap()
            .len;

        let packet = Packet::parse(LinkType::Ethernet, &buf[..n]).unwrap();
        assert_eq!(packet.source, SocketAddr::V6(src));
        assert_eq!(packet.dest, SocketAddr::V6(dst));
        assert_eq!(packet.ttl, 255);
        assert_eq!(packet.dst_mac, Some(dst_mac));
        assert_eq!(packet.src_mac, Some(src_mac));
        assert_eq!(packet.payload, &payload);
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn round_trips_dlt_null_ipv4() {
        let src = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5353);
        let dst = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5354);
        let payload = [0x01, 0x02];
        let mut buf = [0u8; 64];
        let n = frame::dlt_null_ipv4_udp(src, dst, 64, &payload, &mut buf)
            .unwrap()
            .len;

        let packet = Packet::parse(LinkType::DltNull, &buf[..n]).unwrap();
        assert_eq!(packet.source, SocketAddr::V4(src));
        assert_eq!(packet.dest, SocketAddr::V4(dst));
        assert_eq!(packet.ttl, 64);
        // DLT_NULL has no L2 header, so no MACs to report.
        assert_eq!(packet.dst_mac, None);
        assert_eq!(packet.src_mac, None);
        assert_eq!(packet.payload, &payload);
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn round_trips_dlt_null_ipv6() {
        let src = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5353, 0, 0);
        let dst = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5354, 0, 0);
        let payload = [0x09];
        let mut buf = [0u8; 80];
        let n = frame::dlt_null_ipv6_udp(src, dst, 255, &payload, &mut buf)
            .unwrap()
            .len;

        let packet = Packet::parse(LinkType::DltNull, &buf[..n]).unwrap();
        assert_eq!(packet.source, SocketAddr::V6(src));
        assert_eq!(packet.dest, SocketAddr::V6(dst));
        assert_eq!(packet.ttl, 255);
        assert_eq!(packet.payload, &payload);
    }

    // A captured frame can carry trailing link padding (Ethernet min-frame, BPF slack)
    // past the datagram; the declared IP total length must trim it off the payload.
    #[test]
    fn trims_trailing_link_padding() {
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1);
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 2);
        let payload = [0x11, 0x22, 0x33];
        let mut buf = [0u8; 64]; // zero-filled tail stands in for padding
        let mac = MacAddr::broadcast();
        let n = frame::ethernet_ipv4_udp(mac, mac, src, dst, 64, &payload, &mut buf)
            .unwrap()
            .len;

        let packet = Packet::parse(LinkType::Ethernet, &buf[..n + 10]).unwrap();
        assert_eq!(packet.payload, &payload);
    }

    // IPv4 options: a header longer than 20 bytes (IHL > 5) must be skipped to find L4.
    // The builder never emits options, so this frame is laid out by hand.
    #[test]
    fn parses_ipv4_with_options() {
        let mut frame = [0u8; 50]; // 14 Ethernet + 24 IPv4 (IHL 6) + 8 UDP + 4 payload
        frame[14] = 0x46; // version 4, IHL 6 (24-byte header, 4 option bytes)
        frame[16..18].copy_from_slice(&36u16.to_be_bytes()); // total length (IP + UDP + payload)
        frame[22] = 64; // ttl
        frame[23] = IP_PROTO_UDP;
        frame[26..30].copy_from_slice(&[10, 1, 2, 3]); // src IP
        frame[30..34].copy_from_slice(&[10, 4, 5, 6]); // dst IP
        // frame[34..38] are the 4 option bytes (left zero; the parser skips them).
        frame[38..40].copy_from_slice(&1111u16.to_be_bytes()); // src port
        frame[40..42].copy_from_slice(&2222u16.to_be_bytes()); // dst port
        frame[42..44].copy_from_slice(&12u16.to_be_bytes()); // UDP length
        frame[46..50].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload

        let packet = Packet::parse(LinkType::Ethernet, &frame).unwrap();
        assert_eq!(packet.source, "10.1.2.3:1111".parse().unwrap());
        assert_eq!(packet.dest, "10.4.5.6:2222".parse().unwrap());
        assert_eq!(packet.ttl, 64);
        assert_eq!(packet.payload, &[0xde, 0xad, 0xbe, 0xef]);
    }

    /// Build a valid Ethernet IPv4 UDP frame into `buf`, returning its length. The
    /// rejection tests corrupt one field of this baseline.
    fn valid_ethernet_ipv4(buf: &mut [u8]) -> usize {
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1234);
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 5678);
        let mac = MacAddr::broadcast();
        frame::ethernet_ipv4_udp(mac, mac, src, dst, 64, &[0xab; 4], buf)
            .unwrap()
            .len
    }

    #[test]
    fn rejects_frame_shorter_than_link_header() {
        assert_eq!(
            Packet::parse(LinkType::Ethernet, &[0u8; 10]),
            Err(ParseError::Truncated)
        );
    }

    #[test]
    fn rejects_truncated_ip_header() {
        // Ethernet header, then a valid IPv4 version nibble but only a few L3 bytes.
        let mut frame = [0u8; 18];
        frame[14] = 0x45;
        assert_eq!(
            Packet::parse(LinkType::Ethernet, &frame),
            Err(ParseError::Truncated)
        );
    }

    #[test]
    fn rejects_unsupported_ip_version() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        buf[14] = 0x55; // version 5
        assert_eq!(
            Packet::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::BadIpVersion(5))
        );
    }

    #[test]
    fn rejects_ipv4_fragment() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        buf[20] = 0x20; // set the More-Fragments flag (IP flags/frag high byte)
        assert_eq!(
            Packet::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::Fragmented)
        );
    }

    #[test]
    fn rejects_non_udp() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        buf[23] = 6; // IP protocol TCP
        assert_eq!(
            Packet::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::NotUdp(6))
        );
    }

    #[test]
    fn rejects_oversized_total_length() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        buf[16..18].copy_from_slice(&u16::MAX.to_be_bytes()); // total length past the frame
        assert_eq!(
            Packet::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::BadLength)
        );
    }

    #[test]
    fn rejects_oversized_udp_length() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        // UDP length field sits at the start of L4 + 4: Ethernet(14) + IPv4(20) + 4.
        buf[38..40].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            Packet::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::BadLength)
        );
    }

    #[test]
    fn rejects_ipv4_header_length_below_minimum() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        buf[14] = 0x44; // version 4, IHL 4: a 16-byte header, below the 20-byte minimum
        assert_eq!(
            Packet::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::BadLength)
        );
    }

    // The fragment check masks 0x3fff, so Don't-Fragment (0x4000) alone must parse.
    // Guards against a regression that widened the mask to also catch DF.
    #[test]
    fn accepts_dont_fragment_flag() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        buf[20] = 0x40; // DF set, MF and fragment offset clear
        buf[21] = 0x00;
        let packet = Packet::parse(LinkType::Ethernet, &buf[..n]).unwrap();
        assert_eq!(packet.payload, &[0xab; 4]);
    }

    #[test]
    fn accepts_empty_udp_payload() {
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1);
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 2);
        let mac = MacAddr::broadcast();
        let mut buf = [0u8; 64];
        let n = frame::ethernet_ipv4_udp(mac, mac, src, dst, 64, &[], &mut buf)
            .unwrap()
            .len;
        let packet = Packet::parse(LinkType::Ethernet, &buf[..n]).unwrap();
        assert!(packet.payload.is_empty());
    }

    /// Build a valid Ethernet IPv6 UDP frame into `buf`, returning its length. The
    /// IPv6 counterpart of [`valid_ethernet_ipv4`] for the rejection tests.
    fn valid_ethernet_ipv6(buf: &mut [u8]) -> usize {
        let src = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1234, 0, 0);
        let dst = SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb), 5678, 0, 0);
        let mac = MacAddr::broadcast();
        frame::ethernet_ipv6_udp(mac, mac, src, dst, 64, &[0xab; 4], buf)
            .unwrap()
            .len
    }

    #[test]
    fn rejects_truncated_ipv6_header() {
        // Ethernet header, then a valid IPv6 version nibble but fewer than 40 L3 bytes.
        let mut frame = [0u8; 30];
        frame[14] = 0x60;
        assert_eq!(
            Packet::parse(LinkType::Ethernet, &frame),
            Err(ParseError::Truncated)
        );
    }

    #[test]
    fn rejects_ipv6_non_udp() {
        let mut buf = [0u8; 80];
        let n = valid_ethernet_ipv6(&mut buf);
        buf[20] = 6; // IPv6 next header (L3 offset 6) -> TCP
        assert_eq!(
            Packet::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::NotUdp(6))
        );
    }

    #[test]
    fn rejects_oversized_ipv6_payload_length() {
        let mut buf = [0u8; 80];
        let n = valid_ethernet_ipv6(&mut buf);
        buf[18..20].copy_from_slice(&u16::MAX.to_be_bytes()); // payload length past the frame
        assert_eq!(
            Packet::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::BadLength)
        );
    }

    #[test]
    fn rejects_udp_length_below_minimum() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        buf[38..40].copy_from_slice(&4u16.to_be_bytes()); // UDP length below the 8-byte header
        assert_eq!(
            Packet::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::BadLength)
        );
    }

    #[test]
    fn rejects_l4_region_smaller_than_the_udp_header() {
        let mut buf = [0u8; 64];
        let n = valid_ethernet_ipv4(&mut buf);
        buf[16..18].copy_from_slice(&24u16.to_be_bytes()); // total length leaves 4 bytes for L4
        assert_eq!(
            Packet::parse(LinkType::Ethernet, &buf[..n]),
            Err(ParseError::Truncated)
        );
    }

    #[test]
    fn rejects_ethernet_frame_with_no_l3_bytes() {
        assert_eq!(
            Packet::parse(LinkType::Ethernet, &[0u8; ETHERNET_HEADER_SIZE]),
            Err(ParseError::Truncated)
        );
    }
}
