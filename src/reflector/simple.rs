//! The shared stateless reflector.
//!
//! mDNS (both directions), the WSD Hello/Bye announcements, SSDP's `NOTIFY` advertisements and
//! Wake-on-LAN are the same operation: classify the payload and, if it's a message for this leg,
//! re-emit it on the egress interface, verbatim or through an optional [`ReplyRewrite`] (SSDP's
//! advertisement direction rewrites the DIAL `LOCATION`). What differs per protocol enters as
//! parameters: the [`Classify`] gate and the [`Emit`] policy (which source and TTL the re-emit
//! carries). Where it goes follows from the captured destination alone ([`link_destination`]). The
//! search directions are stateful (per-searcher sessions), so they use the shared `SearchReflector`
//! instead.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::dispatch::{CaptureKey, DatagramSource, Outcome, PacketDispatcher, PacketHandler};
use crate::interface::InterfaceAddresses;
use crate::logging::log_rate;
use crate::net::packet::Packet;
use crate::reactor::Reactor;

use super::{NoRewrite, ReplyRewrite, Verdict, WARN_WINDOW, egress_sources};

/// A leg's ingress gate: is this packet a message for it? See [`Verdict`].
pub(crate) trait Classify {
    fn classify(&self, packet: &Packet) -> Verdict;
}

/// A plain function over the payload: the multicast-discovery protocols gate on the message alone.
impl<F: Fn(&[u8]) -> Verdict> Classify for F {
    fn classify(&self, packet: &Packet) -> Verdict {
        self(packet.payload)
    }
}

/// The IP source a re-emit carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// The egress's own address, at the given port.
    Egress(SourcePort),
    /// The captured sender's own address and port, kept on the re-emit: the transparent relay,
    /// whose peers take the sender from the datagram's source.
    Captured,
}

impl Source {
    fn resolve(self, packet: &Packet) -> DatagramSource {
        match self {
            Self::Egress(port) => DatagramSource::Egress {
                port: port.resolve(packet),
            },
            Self::Captured => DatagramSource::Captured(packet.source),
        }
    }
}

/// The UDP source port an egress-sourced re-emit carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourcePort {
    /// A protocol's well-known port.
    Fixed(u16),
    /// The captured packet's own.
    Captured,
}

impl SourcePort {
    fn resolve(self, packet: &Packet) -> u16 {
        match self {
            Self::Fixed(port) => port,
            Self::Captured => packet.source.port(),
        }
    }
}

/// The TTL / hop limit a re-emit carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ttl {
    Fixed(u8),
    /// The captured packet's own.
    Captured,
}

impl Ttl {
    fn resolve(self, packet: &Packet) -> u8 {
        match self {
            Self::Fixed(ttl) => ttl,
            Self::Captured => packet.ttl,
        }
    }
}

/// How a re-emit is stamped: the source and TTL it carries. The destination follows from the
/// captured one ([`link_destination`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Emit {
    pub(crate) source: Source,
    pub(crate) ttl: Ttl,
}

impl Emit {
    /// From the egress's address at `port`, at `ttl`: the multicast-discovery protocols.
    pub(crate) const fn fixed(port: u16, ttl: u8) -> Self {
        Self {
            source: Source::Egress(SourcePort::Fixed(port)),
            ttl: Ttl::Fixed(ttl),
        }
    }

    /// From the egress's address at the captured source port, at the captured TTL: Wake-on-LAN.
    pub(crate) const fn captured_from_egress() -> Self {
        Self {
            source: Source::Egress(SourcePort::Captured),
            ttl: Ttl::Captured,
        }
    }

    /// From the captured sender's own ip:port, at the captured TTL: the transparent UDP relay.
    pub(crate) const fn captured() -> Self {
        Self {
            source: Source::Captured,
            ttl: Ttl::Captured,
        }
    }
}

/// One stateless leg of one protocol: re-emits each accepted packet captured on its ingress onto
/// `egress`, stamped per its [`Emit`] policy. `classify` is the directional gate; an optional
/// [`ReplyRewrite`] transforms the payload before re-emit (default: forward verbatim).
pub(crate) struct SimpleReflector<C> {
    egress: CaptureKey,
    /// Protocol tag for logs, e.g. `"mDNS"`.
    name: &'static str,
    /// The message kind/direction this reflector handles, for logs, e.g. `"query"`.
    kind: &'static str,
    classify: C,
    emit: Emit,
    /// Transforms the payload before re-emit; [`NoRewrite`] (the default) forwards verbatim.
    rewrite: Box<dyn ReplyRewrite>,
    /// The unreachable-advertisement suppression check for payloads `rewrite` left untouched
    /// (default: none).
    suppress: fn(&[u8]) -> bool,
}

impl<C: Classify> SimpleReflector<C> {
    pub(crate) fn new(
        egress: CaptureKey,
        name: &'static str,
        kind: &'static str,
        classify: C,
        emit: Emit,
    ) -> Self {
        Self {
            egress,
            name,
            kind,
            classify,
            emit,
            rewrite: Box::new(NoRewrite),
            suppress: |_| false,
        }
    }

    /// Apply `rewrite` to the payload before re-emit (e.g. SSDP's DIAL `LOCATION` rewrite); without it
    /// the payload is forwarded verbatim.
    pub(crate) fn with_rewrite(mut self, rewrite: Box<dyn ReplyRewrite>) -> Self {
        self.rewrite = rewrite;
        self
    }

    /// Drop (rather than re-emit) any payload `suppress` flags: the protocol's
    /// `advertises_only_unreachable` check.
    pub(crate) fn with_suppress(mut self, suppress: fn(&[u8]) -> bool) -> Self {
        self.suppress = suppress;
        self
    }
}

impl<C: Classify> PacketHandler for SimpleReflector<C> {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) -> Outcome {
        let message_type = match self.classify.classify(packet) {
            Verdict::Reflect(message_type) => message_type,
            Verdict::Skip(message_type) => return Outcome::Skipped(message_type),
            Verdict::Excluded => return Outcome::Filtered,
            Verdict::Junk => {
                log::debug!(
                    "{}: dropping unrecognized payload ({} B) to {} from {}",
                    self.name,
                    packet.payload.len(),
                    packet.dest,
                    packet.source
                );
                return Outcome::Filtered;
            }
        };

        let dest = link_destination(
            packet.dest,
            dispatcher
                .egress_addrs(self.egress)
                .and_then(InterfaceAddresses::v4_directed_broadcast),
        );

        // A family the egress can't currently source is a quiet, transient drop (address
        // loss): a Stalled, not a genuine send failure.
        if !egress_sources(dispatcher, self.egress, dest) {
            log::debug!(
                "{}: egress has no source for {dest} yet; dropping {} from {}",
                self.name,
                self.kind,
                packet.source
            );
            return Outcome::Stalled(message_type);
        }

        let rewritten = self
            .rewrite
            .rewrite(packet.payload, self.egress, dispatcher, reactor);

        // A rewritten payload is exempt: the rewrite inserts netflector's own egress-side listener,
        // reachable from the egress link even when that interface's address is itself link-local.
        // Only an untouched payload still advertises the far link's addresses.
        if rewritten.is_none() && (self.suppress)(packet.payload) {
            log::debug!(
                "{}: suppressing {} from {}: advertises only unreachable addresses",
                self.name,
                self.kind,
                packet.source
            );
            return Outcome::Dropped(message_type);
        }
        let payload = rewritten.unwrap_or(packet.payload);

        match dispatcher.send_udp_group(
            self.egress,
            dest,
            self.emit.source.resolve(packet),
            self.emit.ttl.resolve(packet),
            payload,
        ) {
            Ok(()) => {
                log::debug!(
                    "reflected {} {} from {} to {dest}",
                    self.name,
                    self.kind,
                    packet.source
                );
                Outcome::Reflected(message_type)
            }
            Err(e) => {
                log_rate!(
                    log::Level::Warn,
                    WARN_WINDOW,
                    "{}: cannot reflect {} from {} to {dest}: {e}",
                    self.name,
                    self.kind,
                    packet.source
                );
                Outcome::Dropped(message_type)
            }
        }
    }
}

/// IPv6 link-local all-nodes group (`ff02::1`), the v6 equivalent of the IPv4 limited broadcast.
const V6_ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// Where a re-emit of a packet captured to `dest` goes, at the captured port: a multicast group
/// (the dispatcher's filter pinned it) and the IPv4 limited broadcast re-emit to themselves; any
/// other IPv4 destination, a directed broadcast or a unicast wake aimed at this host, goes to the
/// egress's own directed broadcast, or the limited broadcast while its prefix is unknown; any other
/// IPv6 destination goes to the all-nodes group.
fn link_destination(dest: SocketAddr, directed_broadcast: Option<Ipv4Addr>) -> SocketAddr {
    match dest {
        SocketAddr::V4(v4) if v4.ip().is_multicast() || v4.ip().is_broadcast() => dest,
        SocketAddr::V4(v4) => {
            SocketAddr::from((directed_broadcast.unwrap_or(Ipv4Addr::BROADCAST), v4.port()))
        }
        SocketAddr::V6(v6) if v6.ip().is_multicast() => dest,
        SocketAddr::V6(v6) => SocketAddr::from((V6_ALL_NODES, v6.port())),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;
    use crate::capture::{Capture, loopback_lock};
    use crate::dispatch::MessageType;

    /// Open a loopback capture, or `None` (skip) without `CAP_NET_RAW`. A real capture gives the
    /// egress a source address, so `on_packet` reaches the suppression gate.
    fn open_loopback_or_skip() -> Option<Capture> {
        match Capture::open(crate::interface::LOOPBACK_IFACE) {
            Ok(cap) => Some(cap),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skip: no CAP_NET_RAW to open a loopback capture ({e})");
                None
            }
            Err(e) => panic!("unexpected loopback capture open failure: {e}"),
        }
    }

    fn reflect_all(_: &[u8]) -> Verdict {
        Verdict::Reflect(MessageType::MdnsResponse)
    }

    type LoopbackRig = (
        SimpleReflector<fn(&[u8]) -> Verdict>,
        PacketDispatcher,
        Reactor,
    );

    /// A reflector with the given transform and suppression check, plus the dispatcher/reactor it
    /// runs against, over a real loopback egress (`None` = skip, no `CAP_NET_RAW`).
    fn reflector_over_loopback(
        rewrite: Box<dyn ReplyRewrite>,
        suppress: fn(&[u8]) -> bool,
    ) -> Option<LoopbackRig> {
        let cap = open_loopback_or_skip()?;
        let mut dispatcher = PacketDispatcher::new();
        let egress = dispatcher
            .add_capture(cap)
            .expect("add the loopback capture");
        let reactor = Reactor::new().expect("reactor");
        let reflector = SimpleReflector::new(
            egress,
            "TEST",
            "response",
            reflect_all as fn(&[u8]) -> Verdict,
            Emit::fixed(5353, 255),
        )
        .with_rewrite(rewrite)
        .with_suppress(suppress);
        Some((reflector, dispatcher, reactor))
    }

    fn group_packet() -> Packet<'static> {
        Packet {
            source: "127.0.0.1:5353".parse().unwrap(),
            dest: "224.0.0.251:5353".parse().unwrap(),
            ttl: 255,
            dst_mac: None,
            src_mac: None,
            payload: b"response",
        }
    }

    /// A packet from an ephemeral port at a non-default TTL, so a captured policy reads apart from a
    /// fixed one.
    fn packet_to(dest: &str) -> Packet<'static> {
        Packet {
            source: "10.0.0.1:40000".parse().unwrap(),
            dest: dest.parse().unwrap(),
            ttl: 7,
            dst_mac: None,
            src_mac: None,
            payload: b"",
        }
    }

    #[test]
    fn link_destination_keeps_groups_and_broadcasts_the_rest() {
        let dest = |s: &str| s.parse::<SocketAddr>().unwrap();
        let egress = Some(Ipv4Addr::new(192, 0, 2, 255));
        for group in ["224.0.0.251:5353", "[ff02::fb]:5353"] {
            assert_eq!(dest(group), link_destination(dest(group), egress));
        }
        // The limited broadcast stays limited; a directed broadcast or a unicast wake aimed at
        // this host goes to the egress's own directed broadcast, at the captured port.
        assert_eq!(
            dest("255.255.255.255:9"),
            link_destination(dest("255.255.255.255:9"), egress)
        );
        for captured in ["10.0.0.255:9", "10.0.0.2:9"] {
            assert_eq!(
                dest("192.0.2.255:9"),
                link_destination(dest(captured), egress)
            );
            // Without the egress prefix, link-wide still means the limited broadcast.
            assert_eq!(
                dest("255.255.255.255:9"),
                link_destination(dest(captured), None)
            );
        }
        assert_eq!(
            dest("[ff02::1]:9"),
            link_destination(dest("[fe80::2]:9"), egress)
        );
    }

    #[test]
    fn source_port_and_ttl_policies_resolve_fixed_or_captured() {
        let packet = packet_to("10.0.0.2:9");
        assert_eq!(SourcePort::Fixed(1900).resolve(&packet), 1900);
        assert_eq!(SourcePort::Captured.resolve(&packet), 40000);
        assert_eq!(Ttl::Fixed(2).resolve(&packet), 2);
        assert_eq!(Ttl::Captured.resolve(&packet), 7);
    }

    #[test]
    fn a_function_classifies_by_payload_alone() {
        fn by_length(payload: &[u8]) -> Verdict {
            if payload.is_empty() {
                Verdict::Junk
            } else {
                Verdict::Reflect(MessageType::MdnsQuery)
            }
        }
        assert_eq!(by_length.classify(&packet_to("10.0.0.2:9")), Verdict::Junk);
        assert_eq!(
            by_length.classify(&group_packet()),
            Verdict::Reflect(MessageType::MdnsQuery)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn a_suppressed_payload_is_dropped_before_the_send() {
        let _serial = loopback_lock();
        // The Dropped outcome proves the early return: a completed loopback send would be Reflected.
        let Some((mut reflector, mut dispatcher, mut reactor)) =
            reflector_over_loopback(Box::new(NoRewrite), |_| true)
        else {
            return;
        };
        assert_eq!(
            reflector.on_packet(&group_packet(), &mut dispatcher, &mut reactor),
            Outcome::Dropped(MessageType::MdnsResponse)
        );
    }

    /// A rewrite that replaces the payload wholesale, standing in for a DIAL rewrite that spliced
    /// in the proxy's own listener.
    struct ReplaceRewrite;

    impl ReplyRewrite for ReplaceRewrite {
        fn rewrite<'a>(
            &'a mut self,
            _: &[u8],
            _: CaptureKey,
            _: &mut PacketDispatcher,
            _: &mut Reactor,
        ) -> Option<&'a [u8]> {
            Some(b"REWRITTEN")
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn a_rewritten_payload_is_exempt_from_suppression() {
        // The rewrite spliced in our own egress-side listener, reachable from that link whatever
        // its address class, so the gate must not even be consulted. The tracking fn (would-be
        // suppressing) proves it: a fn pointer can't capture, hence the static.
        static SUPPRESS_CONSULTED: AtomicBool = AtomicBool::new(false);
        fn tracking_suppress(_: &[u8]) -> bool {
            SUPPRESS_CONSULTED.store(true, Ordering::Relaxed);
            true
        }
        let _serial = loopback_lock();
        let Some((mut reflector, mut dispatcher, mut reactor)) =
            reflector_over_loopback(Box::new(ReplaceRewrite), tracking_suppress)
        else {
            return;
        };
        let outcome = reflector.on_packet(&group_packet(), &mut dispatcher, &mut reactor);
        assert!(
            !SUPPRESS_CONSULTED.load(Ordering::Relaxed),
            "the gate ran on a rewritten payload"
        );
        // And the exempt payload completed the reflect: it was sent, not merely spared the gate.
        assert_eq!(outcome, Outcome::Reflected(MessageType::MdnsResponse));
    }
}
