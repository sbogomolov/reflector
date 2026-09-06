//! Packet dispatch: the routing layer between captures and reflectors.
//!
//! [`PacketDispatcher`] is the single owner of every interface [`Capture`] (each linked
//! to its interface and addressed by a `Copy` [`CaptureKey`]) and of the routing
//! registrations. When an interface's fd is readable, [`drain_and_route`] takes that
//! capture *out* of the table, drains it, parses each frame into a [`Packet`], and
//! offers it to every registration whose [`Filter`] matches. A matching reflector
//! re-emits on the opposite interface via [`send`], keyed.
//!
//! Taking the ingress capture out is load-bearing: the parsed `Packet` then borrows a
//! local, not `self`, so `&mut PacketDispatcher` is free to hand to a reflector, which
//! can send on the *other* captures still in the table and register further work. The
//! reflector never owns an fd; the fd lives in exactly one `Capture`, reached by key.
//! `egress == ingress` can't arise: reflectors bridge A→B, never A→A. If it did, the
//! key resolves to the taken-out `None` slot and the send is a logged drop, not UB.
//!
//! [`drain_and_route`]: PacketDispatcher::drain_and_route
//! [`send`]: PacketDispatcher::send

mod counters;
mod datagram;
mod dial_context;
mod interface_table;
mod multicast;

#[cfg(test)]
mod pair_tests;

pub(crate) use self::counters::{MessageType, Outcome};
pub(crate) use self::datagram::DatagramSource;
pub(crate) use self::dial_context::{DialContext, DialProxyKey};
pub(crate) use self::multicast::{join_capped, join_deferrable};

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use crate::capture::{Capture, Read};
use crate::interface::{InterfaceAddresses, InterfaceEvent, InterfaceMonitor};
use crate::linear_map::LinearMap;
use crate::net::LinkType;
use crate::net::mac::{MacAddr, MacSet};
use crate::net::packet::Packet;
use crate::reactor::{Arena, ControlEvent, Handler, Key, Reactor, ReadyEvent};

use self::counters::log_counters;
use self::datagram::{build_udp, ethernet_dst};
use self::interface_table::{InterfaceTable, SentFrame};

/// The most frames drained per readable event before yielding, so a flooded interface
/// can't starve the others. `AF_PACKET` stops here and the level-triggered wait
/// re-reports the rest; BPF finishes its current userland batch past this, since the
/// wait won't re-fire for those already-read records.
const MAX_FRAMES_PER_EVENT: u32 = 64;

/// The reactor `user_data` for the interface monitor's fd. A [`CaptureKey`] packs a `u32`
/// (via [`to_u64`](CaptureKey::to_u64)), so `u64::MAX` never collides with a real capture.
const MONITOR_TAG: u64 = u64::MAX;

/// The reconcile's periodic floor: the guarantee that an interface recreation whose every
/// event was lost (macOS's silent route-socket overflow) is still detected. Cheap while
/// healthy -- one name lookup per watched interface plus one kernel probe per capture.
const RECONCILE_TICK: Duration = Duration::from_secs(30);

/// The reconcile cadence while an interface is parked absent or a rebuild step failed: the
/// retry driver that picks up the interface's return and re-attempts failed re-binds.
const RECONCILE_RETRY: Duration = Duration::from_secs(1);

/// A `Copy` handle to a capture the dispatcher owns: an index into the interface table's
/// captures. A newtype, not a bare alias, so it can't be passed where an [`InterfaceKey`](interface_table::InterfaceKey)
/// or a reactor key is expected, where it would silently miss instead of failing to
/// compile. Captures are insert-only, so the index is a stable identity (no generation).
/// Reflectors hold these for the interface(s) they egress on and send by key, never
/// touching an fd directly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct CaptureKey(u32);

impl CaptureKey {
    /// Pack into the reactor's opaque `user_data` slot, recoverable via
    /// [`from_u64`](Self::from_u64). With no generation to carry, this is a trivial widen,
    /// kept as a named seam so the reactor wiring stays unchanged.
    #[must_use]
    fn to_u64(self) -> u64 {
        u64::from(self.0)
    }

    /// Reconstruct a key packed by [`to_u64`](Self::to_u64); also how a test mints a synthetic key
    /// for a capture it never opens (the value is only resolved against the table on a real drain).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn from_u64(packed: u64) -> Self {
        CaptureKey(packed as u32)
    }
}

/// A `Copy` handle to a routing registration: the generational arena [`Key`] of its slot, newtyped
/// so it can't be confused with a reactor key or a [`CaptureKey`]. Returned by
/// [`register`](PacketDispatcher::register); the SSDP search reflector will hold it to
/// [`unregister`](PacketDispatcher::unregister) a per-searcher response registration when its
/// session ends.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct RegistrationKey(Key);

/// A non-empty set of one filter field's accepted values, so a single registration can span several:
/// mDNS's two multicast groups (`dst_ip`), or `WoL`'s ports (`dst_port`). A one-element set pins a
/// single value.
#[derive(Clone)]
pub(crate) struct FilterSet<T>(Box<[T]>);

impl<T> Deref for FilterSet<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<T> for FilterSet<T> {
    fn from(value: T) -> Self {
        FilterSet(Box::new([value]))
    }
}

impl<T, const N: usize> From<[T; N]> for FilterSet<T> {
    fn from(values: [T; N]) -> Self {
        FilterSet(Box::from(values))
    }
}

impl<T> FromIterator<T> for FilterSet<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        FilterSet(iter.into_iter().collect())
    }
}

/// The `dst_ip` filter set: the multicast groups one handler serves.
pub(crate) type IpSet = FilterSet<IpAddr>;
/// The `dst_port` filter set: the ports one handler serves.
pub(crate) type PortSet = FilterSet<u16>;

/// An optional-field packet filter: an unset field
/// matches anything. A `src_mac`/`dst_mac` filter never matches a `DLT_NULL` packet,
/// which has no L2 addresses. `dst_ip`/`dst_port` match membership in their [`FilterSet`].
#[derive(Clone, Default)]
pub(crate) struct Filter {
    pub(crate) src_ip: Option<IpAddr>,
    pub(crate) dst_ip: Option<IpSet>,
    pub(crate) src_port: Option<u16>,
    pub(crate) dst_port: Option<PortSet>,
    /// Allow-set on the source MAC: the packet's source must be a member.
    pub(crate) src_mac: Option<MacSet>,
    pub(crate) dst_mac: Option<MacAddr>,
    /// Require an IPv4 broadcast destination, see [`Packet::is_broadcast`].
    pub(crate) broadcast: bool,
}

impl Filter {
    /// Whether `p` satisfies every set field (an unset field matches anything), given the ingress's
    /// directed broadcast for the `broadcast` field on a link without MACs.
    fn matches(&self, p: &Packet, ingress_directed_broadcast: Option<Ipv4Addr>) -> bool {
        (!self.broadcast || p.is_broadcast(ingress_directed_broadcast))
            && self.src_ip.is_none_or(|ip| p.source.ip() == ip)
            && self
                .dst_ip
                .as_ref()
                .is_none_or(|set| set.contains(&p.dest.ip()))
            && self.src_port.is_none_or(|port| p.source.port() == port)
            && self
                .dst_port
                .as_ref()
                .is_none_or(|set| set.contains(&p.dest.port()))
            && self
                .src_mac
                .as_ref()
                .is_none_or(|set| p.src_mac.is_some_and(|mac| set.contains(&mac)))
            && self.dst_mac.is_none_or(|mac| p.dst_mac == Some(mac))
    }
}

/// A reflector: re-emits matching packets on its egress capture(s) via
/// `dispatcher.send(key, ..)`, and may register further work through `&mut Dispatcher`
/// / `&mut Reactor`. Called only after a registration's filter matches.
pub(crate) trait PacketHandler {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) -> Outcome;

    /// The earliest instant this handler wants [`on_deadline`](Self::on_deadline) called, or `None`
    /// (the default) if it keeps no timer. The dispatcher reports the soonest of these to the reactor,
    /// which waits within it, so a handler tracking timed state (e.g. expiring sessions) is swept on
    /// time without polling.
    fn next_deadline(&self) -> Option<Instant> {
        None
    }

    /// `now` has reached this handler's [`next_deadline`](Self::next_deadline). As in `on_packet`, it
    /// gets `&mut PacketDispatcher` (to send / register / unregister) and `&mut Reactor`.
    fn on_deadline(
        &mut self,
        _now: Instant,
        _dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) {
    }

    /// One of `captures` was rebound to a recreated interface or had an address moved, so any state
    /// this handler pinned to it (a reserved port, a response registration) may be stale. The search
    /// reflectors drop their sessions on that interface; most handlers re-resolve per packet and keep
    /// nothing, so the default is a no-op. Broadcast to every handler after the dispatcher has already
    /// repaired the table, so `dispatcher` reads current state.
    fn on_iface_change(
        &mut self,
        _captures: &[CaptureKey],
        _dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) {
    }
}

/// One routing registration: the ingress it applies to, its filter, and the reflector
/// it gates. The handler is taken out of its slot for its call (so the dispatcher is
/// free to pass `&mut self`), mirroring the reactor's take-out one level down.
struct Registration {
    ingress: CaptureKey,
    filter: Filter,
    handler: Option<Box<dyn PacketHandler>>,
}

/// The periodic counter-summary schedule: log every capture's counts every `interval`. Held as an
/// `Option` on the dispatcher; `None` disables reporting, and the counters accrue regardless.
struct CounterReport {
    interval: Duration,
    next: Instant,
}

/// Owns the interface table and the routing registrations. The sole owner of capture fds:
/// egress goes through [`send`](Self::send), keyed.
pub(crate) struct PacketDispatcher {
    table: InterfaceTable,
    registrations: Arena<Registration>,
    /// Reused scratch for [`route`](Self::route)'s per-packet snapshot of the live registration
    /// keys, taken once at the start of a route so a mid-route registration isn't fed the
    /// in-flight frame, and kept allocated across calls so the data path doesn't allocate per packet.
    route_keys: Vec<RegistrationKey>,
    /// The address-change monitor, opened best-effort in [`new`](Self::new). `None` is a
    /// degraded mode: addresses stay at their startup-resolved values.
    monitor: Option<InterfaceMonitor>,
    /// The DIAL proxy registry, shared across the SSDP advertisement/response reflectors. Empty unless a
    /// DIAL reflector is configured; the dispatcher evicts its past-grace proxies on the deadline sweep.
    dial: DialContext,
    /// The reused frame-build buffer shared by every reflector's send. One buffer serves them all:
    /// the single-threaded loop runs one `send_udp_group` at a time.
    scratch: Box<[u8]>,
    /// The periodic counter-summary schedule, or `None` when the summary is disabled.
    report: Option<CounterReport>,
    /// The largest kernel ifindex seen: the watched interfaces' own, raised by every drained
    /// notification. On monotonic platforms ([`InterfaceMonitor::INDEXES_MONOTONIC`]) an
    /// unknown-index Link event at or below this ceiling is churn on an existing unwatched
    /// interface, not a creation, so it doesn't trigger the reconcile.
    max_seen_ifindex: u32,
    /// When the next reconcile pass is due: the [`RECONCILE_TICK`] floor when healthy,
    /// [`RECONCILE_RETRY`] while an interface is parked absent or a rebuild step failed, `now`
    /// when a capture read error pulls it forward.
    next_reconcile: Instant,
    /// The number of the packet being routed, from 1: the scope of the duplicate-send check in
    /// [`send_udp`](Self::send_udp).
    packet: u64,
    /// Whether [`route`](Self::route) is running; a send outside it (a timer, a session) is
    /// never a duplicate of a packet's re-emit.
    routing: bool,
}

impl PacketDispatcher {
    /// A dispatcher with no captures yet. Opens the interface monitor up front, before the
    /// first [`add_capture`](Self::add_capture) resolve, so a change during startup is
    /// already queued rather than missed.
    pub(crate) fn new() -> Self {
        Self::with_table(InterfaceTable::new())
    }

    /// A dispatcher that joins no multicast group: `--no-join`.
    pub(crate) fn without_group_joins() -> Self {
        Self::with_table(InterfaceTable::without_group_joins())
    }

    fn with_table(table: InterfaceTable) -> Self {
        Self {
            table,
            registrations: Arena::new(),
            route_keys: Vec::new(),
            monitor: Self::open_monitor(),
            dial: DialContext::new(),
            scratch: vec![0u8; crate::net::MAX_FRAME_LEN].into_boxed_slice(),
            report: None,
            max_seen_ifindex: 0,
            next_reconcile: Instant::now() + RECONCILE_TICK,
            packet: 0,
            routing: false,
        }
    }

    /// Enable the periodic counter summary: log each capture's counts every `interval`, first firing
    /// `interval` after `now`. Called from [`run`](crate::run) when the config sets a positive
    /// interval; the counters accrue regardless, so this controls only whether they are reported.
    pub(crate) fn enable_counter_report(&mut self, interval: Duration, now: Instant) {
        self.report = Some(CounterReport {
            interval,
            next: now + interval,
        });
    }

    /// Open the address-change monitor. Best-effort: a failure logs and yields `None`, and the
    /// daemon then runs on its startup-resolved addresses (no live updates), never aborting.
    fn open_monitor() -> Option<InterfaceMonitor> {
        match InterfaceMonitor::open() {
            Ok(monitor) => {
                log::debug!("interface monitor installed");
                Some(monitor)
            }
            Err(e) => {
                log::warn!("interface monitor unavailable; addresses won't refresh on change: {e}");
                None
            }
        }
    }

    /// Hand a capture to the dispatcher; the returned key is how reflectors send on it. The
    /// capture's interface is found-or-created from its [`if_name`](Capture::if_name), so
    /// captures on the same interface share one [`Interface`](crate::interface::Interface) record.
    ///
    /// # Errors
    /// Propagates a resolution syscall failure when first opening the capture's interface.
    pub(crate) fn add_capture(&mut self, capture: Capture) -> io::Result<CaptureKey> {
        let interface = self.table.find_or_add_interface(capture.if_name())?;
        let key = self.table.add_capture(capture, interface);
        // Seed the seen-index ceiling with the watched interfaces' own identities.
        self.max_seen_ifindex = self
            .max_seen_ifindex
            .max(self.table.interface_index(interface).unwrap_or(0));
        if let Some(name) = self.table.interface_name(interface) {
            log::debug!("watching {name} as capture {key:?}");
        }
        Ok(key)
    }

    /// Each capture's `(fd, user_data)` for [`Reactor::register_with_fds`]: the reactor
    /// watches them all under the dispatcher's one handler key, tagging each with its
    /// [`CaptureKey`] so `on_readable` recovers the capture without a lookup. The address
    /// monitor's fd, when it opened, rides along under [`MONITOR_TAG`].
    pub(crate) fn capture_watches(&self) -> Vec<(RawFd, u64)> {
        let mut watches = self.table.capture_watches();
        if let Some(monitor) = &self.monitor {
            watches.push((monitor.as_raw_fd(), MONITOR_TAG));
        }
        watches
    }

    /// Register `handler`, gated by `filter`, for packets captured on `ingress`. The returned
    /// [`Key`] removes it again via [`unregister`](Self::unregister), for the per-searcher response
    /// registrations the SSDP search reflector creates dynamically; a static reflector ignores it.
    pub(crate) fn register(
        &mut self,
        ingress: CaptureKey,
        filter: Filter,
        handler: Box<dyn PacketHandler>,
    ) -> RegistrationKey {
        RegistrationKey(self.registrations.insert(Registration {
            ingress,
            filter,
            handler: Some(handler),
        }))
    }

    /// Remove the registration `key` addresses, freeing its slot; a stale key is a safe no-op.
    /// Tears down a per-searcher response registration when its session expires.
    pub(crate) fn unregister(&mut self, key: RegistrationKey) {
        self.registrations.remove(key.0);
    }

    /// Join `group`'s multicast membership on the interface behind `capture`, so the raw capture
    /// is admitted the group's frames. Records the group for re-attempt when the interface's
    /// addresses next change. A reflector calls this at build, once per group per interface.
    ///
    /// # Errors
    /// Propagates the join's OS error. A family with no address yet is *not* an error: it's
    /// recorded and retried on the next address-up event; only a hard failure surfaces here.
    pub(crate) fn join_group(&mut self, capture: CaptureKey, group: IpAddr) -> io::Result<()> {
        let Some(interface) = self.table.interface_of(capture) else {
            log::warn!("join_group: capture {capture:?} unknown; group {group} not joined");
            return Ok(());
        };
        self.table.join_on(interface, group)
    }

    /// Inject `frame` on the capture `egress` addresses.
    ///
    /// # Errors
    /// Returns an error if the underlying send fails. A key resolving to a drained
    /// (taken-out) or out-of-range capture is a logged drop, not an error and never UB.
    pub(crate) fn send(&self, egress: CaptureKey, frame: &[u8]) -> io::Result<()> {
        if let Some(capture) = self.table.capture(egress) {
            capture.send(frame).map_err(|e| {
                oversize_context(e, capture.if_name(), frame.len(), self.table.mtu_of(egress))
            })
        } else {
            log::warn!("egress {egress:?} unavailable (drained or unknown); frame dropped");
            Ok(())
        }
    }

    /// The MTU of the interface behind `capture`, as of its last resolution.
    pub(crate) fn interface_mtu(&self, capture: CaptureKey) -> Option<u32> {
        self.table.mtu_of(capture)
    }

    /// The current source addresses of the interface behind `egress`, for a reflector
    /// building a frame. `InterfaceAddresses` is `Copy`, so a caller reads out the fields it
    /// needs.
    pub(crate) fn egress_addrs(&self, egress: CaptureKey) -> Option<&InterfaceAddresses> {
        self.table.egress_addrs(egress)
    }

    /// The DIAL proxy registry, shared by the SSDP advertisement/response reflectors so a device gets
    /// one proxy across both paths (see [`rewrite_location`](crate::reflector::dial::rewrite_location)),
    /// paired with the name of the interface behind `target` (the proxy's egress pin). One call
    /// returns both because they come from disjoint fields of one `&mut self`: a caller could not
    /// hold the borrowed name across a second `&mut` accessor.
    pub(crate) fn dial_context(&mut self, target: CaptureKey) -> (&mut DialContext, Option<&str>) {
        let target_iface = self
            .table
            .interface_of(target)
            .and_then(|interface| self.table.interface_name(interface));
        (&mut self.dial, target_iface)
    }

    /// The kernel ifindex of the interface behind `capture`: the table's cached identity,
    /// re-pointed by the reconcile when the interface is recreated (0 while it is parked
    /// absent). The SSDP/WSD search reflectors read it per session for their IPv6 link-local
    /// reserved-port binds. `None` if the key is unknown.
    pub(crate) fn capture_ifindex(&self, capture: CaptureKey) -> Option<u32> {
        self.table.ifindex_of(capture)
    }

    /// The link-layer framing of the capture behind `egress`, so [`send_udp_group`](Self::send_udp_group)
    /// picks the matching frame builder. `None` if the key is unknown or its capture is
    /// currently taken out (mid-drain).
    pub(crate) fn link_type(&self, egress: CaptureKey) -> Option<LinkType> {
        self.table.capture(egress).map(Capture::link_type)
    }

    /// Build a UDP datagram from `source` with `dst_mac` as the L2 destination, and inject it on
    /// `egress`. The caller supplies the L2 MAC, so this serves unicast, multicast, and broadcast
    /// alike; the link framing (Ethernet vs `DLT_NULL`) follows the egress's link type, and `ttl`
    /// and `payload` are carried verbatim. Builds into the dispatcher's reused scratch buffer, so
    /// the data path never allocates. An unknown or draining egress is a logged drop, like
    /// [`send`](Self::send).
    ///
    /// # Errors
    /// Propagates a send failure, and reports a frame that can't be built from the egress's
    /// current state: no source address/MAC for the datagram, a captured source of the other
    /// family, or a payload that overflows the scratch buffer or the datagram length fields.
    pub(crate) fn send_udp(
        &mut self,
        egress: CaptureKey,
        dst: SocketAddr,
        dst_mac: MacAddr,
        source: DatagramSource,
        ttl: u8,
        payload: &[u8],
    ) -> io::Result<()> {
        // Copy the addresses out (they're `Copy`) so the borrow of the table ends before the
        // mutable borrow of `self.scratch`.
        let (Some(addrs), Some(link)) =
            (self.egress_addrs(egress).copied(), self.link_type(egress))
        else {
            log::warn!("egress {egress:?} unavailable (drained or unknown); datagram dropped");
            return Ok(());
        };
        let built = build_udp(
            &addrs,
            link,
            dst,
            dst_mac,
            source,
            ttl,
            payload,
            &mut self.scratch,
        )
        .map_err(io::Error::other)?;
        // Two entries whose legs coincide (per-device entries on one pair, whose query legs
        // carry no MAC filter) both relay a packet; the second's frame equals the first's. Noted
        // only once sent, so a failed send leaves the second to try.
        let frame = self.routing.then_some(SentFrame {
            packet: self.packet,
            len: built.len,
            checksum: built.udp_checksum,
        });
        if let Some(frame) = frame
            && self.table.is_last_sent(egress, frame)
        {
            log::trace!("egress {egress:?}: an equal frame already went out for this packet");
            return Ok(());
        }
        self.send(egress, &self.scratch[..built.len])?;
        if let Some(frame) = frame {
            self.table.set_last_sent(egress, frame);
        }
        Ok(())
    }

    /// Inject a broadcast/multicast UDP datagram on `egress`, deriving the L2 destination MAC from
    /// `dst`'s address class (all-ones for the IPv4 limited broadcast, the RFC-derived group MAC
    /// for multicast). A thin wrapper over [`send_udp`](Self::send_udp). A unicast `dst` has no
    /// derivable group MAC, so it is a [`DatagramError::UnicastDestination`](datagram::DatagramError::UnicastDestination); use `send_udp` with an
    /// explicit MAC for unicast.
    ///
    /// # Errors
    /// As [`send_udp`](Self::send_udp), plus [`DatagramError::UnicastDestination`](datagram::DatagramError::UnicastDestination) for a unicast `dst`.
    pub(crate) fn send_udp_group(
        &mut self,
        egress: CaptureKey,
        dst: SocketAddr,
        source: DatagramSource,
        ttl: u8,
        payload: &[u8],
    ) -> io::Result<()> {
        let dst_mac = self.group_mac(egress, dst)?;
        self.send_udp(egress, dst, dst_mac, source, ttl, payload)
    }

    /// The L2 destination for a broadcast/multicast `dst` on `egress`: its own directed broadcast
    /// counts as broadcast there.
    fn group_mac(&self, egress: CaptureKey, dst: SocketAddr) -> io::Result<MacAddr> {
        ethernet_dst(
            dst.ip(),
            self.egress_addrs(egress)
                .and_then(InterfaceAddresses::v4_directed_broadcast),
        )
        .map_err(io::Error::other)
    }

    /// Drain the capture `ingress` addresses and route each parsed packet. Makes up to
    /// [`MAX_FRAMES_PER_EVENT`] reads, dropped oversized frames included, then yields for
    /// fairness (the BPF batch exception is via `has_buffered`); a read error abandons the
    /// batch and logs.
    fn drain_and_route(&mut self, ingress: CaptureKey, reactor: &mut Reactor) {
        // Take the ingress capture OUT: the parsed Packet then borrows the owned local, not
        // `self`, so `&mut self` is free for routing, and a reflector can send on the OTHER
        // captures still in the table.
        let Some(mut capture) = self.table.take(ingress) else {
            if self.table.contains(ingress) {
                // In range but already taken out: a reflector re-entered the drain on its
                // own ingress, which it shouldn't; the take-out makes it a safe no-op.
                log::warn!("drain_and_route: ingress {ingress:?} already draining; skipped");
            } else {
                // Out of range: a `user_data` that names no capture reached us (a bug).
                log::warn!("drain_and_route: ingress {ingress:?} out of range; skipped");
            }
            return;
        };
        let link = capture.link_type(); // hoisted: next_frame's borrow would pin `capture`
        let fd = capture.as_raw_fd();
        let mut drained = 0u32;
        loop {
            if drained >= MAX_FRAMES_PER_EVENT && !capture.has_buffered() {
                break;
            }
            let frame = match capture.next_frame() {
                Ok(Some(Read::Frame(frame))) => frame,
                Ok(Some(Read::Oversized)) => {
                    drained += 1;
                    continue;
                }
                Ok(None) => break,
                Err(e) => {
                    // A dead capture's read error (Linux parks ENETDOWN on the unregistered
                    // packet socket; a detached BPF descriptor reads ENXIO) is the expected
                    // first sign of an interface destruction: pull the reconcile forward --
                    // it must not run from here, mid-drain, with this capture taken out of
                    // its slot. Other read errors are real failures and are left to the tick;
                    // they say nothing about the interface.
                    if matches!(e.raw_os_error(), Some(libc::ENETDOWN | libc::ENXIO)) {
                        log::info!("fd {fd}: capture lost its interface ({e}); reconciling");
                        self.next_reconcile = Instant::now();
                    } else {
                        log::error!("fd {fd}: capture read failed, abandoning batch: {e}");
                    }
                    break;
                }
            };
            match Packet::parse(link, frame) {
                // `packet` borrows the local `capture`, not `self`, so routing through
                // `&mut self` is legal.
                Ok(packet) => {
                    log::trace!(
                        "fd {fd}: routing {} -> {} ({} B)",
                        packet.source,
                        packet.dest,
                        packet.payload.len()
                    );
                    self.route(ingress, &packet, reactor);
                }
                Err(e) => log::trace!("fd {fd}: skip unparsable frame: {e}"),
            }
            drained += 1;
        }
        if drained > 0 {
            log::trace!("fd {fd}: drained {drained} frame(s)");
        }
        let oversized = capture.take_oversized();
        if oversized > 0 {
            self.table.record_oversized(ingress, oversized);
        }
        if !self.table.restore(ingress, capture) {
            log::warn!("drain_and_route: ingress {ingress:?} vanished mid-drain; capture dropped");
        }
    }

    /// Offer `packet` (captured on `ingress`) to every matching registration, in order.
    fn route(&mut self, ingress: CaptureKey, packet: &Packet, reactor: &mut Reactor) {
        // A handler is `None` only while it is out for a call, so one missing here proves a
        // handler re-entered routing (it would clear the shared `route_keys` scratch out from
        // under the outer loop). The same-ingress case bounces off the capture take-out guard;
        // this catches the cross-ingress case the guard cannot see.
        debug_assert!(
            self.registrations
                .iter()
                .all(|(_, reg)| reg.handler.is_some()),
            "route re-entered from inside a handler call"
        );
        // Our own re-emit handed back by the link (a hairpin bridge port, an access point that
        // re-broadcasts a station's multicast) arrives as an ordinary received frame, past the
        // capture's outgoing drop, and a same-direction handler on this ingress (the mirrored leg
        // of a bidirectional pair) would relay it again. Only its source MAC gives it away.
        if is_own_echo(
            packet.src_mac,
            self.table
                .egress_addrs(ingress)
                .and_then(InterfaceAddresses::mac),
        ) {
            self.table.record_echo(ingress);
            log::trace!(
                "dropping our own echoed frame {} -> {} on {ingress:?}",
                packet.source,
                packet.dest
            );
            return;
        }
        // Snapshot the live registration keys into the reused buffer. Taking them once means a
        // reflector registering mid-route isn't fed the in-flight frame (its key isn't in the
        // snapshot whether it appended or reused a freed slot), and a generational key keeps the
        // put-back safe even if a registration is removed during its own call (the key goes stale
        // and the restore is a no-op). `route` never nests: a handler sends but never re-drains,
        // so one shared buffer suffices.
        self.route_keys.clear();
        self.route_keys.extend(
            self.registrations
                .iter()
                .map(|(key, _)| RegistrationKey(key)),
        );
        let ingress_directed_broadcast = self
            .table
            .egress_addrs(ingress)
            .and_then(InterfaceAddresses::v4_directed_broadcast);
        self.packet += 1;
        self.routing = true;
        let mut final_outcome: Option<Outcome> = None;
        for i in 0..self.route_keys.len() {
            let key = self.route_keys[i];
            let applies = self.registrations.get(key.0).is_some_and(|reg| {
                reg.ingress == ingress && reg.filter.matches(packet, ingress_directed_broadcast)
            });
            if !applies {
                continue;
            }
            // Take the matched reflector out so `&mut self` is free for the call, then restore it
            // by key. `take` never misses: a `handler` is `None` only transiently while out
            // mid-call, and `route` doesn't re-enter the same registration in one pass. A `get_mut`
            // miss on the put-back means the call removed this registration: drop it, don't revive.
            let mut handler = self
                .registrations
                .get_mut(key.0)
                .expect("a key that just matched is still live")
                .handler
                .take()
                .expect("a matching registration has its handler present");
            let outcome = handler.on_packet(packet, self, reactor);
            if let Some(reg) = self.registrations.get_mut(key.0) {
                reg.handler = Some(handler);
            }
            // Fold this handler's outcome into the packet's running result (highest disposition wins),
            // logging the "can't happen under a valid config" anomalies the fold surfaces.
            final_outcome = Some(match final_outcome {
                None => outcome,
                Some(prev) => {
                    let (merged, anomalies) = prev.combine(outcome);
                    if anomalies.type_mismatch {
                        log::error!(
                            "handlers disagree on a packet's message type on {ingress:?} \
                             ({prev:?} vs {outcome:?})"
                        );
                    }
                    merged
                }
            });
        }
        self.routing = false;
        // One packet, one count: record the folded outcome on the ingress capture's row. The row
        // always exists: `route` is reached only via the drain, whose take-out guard admits only a
        // real, in-range ingress key.
        if let Some(outcome) = final_outcome {
            self.table.record(ingress, outcome);
        } else {
            // The one drop no counter covers: past the kernel filter but matching no
            // registration (e.g. a reply outliving its search session's registration).
            log::trace!(
                "no registration matched {} -> {} on {ingress:?}",
                packet.source,
                packet.dest
            );
        }
    }

    /// Drain the interface monitor and re-resolve each interface a notification names,
    /// coalescing duplicates so one interface re-resolves at most once per wakeup. An
    /// [`InterfaceEvent::Overflow`] re-resolves every interface. Best-effort: a read or
    /// resolution failure logs and is dropped, and the daemon keeps its last-known addresses.
    ///
    /// Doubles as the recreation detector: events that can announce a destroyed or recreated
    /// interface run the reconcile afterwards. A `Link` event on a watched interface, or one
    /// carrying an index above everything seen (a creation, on platforms whose indexes are
    /// monotonic), or any unknown-index event where no lifecycle messages exist (macOS), or an
    /// overflow (the announcement may be among the drops) -- and, for a recreation that reused
    /// the watched index, a per-capture kernel probe on every matched refresh.
    fn refresh_changed_interfaces(&mut self, reactor: &mut Reactor) {
        let Some(monitor) = self.monitor.as_mut() else {
            return;
        };
        // Coalesce to one ifindex -> saw-a-Link-event entry per interface.
        let mut changed: LinearMap<u32, bool> = LinearMap::new();
        let mut overflow = false;
        if let Err(e) = monitor.drain(|event| match event {
            InterfaceEvent::Overflow => overflow = true,
            InterfaceEvent::Address(ifindex) | InterfaceEvent::Link(ifindex) => {
                let is_link = matches!(event, InterfaceEvent::Link(_));
                match changed.get_mut(&ifindex) {
                    Some(link) => *link |= is_link,
                    None => {
                        changed.insert(ifindex, is_link);
                    }
                }
            }
        }) {
            // The drain already consumed and collected these notifications before failing, so refresh
            // what we have rather than discard it; the socket's unread remainder stays readable and the
            // level-triggered wait re-drains it.
            log::warn!(
                "interface monitor read failed mid-drain; refreshing what was collected: {e}"
            );
        }
        if changed.is_empty() && !overflow {
            return; // nothing collected (a spurious wakeup, or a drain error before the first read)
        }
        // The creation gate compares against the ceiling from BEFORE this batch: the creation's
        // own Link event would otherwise raise the ceiling past itself and slip through.
        let prior_ceiling = self.max_seen_ifindex;
        for (ifindex, _) in changed.iter() {
            self.max_seen_ifindex = self.max_seen_ifindex.max(*ifindex);
        }
        let mut want_reconcile = overflow;
        // The DIAL proxies bind IPv4 only, so collect the interfaces whose v4 address actually moved. A
        // routine v6 or MAC change must not churn a proxy whose v4 (and cached LOCATION) is unchanged.
        let mut v4_moved: Vec<u32> = Vec::new();
        // Interfaces whose addresses actually moved this cycle, for the session notification below:
        // search reflectors drop sessions whose reserved port was bound to a re-addressed interface.
        // Only a real address delta (either family) qualifies, not a benign Link / no-op-Address event,
        // so a healthy session survives a carrier flap or an unrelated interface's churn. (DIAL is
        // v4-only via v4_moved; sessions can be either family. Recreations are handled by the reconcile,
        // keyed by capture, so they need no entry here.)
        let mut touched: Vec<u32> = Vec::new();
        if overflow {
            // Notifications were dropped, so re-resolve every interface.
            log::debug!("interface monitor overflow; re-resolving all interfaces");
            for (ifindex, result) in self.table.refresh_all() {
                match result {
                    Ok(change) => {
                        if change.v4 {
                            v4_moved.push(ifindex);
                        }
                        if change.v4 || change.v6 {
                            touched.push(ifindex);
                        }
                    }
                    Err(e) => {
                        // The overflow already means notifications were dropped, so this is the one
                        // chance to catch a move whose event was lost, and we can't confirm the address
                        // survived. Treat it as moved so any DIAL proxy re-mints and any session drops
                        // rather than keeping a listener bound to a possibly-vanished address.
                        log::warn!(
                            "re-resolving ifindex {ifindex} failed: {e}; evicting its proxies"
                        );
                        v4_moved.push(ifindex);
                        touched.push(ifindex);
                    }
                }
            }
        } else {
            for (ifindex, is_link) in changed.iter() {
                match self.table.refresh_by_ifindex(*ifindex) {
                    Ok(Some(change)) => {
                        log::debug!("re-resolved interface (ifindex {ifindex}) after a change");
                        if change.v4 {
                            v4_moved.push(*ifindex);
                        }
                        // Only a real address delta invalidates a session's reserved reply address; a
                        // bare Link event (carrier / MTU / flag) with no delta must not clear sessions.
                        if change.v4 || change.v6 {
                            touched.push(*ifindex);
                        }
                        // A lifecycle event on a watched interface, or a capture whose kernel
                        // binding died behind this (possibly reused) index: reconcile.
                        if *is_link || !self.table.probe_by_ifindex(*ifindex) {
                            want_reconcile = true;
                        }
                    }
                    Ok(None) => {
                        // An interface we don't watch -- unless it is one of ours, recreated
                        // under a new index. A Link event above every index seen so far is a
                        // creation where indexes are monotonic; where they aren't (FreeBSD),
                        // any Link announcement reconciles; where lifecycle events don't
                        // exist at all (macOS), any unknown-index event has to.
                        let creation = if InterfaceMonitor::INDEXES_MONOTONIC {
                            *is_link && *ifindex > prior_ceiling
                        } else {
                            *is_link
                        };
                        if creation || !InterfaceMonitor::LIFECYCLE_EVENTS {
                            want_reconcile = true;
                        }
                    }
                    Err(e) => {
                        // Same conservative stance as the overflow branch: a failed re-resolve can't
                        // confirm the bound v4 survived (a notification arrived, so something changed),
                        // so evict any proxy on it rather than risk a stale, silently-dead listener.
                        // Reconcile, since it can't confirm the interface survived either.
                        log::warn!(
                            "re-resolving ifindex {ifindex} failed: {e}; evicting its proxies"
                        );
                        v4_moved.push(*ifindex);
                        touched.push(*ifindex);
                        want_reconcile = true;
                    }
                }
            }
        }
        // Evict proxies whose source or target interface lost the v4 address they bound, and drop
        // search sessions whose reserved port was bound to a re-addressed interface. Both keyed by
        // capture, materialized before the reconcile rewrites the table's caches so the ifindexes here
        // still map to the pre-change identities. A recreation under a new index resolves to no capture
        // here and is handled by the reconcile below.
        let v4_captures = self.captures_for(&v4_moved);
        self.dial.evict_on_interface_change(
            reactor,
            &v4_captures,
            "after its interface's address changed",
        );
        let touched_captures = self.captures_for(&touched);
        self.notify_iface_change(&touched_captures, reactor);
        if want_reconcile {
            self.reconcile_interfaces(reactor);
        }
    }

    /// The captures on the interfaces currently at `ifindexes`, mapping the refresh path's kernel
    /// indexes to the stable [`CaptureKey`]s the eviction and session notification are keyed by.
    fn captures_for(&self, ifindexes: &[u32]) -> Vec<CaptureKey> {
        ifindexes
            .iter()
            .flat_map(|ifindex| self.table.captures_at_ifindex(*ifindex))
            .collect()
    }

    /// Broadcast [`PacketHandler::on_iface_change`] to every registered handler for the interfaces
    /// backing `captures`, taking each handler out for its call so `&mut self` is free. Off the data
    /// path (only the interface-change / reconcile path, which allocates anyway), so it snapshots the
    /// live keys into a fresh `Vec` rather than a reused scratch. A handler that unregisters a sibling
    /// mid-broadcast (a search reflector dropping its sessions' response registrations) is fine: the vacated
    /// slot is skipped.
    fn notify_iface_change(&mut self, captures: &[CaptureKey], reactor: &mut Reactor) {
        if captures.is_empty() {
            return;
        }
        let keys: Vec<RegistrationKey> = self
            .registrations
            .iter()
            .map(|(key, _)| RegistrationKey(key))
            .collect();
        for key in keys {
            let Some(mut handler) = self
                .registrations
                .get_mut(key.0)
                .and_then(|reg| reg.handler.take())
            else {
                // Expected, not an error: an earlier reflector in this broadcast cleared its sessions
                // and unregistered their response registrations, which are in this snapshot, so they resolve
                // to None here. Mirrors on_deadline's mid-sweep skip.
                log::trace!(
                    "iface-change broadcast: handler for {key:?} gone mid-broadcast, skipped"
                );
                continue;
            };
            handler.on_iface_change(captures, self, reactor);
            if let Some(reg) = self.registrations.get_mut(key.0) {
                reg.handler = Some(handler);
            }
        }
    }

    /// Detect and repair interfaces whose kernel identity moved out from under the table: the
    /// recreation recovery. Each stale entry is re-pointed at its name's current interface (or
    /// parked absent), its captures re-bound in place behind their stable keys, and its DIAL
    /// proxies evicted -- their mint-time snapshots (listener binds, target address, egress
    /// pin) died with the old interface, whatever the new one's values. Re-arms the next pass:
    /// the [`RECONCILE_TICK`] floor when healthy, [`RECONCILE_RETRY`] while an interface is
    /// absent or a rebuild step failed (the probe keeps re-flagging a half-rebuilt entry).
    fn reconcile_interfaces(&mut self, reactor: &mut Reactor) {
        let mut pending = false;
        for stale in self.table.stale_interfaces() {
            let name = self
                .table
                .interface_name(stale.key)
                .expect("stale keys come from this table's own scan")
                .to_owned();
            let captures = self.table.captures_of(stale.key);
            let mut failed = false;
            match (stale.cached, stale.cur) {
                (was, 0) => {
                    log::info!(
                        "interface {name} is gone (was ifindex {was}); parking until it returns"
                    );
                }
                (0, now) => {
                    log::info!("interface {name}: returned as ifindex {now}; re-binding");
                }
                (was, now) => {
                    log::info!("interface {name}: recreated (ifindex {was} -> {now}); re-binding");
                }
            }
            match self.table.rebind_interface(stale.key, stale.cur) {
                // Both kinds are retried on every later address event, but only a deferral has a
                // trigger that will resolve it, so only that one may promise a retry.
                Ok(counts) => {
                    if counts.failed > 0 {
                        log::warn!(
                            "{} group membership(s) on {name} did not re-join; that traffic is \
                             not reflected until they do",
                            counts.failed
                        );
                    }
                    if counts.deferred > 0 {
                        log::warn!(
                            "{} group membership(s) on {name} not re-joined yet; retrying \
                             on its next address event",
                            counts.deferred
                        );
                    }
                }
                Err(e) => {
                    log::warn!("re-resolving {name} failed: {e}; will retry");
                    failed = true;
                }
            }
            if stale.cur != 0 {
                for capture in &captures {
                    match self.table.rebind_capture(*capture) {
                        Ok(true) => {}
                        Ok(false) => {
                            log::warn!("capture {capture:?} missing during {name}'s rebuild");
                        }
                        Err(e) => {
                            log::warn!("re-binding a capture on {name} failed: {e}; will retry");
                            failed = true;
                        }
                    }
                }
            }
            // The proxies' snapshots reference the dead interface regardless of what the
            // replacement resolves to, so the eviction is keyed by capture, not by address
            // deltas (and not through v4_moved, whose indexes predate the rebuild).
            let reason = if stale.cur == 0 {
                "after its interface was removed"
            } else {
                "after its interface was recreated"
            };
            self.dial
                .evict_on_interface_change(reactor, &captures, reason);
            // Drop search sessions on the interface's captures: their reserved port and response
            // registration belonged to the interface that was removed or recreated (even one that
            // returned on the same index, which the reconcile reached via the attached() probe).
            self.notify_iface_change(&captures, reactor);
            if stale.cur != 0 && !failed {
                for capture in &captures {
                    self.table.record_recovery(*capture);
                }
                log::info!("interface {name}: recovery complete");
            }
            pending |= failed;
        }
        // The fast cadence also covers parked interfaces (quiescent, so not in the stale list):
        // their return must be picked up promptly even if every event for it is lost.
        let retry = pending || self.table.any_absent();
        self.next_reconcile = Instant::now()
            + if retry {
                RECONCILE_RETRY
            } else {
                RECONCILE_TICK
            };
    }
}

impl Handler for PacketDispatcher {
    /// [`MONITOR_TAG`] routes to an address-monitor drain; otherwise `event.user_data` is the
    /// ready capture's [`CaptureKey`] (tagged at registration), so drain that capture
    /// directly, no fd lookup. A bad capture value resolves to a stale key and is a logged
    /// drop in [`drain_and_route`](Self::drain_and_route).
    fn on_readable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
        if event.user_data == MONITOR_TAG {
            self.refresh_changed_interfaces(reactor);
        } else {
            self.drain_and_route(CaptureKey::from_u64(event.user_data), reactor);
        }
    }

    /// The soonest deadline any registered handler keeps; the reactor waits within it.
    fn next_deadline(&self) -> Option<Instant> {
        // O(registrations) every run-loop iteration. n is bounded by MAX_SESSIONS per search
        // reflector (SSDP and WSD each, per reflector pair) plus a few base handlers, so a
        // fan-out config carries hundreds. The scan still beats a min-heap, whose O(1) peek isn't
        // worth the entry invalidation a cancelled or moved deadline would force. Revisit if
        // timers grow.
        self.registrations
            .iter()
            .filter_map(|(_, reg)| reg.handler.as_ref().and_then(|h| h.next_deadline()))
            .chain(self.dial.next_grace()) // and the soonest DIAL proxy grace, for its eviction sweep
            .chain(self.report.as_ref().map(|r| r.next)) // and the next counter summary, if enabled
            .chain(Some(self.next_reconcile)) // and the interface reconcile tick
            .min()
    }

    /// Fire [`PacketHandler::on_deadline`] on every registration whose deadline has reached `now`,
    /// taking each handler out for its call (as `route` does) so `&mut self` is free. Reached at most
    /// about once a second and only while a handler keeps a timer, so the snapshot allocation is off
    /// the data path. A registration removed during its own call isn't restored.
    fn on_deadline(&mut self, now: Instant, reactor: &mut Reactor) {
        let due: Vec<RegistrationKey> = self
            .registrations
            .iter()
            .filter(|(_, reg)| {
                reg.handler
                    .as_ref()
                    .and_then(|h| h.next_deadline())
                    .is_some_and(|d| d <= now)
            })
            .map(|(key, _)| RegistrationKey(key))
            .collect();
        for key in due {
            // Gone if an earlier handler in this sweep unregistered it (a sibling, or itself).
            let Some(mut handler) = self
                .registrations
                .get_mut(key.0)
                .and_then(|reg| reg.handler.take())
            else {
                log::trace!("deadline sweep: handler for {key:?} gone mid-sweep, skipped");
                continue;
            };
            handler.on_deadline(now, self, reactor);
            if let Some(reg) = self.registrations.get_mut(key.0) {
                reg.handler = Some(handler);
            }
        }
        self.dial.sweep(now, reactor); // evict DIAL proxies whose advertisement grace has lapsed

        // The periodic counter summary, when enabled and due.
        if let Some(report) = &mut self.report
            && now >= report.next
        {
            log_counters(self.table.counter_rows());
            report.next = now + report.interval;
        }

        // The interface reconcile tick (it re-arms itself): the detection floor for
        // recreations whose events were lost, and the retry driver while one is mid-recovery.
        if now >= self.next_reconcile {
            self.reconcile_interfaces(reactor);
        }
    }

    /// A SIGUSR1 diagnostics dump: log the per-interface counter summary on demand. Independent of the
    /// periodic report's interval (the counters accrue regardless), so it works even when unconfigured.
    fn on_control(&mut self, event: ControlEvent, _reactor: &mut Reactor) {
        match event {
            ControlEvent::Dump => log_counters(self.table.counter_rows()),
        }
    }
}

/// Whether a captured frame is one of our own re-emits handed back by the link: its source MAC is
/// the ingress interface's own. The all-zero address is exempt: Linux reports it as a loopback's
/// hardware address and every loopback frame carries it, so it identifies nothing.
fn is_own_echo(src_mac: Option<MacAddr>, own_mac: Option<MacAddr>) -> bool {
    match (src_mac, own_mac) {
        (Some(src), Some(own)) => src == own && !own.is_unspecified(),
        _ => false,
    }
}

/// Re-word an `EMSGSIZE` send failure to name the frame, the interface, and its MTU (as of the
/// interface's last resolution); the bare "Message too long" names none of them. Any other error
/// passes through.
fn oversize_context(e: io::Error, if_name: &str, frame_len: usize, mtu: Option<u32>) -> io::Error {
    if e.raw_os_error() != Some(libc::EMSGSIZE) {
        return e;
    }
    let mtu = mtu.map_or_else(String::new, |mtu| format!(" (MTU {mtu})"));
    io::Error::new(
        e.kind(),
        format!("a frame of {frame_len} bytes exceeds what {if_name}{mtu} can carry"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{loopback_lock, open_or_skip};
    use crate::interface::LOOPBACK_IFACE;
    use std::cell::{Cell, RefCell};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    impl PacketDispatcher {
        /// The number of live routing registrations, a seam for the SSDP session lifecycle tests.
        pub(crate) fn registration_count(&self) -> usize {
            self.registrations.iter().count()
        }
    }

    // The reconcile detects a cached identity that moved (corrupted here through the test
    // seam, as a recreation would move it) and repairs it in place, then re-arms the slow
    // tick. Unprivileged: resolution only, no captures.
    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn reconcile_repairs_a_moved_identity_and_arms_the_slow_tick() -> io::Result<()> {
        let mut reactor = Reactor::new()?;
        let mut dispatcher = PacketDispatcher::new();
        let key = dispatcher.table.find_or_add_interface(LOOPBACK_IFACE)?;
        let real = crate::interface::if_index(LOOPBACK_IFACE).expect("loopback has an ifindex");
        dispatcher.table.set_test_ifindex(key, real + 1000);
        assert!(!dispatcher.table.stale_interfaces().is_empty());

        dispatcher.reconcile_interfaces(&mut reactor);

        assert!(
            dispatcher.table.stale_interfaces().is_empty(),
            "the moved identity is repaired"
        );
        assert!(
            dispatcher.next_reconcile > Instant::now() + RECONCILE_RETRY,
            "a healthy table re-arms the slow tick, not the retry"
        );
        Ok(())
    }

    // A vanished interface parks (identity 0, quiescent thereafter) and keeps the fast retry
    // cadence armed, so its return is picked up promptly even with every event lost.
    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn reconcile_parks_a_vanished_interface_and_keeps_the_fast_retry() -> io::Result<()> {
        let mut reactor = Reactor::new()?;
        let mut dispatcher = PacketDispatcher::new();
        let key = dispatcher.table.find_or_add_interface(LOOPBACK_IFACE)?;
        dispatcher.table.set_test_name(key, "netflector-gone0");

        dispatcher.reconcile_interfaces(&mut reactor);

        assert!(
            dispatcher.table.stale_interfaces().is_empty(),
            "a parked entry is quiescent, not perpetually stale"
        );
        assert!(dispatcher.table.any_absent());
        assert!(
            dispatcher.next_reconcile <= Instant::now() + RECONCILE_RETRY,
            "an absent interface keeps the fast retry cadence"
        );
        // The interface "returns" (the name resolves again): the next pass rebuilds it.
        dispatcher.table.set_test_name(key, LOOPBACK_IFACE);
        dispatcher.reconcile_interfaces(&mut reactor);
        assert!(
            !dispatcher.table.any_absent(),
            "the returned interface is re-pointed"
        );
        assert!(
            dispatcher.next_reconcile > Instant::now() + RECONCILE_RETRY,
            "recovery re-arms the slow tick"
        );
        Ok(())
    }

    // A completed recovery bumps the recoveries count on each of the interface's capture rows.
    // Unprivileged: the moved identity is faked through the test seam and the capture row is a
    // capture-less test entry (rebind_capture reports it missing, which does not fail the recovery).
    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn reconcile_counts_a_recovery_on_the_interface_captures() -> io::Result<()> {
        let mut reactor = Reactor::new()?;
        let mut dispatcher = PacketDispatcher::new();
        let key = dispatcher.table.find_or_add_interface(LOOPBACK_IFACE)?;
        let capture = dispatcher.table.add_test_capture(); // links the first interface
        assert_eq!(dispatcher.table.recoveries_of(capture), 0);
        let real = crate::interface::if_index(LOOPBACK_IFACE).expect("loopback has an ifindex");
        dispatcher.table.set_test_ifindex(key, real + 1000); // as a recreation would move it

        dispatcher.reconcile_interfaces(&mut reactor);

        assert_eq!(
            dispatcher.table.recoveries_of(capture),
            1,
            "the completed recovery is counted on the interface's capture row"
        );
        Ok(())
    }

    fn packet(
        source: &str,
        dest: &str,
        dst_mac: Option<MacAddr>,
        src_mac: Option<MacAddr>,
    ) -> Packet<'static> {
        Packet {
            source: source.parse().unwrap(),
            dest: dest.parse().unwrap(),
            ttl: 64,
            dst_mac,
            src_mac,
            payload: b"",
        }
    }

    /// A loopback probe rig: a bound `receiver` (its port reserved so the probe has a real
    /// destination; the probe is captured off `lo`, never recv'd), the `target` to send to,
    /// and a `sender`. The caller holds the receiver alive for the test's duration.
    fn probe_rig() -> io::Result<(UdpSocket, SocketAddr, UdpSocket)> {
        let receiver = UdpSocket::bind("127.0.0.1:0")?;
        let target = receiver.local_addr()?;
        let sender = UdpSocket::bind("127.0.0.1:0")?;
        Ok((receiver, target, sender))
    }

    /// Call `step`, then sleep 20 ms, until `done` is true or `secs` elapse: the drive loop
    /// for a non-blocking driver like `drain_and_route`. (The reactor test's `poll_once` loop
    /// blocks on its own timeout instead, so it isn't routed through here.)
    fn pump_until(secs: u64, mut done: impl FnMut() -> bool, mut step: impl FnMut()) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while !done() && Instant::now() < deadline {
            step();
            if !done() {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    #[test]
    fn wildcard_filter_matches_anything() {
        assert!(Filter::default().matches(&packet("10.0.0.1:1", "10.0.0.2:2", None, None), None));
    }

    #[test]
    fn filter_matches_destination_group_and_port() {
        let f = Filter {
            dst_ip: Some("224.0.0.251".parse::<IpAddr>().unwrap().into()),
            dst_port: Some(5353.into()),
            ..Filter::default()
        };
        assert!(f.matches(
            &packet("10.0.0.1:5353", "224.0.0.251:5353", None, None),
            None
        ));
        // Wrong group, and wrong port, each miss.
        assert!(!f.matches(
            &packet("10.0.0.1:5353", "224.0.0.252:5353", None, None),
            None
        ));
        assert!(!f.matches(
            &packet("10.0.0.1:5353", "224.0.0.251:1900", None, None),
            None
        ));
    }

    #[test]
    fn filter_broadcast_takes_the_all_ones_mac_or_the_limited_broadcast() {
        let f = Filter {
            broadcast: true,
            ..Filter::default()
        };
        let all_ones = Some(MacAddr::broadcast());
        let unicast = Some(MacAddr::from([0x02, 0, 0, 0, 0, 1]));
        let own = Some(Ipv4Addr::new(10, 0, 0, 255));
        // On the all-ones MAC every subnet's directed broadcast qualifies, the limited one too.
        assert!(f.matches(&packet("10.0.0.1:1", "10.0.0.255:9", all_ones, None), own));
        assert!(f.matches(&packet("10.0.1.1:1", "10.0.1.255:9", all_ones, None), own));
        assert!(f.matches(
            &packet("10.0.0.1:1", "255.255.255.255:9", all_ones, None),
            own
        ));
        // Without MACs (DLT_NULL) the address decides: the limited broadcast, or the link's own.
        assert!(f.matches(&packet("10.0.0.1:1", "255.255.255.255:9", None, None), own));
        assert!(f.matches(&packet("10.0.0.1:1", "10.0.0.255:9", None, None), own));
        assert!(!f.matches(&packet("10.0.1.1:1", "10.0.1.255:9", None, None), own));
        assert!(!f.matches(&packet("10.0.0.1:1", "10.0.0.255:9", None, None), None));
        // The frame decides, not the address's shape: a broadcast-looking address on a unicast
        // frame is unicast, a unicast-looking one on the all-ones MAC is a broadcast of a subnet
        // the sender knows.
        assert!(!f.matches(&packet("10.0.0.1:1", "10.0.0.255:9", unicast, None), own));
        assert!(f.matches(&packet("10.0.0.1:1", "10.0.0.2:9", all_ones, None), own));
        assert!(!f.matches(&packet("10.0.0.1:1", "224.0.0.251:9", None, None), own));
        // A group on the all-ones MAC is still a group: the group handler's, not this one's.
        assert!(!f.matches(&packet("10.0.0.1:1", "224.0.0.251:9", all_ones, None), own));
        assert!(!f.matches(&packet("[fe80::1]:1", "[ff02::1]:9", all_ones, None), own));
    }

    #[test]
    fn filter_dst_ip_set_matches_any_group() {
        // One handler spanning the v4 and v6 mDNS groups: either destination matches.
        let f = Filter {
            dst_ip: Some(
                [
                    "224.0.0.251".parse::<IpAddr>().unwrap(),
                    "ff02::fb".parse().unwrap(),
                ]
                .into(),
            ),
            dst_port: Some(5353.into()),
            ..Filter::default()
        };
        assert!(f.matches(
            &packet("10.0.0.1:5353", "224.0.0.251:5353", None, None),
            None
        ));
        assert!(f.matches(
            &packet("[fe80::1]:5353", "[ff02::fb]:5353", None, None),
            None
        ));
        // A group outside the set, and a member on the wrong port, each miss.
        assert!(!f.matches(
            &packet("10.0.0.1:5353", "239.255.255.250:5353", None, None),
            None
        ));
        assert!(!f.matches(
            &packet("10.0.0.1:5353", "224.0.0.251:1900", None, None),
            None
        ));
    }

    #[test]
    fn filter_dst_port_set_matches_any_port() {
        // One handler spanning WoL ports 7 and 9: either destination port matches.
        let f = Filter {
            dst_port: Some([7u16, 9].into()),
            ..Filter::default()
        };
        assert!(f.matches(&packet("10.0.0.1:1", "255.255.255.255:7", None, None), None));
        assert!(f.matches(&packet("10.0.0.1:1", "255.255.255.255:9", None, None), None));
        // A port outside the set misses.
        assert!(!f.matches(&packet("10.0.0.1:1", "255.255.255.255:8", None, None), None));
    }

    #[test]
    fn filter_matches_source_mac_and_excludes_others() {
        let device = MacAddr::from([0x02, 0, 0, 0, 0, 0x01]);
        let f = Filter {
            src_mac: Some(MacSet::from(device)),
            ..Filter::default()
        };
        assert!(f.matches(
            &packet("10.0.0.1:5353", "10.0.0.2:5353", None, Some(device)),
            None
        ));
        // A different device, and a MAC-less (DLT_NULL) packet, both miss.
        let other = MacAddr::from([0x02, 0, 0, 0, 0, 0x02]);
        assert!(!f.matches(
            &packet("10.0.0.1:5353", "10.0.0.2:5353", None, Some(other)),
            None
        ));
        assert!(!f.matches(&packet("10.0.0.1:5353", "10.0.0.2:5353", None, None), None));
    }

    #[test]
    fn filter_source_mac_set_matches_any_member() {
        let a = MacAddr::from([0x02, 0, 0, 0, 0, 0x01]);
        let b = MacAddr::from([0x02, 0, 0, 0, 0, 0x02]);
        let f = Filter {
            src_mac: Some(MacSet::try_from(vec![a, b]).unwrap()),
            ..Filter::default()
        };
        assert!(f.matches(
            &packet("10.0.0.1:5353", "10.0.0.2:5353", None, Some(a)),
            None
        ));
        assert!(f.matches(
            &packet("10.0.0.1:5353", "10.0.0.2:5353", None, Some(b)),
            None
        ));
        // A device outside the set misses.
        let other = MacAddr::from([0x02, 0, 0, 0, 0, 0x03]);
        assert!(!f.matches(
            &packet("10.0.0.1:5353", "10.0.0.2:5353", None, Some(other)),
            None
        ));
    }

    #[test]
    fn filter_matches_destination_mac_and_excludes_others() {
        let device = MacAddr::from([0x02, 0, 0, 0, 0, 0x0a]);
        let f = Filter {
            dst_mac: Some(device),
            ..Filter::default()
        };
        assert!(f.matches(
            &packet("10.0.0.1:5353", "10.0.0.2:5353", Some(device), None),
            None
        ));
        let other = MacAddr::from([0x02, 0, 0, 0, 0, 0x0b]);
        assert!(!f.matches(
            &packet("10.0.0.1:5353", "10.0.0.2:5353", Some(other), None),
            None
        ));
        assert!(!f.matches(&packet("10.0.0.1:5353", "10.0.0.2:5353", None, None), None));
    }

    // An IP filter is family-specific: a v4 criterion can't match a v6 packet, or vice
    // versa (`IpAddr`'s `PartialEq` is cross-family-aware).
    #[test]
    fn filter_ip_does_not_match_across_families() {
        let v4 = Filter {
            dst_ip: Some("224.0.0.251".parse::<IpAddr>().unwrap().into()),
            ..Filter::default()
        };
        assert!(!v4.matches(
            &packet("[fe80::1]:5353", "[ff02::fb]:5353", None, None),
            None
        ));
        let v6 = Filter {
            dst_ip: Some("ff02::fb".parse::<IpAddr>().unwrap().into()),
            ..Filter::default()
        };
        assert!(!v6.matches(
            &packet("10.0.0.1:5353", "224.0.0.251:5353", None, None),
            None
        ));
    }

    const PROBE: &[u8] = b"netflector-dispatch-probe";
    /// The echo re-emits to this port, distinct from the filter's, so the looped-back
    /// echo can't re-match and amplify.
    const ECHO_DST_PORT: u16 = 1;

    /// Each entry: the payload a reflector saw, and whether its keyed egress succeeded.
    type Seen = Rc<RefCell<Vec<(Vec<u8>, bool)>>>;

    /// A reflector that re-emits each matched packet on its egress capture (by key,
    /// through the dispatcher) and records what it saw. The seam `WoL` et al. will fill.
    struct Echo {
        egress: CaptureKey,
        seen: Seen,
    }

    impl PacketHandler for Echo {
        fn on_packet(
            &mut self,
            packet: &Packet,
            dispatcher: &mut PacketDispatcher,
            _reactor: &mut Reactor,
        ) -> Outcome {
            let (SocketAddr::V4(src), SocketAddr::V4(dst)) = (packet.source, packet.dest) else {
                return Outcome::Filtered;
            };
            let dst = SocketAddr::V4(SocketAddrV4::new(*dst.ip(), ECHO_DST_PORT));
            // Re-emit through the real link-aware send so the framing matches the egress link type
            // (Ethernet vs DLT_NULL) instead of a hardcoded Ethernet frame, which a DLT_NULL loopback
            // (the BSDs) rejects.
            let sent = dispatcher
                .send_udp(
                    self.egress,
                    dst,
                    MacAddr::from([0xff; 6]),
                    DatagramSource::Egress { port: src.port() },
                    packet.ttl,
                    packet.payload,
                )
                .is_ok();
            self.seen.borrow_mut().push((packet.payload.to_vec(), sent));
            Outcome::Reflected(MessageType::MdnsQuery)
        }
    }

    // End-to-end over loopback: a dispatcher owning two `lo` captures drains a looped
    // UDP probe off the ingress key, routes it through the matching Echo reflector,
    // which re-emits on the *egress* key. Skips without capture access (no CAP_NET_RAW).
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn routes_a_captured_packet_to_a_matching_reflector() -> io::Result<()> {
        let _serial = loopback_lock();
        let Some(ingress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_ingress")? else {
            return Ok(());
        };
        let Some(egress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_egress")? else {
            return Ok(());
        };

        let (_receiver, target, sender) = probe_rig()?;

        let mut dispatcher = PacketDispatcher::new();
        let ingress = dispatcher.add_capture(ingress_cap)?;
        let egress = dispatcher.add_capture(egress_cap)?;
        // The egress capture resolves to its interface's address, the seam reflectors read.
        assert_eq!(
            dispatcher
                .egress_addrs(egress)
                .and_then(InterfaceAddresses::v4),
            Some(Ipv4Addr::LOCALHOST),
        );
        let seen = Rc::new(RefCell::new(Vec::new()));
        dispatcher.register(
            ingress,
            Filter {
                dst_port: Some(target.port().into()),
                ..Filter::default()
            },
            Box::new(Echo {
                egress,
                seen: seen.clone(),
            }),
        );

        let mut reactor = Reactor::new()?;
        sender.send_to(PROBE, target)?;
        pump_until(
            2,
            || !seen.borrow().is_empty(),
            || dispatcher.drain_and_route(ingress, &mut reactor),
        );

        let records = seen.borrow();
        assert!(!records.is_empty(), "the reflector never fired");
        assert_eq!(records[0].0, PROBE, "reflector saw the wrong payload");
        assert!(records[0].1, "the keyed egress send failed");
        Ok(())
    }

    /// A reflector that records each matched packet's payload, for routing/registration tests
    /// that need no real egress (no capture, no send).
    struct Recorder {
        seen: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl PacketHandler for Recorder {
        fn on_packet(
            &mut self,
            packet: &Packet,
            _: &mut PacketDispatcher,
            _: &mut Reactor,
        ) -> Outcome {
            self.seen.borrow_mut().push(packet.payload.to_vec());
            Outcome::Reflected(MessageType::MdnsQuery)
        }
    }

    /// A synthetic v4 UDP packet for routing tests; the default filter matches it.
    fn probe_packet(payload: &[u8]) -> Packet<'_> {
        Packet {
            source: "10.0.0.1:5".parse().unwrap(),
            dest: "10.0.0.2:9".parse().unwrap(),
            ttl: 64,
            dst_mac: None,
            src_mac: None,
            payload,
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn unregister_stops_routing_to_a_handler() -> io::Result<()> {
        let mut dispatcher = PacketDispatcher::new();
        let mut reactor = Reactor::new()?;
        let ingress = dispatcher.add_test_capture();
        let seen = Rc::new(RefCell::new(Vec::new()));
        let key = dispatcher.register(
            ingress,
            Filter::default(),
            Box::new(Recorder { seen: seen.clone() }),
        );
        dispatcher.route(ingress, &probe_packet(b"a"), &mut reactor);
        assert_eq!(seen.borrow().len(), 1, "the registration should route once");

        dispatcher.unregister(key);
        dispatcher.route(ingress, &probe_packet(b"b"), &mut reactor);
        assert_eq!(
            seen.borrow().len(),
            1,
            "an unregistered handler is no longer routed to"
        );
        dispatcher.unregister(key); // the now-stale key removes nothing
        Ok(())
    }

    /// A reflector that returns a preset [`Outcome`], driving `route`'s outcome fold and per-capture
    /// recording without a real egress.
    struct Outcomer(Outcome);

    impl PacketHandler for Outcomer {
        fn on_packet(&mut self, _: &Packet, _: &mut PacketDispatcher, _: &mut Reactor) -> Outcome {
            self.0
        }
    }

    impl PacketDispatcher {
        /// Add a capture-less table entry so a routing test can mint a valid `CaptureKey` and
        /// exercise `route`'s record path without opening a real capture; read the row back with
        /// [`counts`](Self::counts).
        fn add_test_capture(&mut self) -> CaptureKey {
            self.table.add_test_capture()
        }

        /// The `(reflected, skipped, dropped, stalled)` count recorded for `ty` on `key`'s row.
        fn counts(&self, key: CaptureKey, ty: MessageType) -> (u64, u64, u64, u64) {
            self.table.typed_counts(key, ty)
        }
    }

    // route folds every matched handler's outcome into one and records it once on the ingress row:
    // a reflect and its mirror skip (both matching) count a single reflect, and a handler whose filter
    // misses doesn't contribute at all.
    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn route_folds_matched_outcomes_and_records_once() -> io::Result<()> {
        let mut dispatcher = PacketDispatcher::new();
        let mut reactor = Reactor::new()?;
        let ingress = dispatcher.add_test_capture();

        // Mirrored a->b / b->a reflectors both match here: one reflects the query, its mirror skips it.
        dispatcher.register(
            ingress,
            Filter::default(),
            Box::new(Outcomer(Outcome::Reflected(MessageType::MdnsQuery))),
        );
        dispatcher.register(
            ingress,
            Filter::default(),
            Box::new(Outcomer(Outcome::Skipped(MessageType::MdnsQuery))),
        );
        // A third handler whose filter never matches (wrong dst port) must not reach the count.
        dispatcher.register(
            ingress,
            Filter {
                dst_port: Some(4242.into()),
                ..Filter::default()
            },
            Box::new(Outcomer(Outcome::Reflected(MessageType::SsdpSearch))),
        );

        dispatcher.route(ingress, &probe_packet(b"q"), &mut reactor);

        // The reflect wins the fold and is counted once; the skip is shadowed, not a second count.
        assert_eq!(
            dispatcher.counts(ingress, MessageType::MdnsQuery),
            (1, 0, 0, 0)
        );
        // The unmatched handler contributed nothing.
        assert_eq!(
            dispatcher.counts(ingress, MessageType::SsdpSearch),
            (0, 0, 0, 0)
        );
        Ok(())
    }

    #[test]
    fn is_own_echo_matches_the_ingress_mac_except_all_zeros() {
        let own = MacAddr::from([0x02, 0, 0, 0, 0, 1]);
        let other = MacAddr::from([0x02, 0, 0, 0, 0, 2]);
        assert!(is_own_echo(Some(own), Some(own)));
        assert!(!is_own_echo(Some(other), Some(own)));
        // A DLT_NULL frame carries no MAC; an interface without one owns nothing.
        assert!(!is_own_echo(None, Some(own)));
        assert!(!is_own_echo(Some(own), None));
        // Linux loopback: zeros on both sides identify nothing.
        let zero = MacAddr::from([0; 6]);
        assert!(!is_own_echo(Some(zero), Some(zero)));
    }

    // A frame whose source MAC is the ingress's own is our own re-emit handed back by the link: it
    // reaches no handler and counts as echoed, while a peer's frame routes as usual.
    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket and interface")]
    fn route_drops_our_own_echoed_frames_before_any_handler() -> io::Result<()> {
        let mut dispatcher = PacketDispatcher::new();
        let mut reactor = Reactor::new()?;
        // The capture-less entry links to interface 0: give that interface a known MAC.
        let interface = dispatcher.table.find_or_add_interface(LOOPBACK_IFACE)?;
        let own = MacAddr::from([0x02, 0, 0, 0, 0, 1]);
        dispatcher.table.set_test_addrs(
            interface,
            InterfaceAddresses::new(Some(own), Some(Ipv4Addr::LOCALHOST), None, None),
        );
        let ingress = dispatcher.add_test_capture();
        assert_eq!(dispatcher.table.interface_of(ingress), Some(interface));
        dispatcher.register(
            ingress,
            Filter::default(),
            Box::new(Outcomer(Outcome::Reflected(MessageType::MdnsQuery))),
        );

        let mut echo = probe_packet(b"ours");
        echo.src_mac = Some(own);
        dispatcher.route(ingress, &echo, &mut reactor);
        assert_eq!(dispatcher.table.echoed_of(ingress), 1);
        assert_eq!(
            dispatcher.counts(ingress, MessageType::MdnsQuery),
            (0, 0, 0, 0),
            "the handler never ran"
        );

        let mut peer = probe_packet(b"theirs");
        peer.src_mac = Some(MacAddr::from([0x02, 0, 0, 0, 0, 2]));
        dispatcher.route(ingress, &peer, &mut reactor);
        assert_eq!(
            dispatcher.counts(ingress, MessageType::MdnsQuery),
            (1, 0, 0, 0)
        );
        assert_eq!(dispatcher.table.echoed_of(ingress), 1);
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn route_folds_fan_out_reflects_and_records_once() -> io::Result<()> {
        let mut dispatcher = PacketDispatcher::new();
        let mut reactor = Reactor::new()?;
        let ingress = dispatcher.add_test_capture();

        // A source fanned out to two targets (a->b, a->c) puts two reflecting handlers on the shared
        // ingress; both reflect the same query. A legal config, not a duplicate-reflector bug.
        dispatcher.register(
            ingress,
            Filter::default(),
            Box::new(Outcomer(Outcome::Reflected(MessageType::MdnsQuery))),
        );
        dispatcher.register(
            ingress,
            Filter::default(),
            Box::new(Outcomer(Outcome::Reflected(MessageType::MdnsQuery))),
        );

        dispatcher.route(ingress, &probe_packet(b"q"), &mut reactor);

        // One packet, one count per ingress: the two reflects fold to a single reflected count.
        assert_eq!(
            dispatcher.counts(ingress, MessageType::MdnsQuery),
            (1, 0, 0, 0)
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn counter_report_fires_on_its_interval() -> io::Result<()> {
        let mut dispatcher = PacketDispatcher::new();
        let mut reactor = Reactor::new()?;
        let now = Instant::now();
        assert_eq!(
            dispatcher.next_deadline(),
            Some(dispatcher.next_reconcile),
            "until enabled, the only standing deadline is the reconcile tick"
        );

        // Shorter than RECONCILE_TICK, so the report deadline is the min() at each assert.
        let interval = Duration::from_secs(5);
        dispatcher.enable_counter_report(interval, now);
        assert_eq!(dispatcher.next_deadline(), Some(now + interval));

        // Firing the report at its deadline reschedules it exactly one interval out.
        dispatcher.on_deadline(now + interval, &mut reactor);
        assert_eq!(dispatcher.next_deadline(), Some(now + interval + interval));
        Ok(())
    }

    /// A reflector carrying only a timer: reports `deadline` and counts each `on_deadline` sweep,
    /// for the dispatcher's deadline aggregation/dispatch, with no packets involved.
    struct Ticker {
        deadline: Option<Instant>,
        fired: Rc<Cell<u32>>,
    }

    impl PacketHandler for Ticker {
        fn on_packet(&mut self, _: &Packet, _: &mut PacketDispatcher, _: &mut Reactor) -> Outcome {
            Outcome::Filtered
        }
        fn next_deadline(&self) -> Option<Instant> {
            self.deadline
        }
        fn on_deadline(&mut self, _now: Instant, _: &mut PacketDispatcher, _: &mut Reactor) {
            self.fired.set(self.fired.get() + 1);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn reports_the_soonest_deadline_and_sweeps_only_the_due_one() -> io::Result<()> {
        let mut dispatcher = PacketDispatcher::new();
        let mut reactor = Reactor::new()?;
        let ingress = CaptureKey::from_u64(0);
        let base = Instant::now();
        let due = Rc::new(Cell::new(0u32));
        let future = Rc::new(Cell::new(0u32));
        dispatcher.register(
            ingress,
            Filter::default(),
            Box::new(Ticker {
                deadline: Some(base),
                fired: due.clone(),
            }),
        );
        dispatcher.register(
            ingress,
            Filter::default(),
            Box::new(Ticker {
                deadline: Some(base + Duration::from_secs(10)),
                fired: future.clone(),
            }),
        );

        // The dispatcher hands the reactor the soonest registration deadline.
        assert_eq!(dispatcher.next_deadline(), Some(base));

        // A sweep fires only the registration whose deadline has come due.
        dispatcher.on_deadline(base + Duration::from_secs(1), &mut reactor);
        assert_eq!(due.get(), 1, "the due handler is swept");
        assert_eq!(future.get(), 0, "the future handler is not");
        Ok(())
    }

    /// Registers a second recorder once, from inside its own call: the mid-route registration.
    struct Registrar {
        ingress: CaptureKey,
        late: Rc<RefCell<Vec<Vec<u8>>>>,
        done: bool,
    }

    impl PacketHandler for Registrar {
        fn on_packet(
            &mut self,
            _: &Packet,
            dispatcher: &mut PacketDispatcher,
            _: &mut Reactor,
        ) -> Outcome {
            if !std::mem::replace(&mut self.done, true) {
                dispatcher.register(
                    self.ingress,
                    Filter::default(),
                    Box::new(Recorder {
                        seen: self.late.clone(),
                    }),
                );
            }
            Outcome::Filtered
        }
    }

    // route snapshots the live registration keys at the start, so a registration created during the
    // call isn't in the snapshot and doesn't receive the in-flight frame. True whether it appends
    // or reuses a freed slot (a key snapshot, unlike the old length bound, doesn't depend on index).
    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn a_mid_route_registration_is_not_fed_the_in_flight_frame() -> io::Result<()> {
        let mut dispatcher = PacketDispatcher::new();
        let mut reactor = Reactor::new()?;
        let ingress = dispatcher.add_test_capture();
        let late = Rc::new(RefCell::new(Vec::new()));
        dispatcher.register(
            ingress,
            Filter::default(),
            Box::new(Registrar {
                ingress,
                late: late.clone(),
                done: false,
            }),
        );

        dispatcher.route(ingress, &probe_packet(b"x"), &mut reactor);
        assert!(
            late.borrow().is_empty(),
            "a registration born this route must not see the in-flight frame",
        );
        // It does receive the next frame.
        dispatcher.route(ingress, &probe_packet(b"y"), &mut reactor);
        assert_eq!(late.borrow().as_slice(), [b"y".to_vec()]);
        Ok(())
    }

    /// A reflector that re-enters the drain on its *own* ingress from inside the call.
    /// The upstream take-out makes that nested drain return at its guard; were the
    /// take-out removed, the nested drain would pull the next buffered frame and
    /// re-route into this handler (which is taken out for the call), panicking the
    /// `expect` in `route`.
    struct Reentrant {
        ingress: CaptureKey,
        calls: Rc<RefCell<u32>>,
    }

    impl PacketHandler for Reentrant {
        fn on_packet(
            &mut self,
            _packet: &Packet,
            dispatcher: &mut PacketDispatcher,
            reactor: &mut Reactor,
        ) -> Outcome {
            *self.calls.borrow_mut() += 1;
            dispatcher.drain_and_route(self.ingress, reactor);
            Outcome::Filtered
        }
    }

    // Re-entrancy guard: a reflector re-entering the drain on its own ingress must hit
    // the take-out guard, not re-route into its taken-out handler. Two probes are
    // buffered so that, without the guard, the first packet's re-entrant drain pulls the
    // second and panics `route`'s `expect`; with it, the outer loop handles both
    // (calls == 2). Skips without capture access (no CAP_NET_RAW).
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn reentrant_drain_on_the_same_ingress_hits_the_guard() -> io::Result<()> {
        let _serial = loopback_lock();
        let Some(ingress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_reentrant")? else {
            return Ok(());
        };

        let (_receiver, target, sender) = probe_rig()?;

        let mut dispatcher = PacketDispatcher::new();
        let ingress = dispatcher.add_capture(ingress_cap)?;
        let calls = Rc::new(RefCell::new(0u32));
        dispatcher.register(
            ingress,
            Filter {
                dst_port: Some(target.port().into()),
                ..Filter::default()
            },
            Box::new(Reentrant {
                ingress,
                calls: calls.clone(),
            }),
        );

        let mut reactor = Reactor::new()?;
        sender.send_to(PROBE, target)?;
        sender.send_to(PROBE, target)?;
        // Let both probes land in the ring before the first drain, so the re-entrant
        // drain inside the first packet has the second frame available to mis-route.
        std::thread::sleep(Duration::from_millis(50));

        pump_until(
            2,
            || *calls.borrow() >= 2,
            || dispatcher.drain_and_route(ingress, &mut reactor),
        );

        assert_eq!(
            *calls.borrow(),
            2,
            "both probes should route via the outer drain; the re-entrant call must no-op"
        );
        Ok(())
    }

    /// A reflector that re-enters the drain on a *different* ingress: the case the same-ingress
    /// take-out guard cannot see.
    struct CrossDrainer {
        other: CaptureKey,
    }

    impl PacketHandler for CrossDrainer {
        fn on_packet(
            &mut self,
            _packet: &Packet,
            dispatcher: &mut PacketDispatcher,
            reactor: &mut Reactor,
        ) -> Outcome {
            dispatcher.drain_and_route(self.other, reactor);
            Outcome::Filtered
        }
    }

    // The cross-ingress re-drain slips past the take-out guard (the other capture is present, so
    // its drain proceeds into `route`, which would rebuild the shared `route_keys` scratch under
    // the outer loop); the entry assert must catch it. Both loopback captures see the one probe.
    // `should_panic` can't express the no-privilege skip, so the panic is caught by hand. Skips
    // without capture access.
    #[test]
    #[cfg_attr(
        not(debug_assertions),
        ignore = "route's re-entry guard is a debug_assert!, compiled out in release"
    )]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn reentrant_drain_on_another_ingress_trips_the_assert() -> io::Result<()> {
        let _serial = loopback_lock();
        let Some(cap_a) = open_or_skip(LOOPBACK_IFACE, "dispatch_cross_a")? else {
            return Ok(());
        };
        let Some(cap_b) = open_or_skip(LOOPBACK_IFACE, "dispatch_cross_b")? else {
            return Ok(());
        };

        let (_receiver, target, sender) = probe_rig()?;

        let mut dispatcher = PacketDispatcher::new();
        let a = dispatcher.add_capture(cap_a)?;
        let b = dispatcher.add_capture(cap_b)?;
        dispatcher.register(
            a,
            Filter {
                dst_port: Some(target.port().into()),
                ..Filter::default()
            },
            Box::new(CrossDrainer { other: b }),
        );

        let mut reactor = Reactor::new()?;
        sender.send_to(PROBE, target)?;

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pump_until(
                1,
                || false, // no success condition: the only exit is the assert firing
                || dispatcher.drain_and_route(a, &mut reactor),
            );
        }))
        .expect_err("a cross-ingress re-drain must trip route's re-entry assert");
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(
            message.contains("route re-entered"),
            "unexpected panic message: {message}"
        );
        Ok(())
    }

    // End-to-end through the reactor: register the dispatcher itself as a handler watching
    // its capture fds, then let `poll_once` drive it. A looped UDP probe makes the ingress
    // capture readable; the reactor names that exact fd, the dispatcher maps it back to the
    // capture, drains it, and routes to the Echo, which re-emits on the egress key.
    // Exercises the per-fd `on_readable`. Skips without capture access (no CAP_NET_RAW).
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn reactor_drives_the_dispatcher_to_route_a_packet() -> io::Result<()> {
        let _serial = loopback_lock();
        let Some(ingress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_reactor_in")? else {
            return Ok(());
        };
        let Some(egress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_reactor_eg")? else {
            return Ok(());
        };

        let (_receiver, target, sender) = probe_rig()?;

        let mut dispatcher = PacketDispatcher::new();
        let ingress = dispatcher.add_capture(ingress_cap)?;
        let egress = dispatcher.add_capture(egress_cap)?;
        let seen = Rc::new(RefCell::new(Vec::new()));
        dispatcher.register(
            ingress,
            Filter {
                dst_port: Some(target.port().into()),
                ..Filter::default()
            },
            Box::new(Echo {
                egress,
                seen: seen.clone(),
            }),
        );

        let mut reactor = Reactor::new()?;
        let watches = dispatcher.capture_watches();
        reactor.register_with_fds(Box::new(dispatcher), &watches)?;

        sender.send_to(PROBE, target)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while seen.borrow().is_empty() && Instant::now() < deadline {
            reactor.poll_once(Some(Duration::from_millis(100)))?;
        }

        let records = seen.borrow();
        assert!(
            !records.is_empty(),
            "the reflector never fired via the reactor"
        );
        assert_eq!(records[0].0, PROBE, "reflector saw the wrong payload");
        assert!(records[0].1, "the keyed egress send failed");
        Ok(())
    }

    // Privilege-free: a fresh dispatcher has no captures, so an out-of-range key stands in
    // for a forged reactor `user_data`. The drain guard, `egress_addrs`, `link_type`, `send`,
    // and `send_udp_group` must each be a safe no-op (log-drop / `None` / `Ok`), never a panic:
    // the new behavior the capture-gated e2e tests above skip without `CAP_NET_RAW`.
    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn unknown_capture_key_is_a_safe_no_op() -> io::Result<()> {
        let mut dispatcher = PacketDispatcher::new();
        let mut reactor = Reactor::new()?;
        let bogus = CaptureKey::from_u64(999);
        dispatcher.drain_and_route(bogus, &mut reactor); // out-of-range guard arm, no panic
        assert!(dispatcher.egress_addrs(bogus).is_none());
        assert!(dispatcher.link_type(bogus).is_none());
        assert!(dispatcher.send(bogus, b"x").is_ok());
        // send_udp_group on an unknown egress is the same logged drop, not a build attempt.
        let dst = SocketAddr::from((Ipv4Addr::BROADCAST, 9));
        assert!(
            dispatcher
                .send_udp_group(bogus, dst, DatagramSource::Egress { port: 1 }, 64, b"x")
                .is_ok()
        );
        Ok(())
    }

    /// The mid-drain probe's recording: the v4 it resolved for the ingress while drained,
    /// and whether the send to the taken-out ingress returned `Ok`.
    type ProbeResult = Rc<RefCell<Option<(Option<Ipv4Addr>, bool)>>>;

    /// Probes the take-out invariants from inside the drain: while its ingress capture is
    /// taken out, the interface link stays resident (so `egress_addrs` resolves) and a send
    /// to the taken-out capture is a logged drop (`Ok`), not a panic.
    struct MidDrainProbe {
        ingress: CaptureKey,
        result: ProbeResult,
    }

    impl PacketHandler for MidDrainProbe {
        fn on_packet(
            &mut self,
            _packet: &Packet,
            dispatcher: &mut PacketDispatcher,
            _reactor: &mut Reactor,
        ) -> Outcome {
            let addrs = dispatcher
                .egress_addrs(self.ingress)
                .and_then(InterfaceAddresses::v4);
            let sent_ok = dispatcher.send(self.ingress, b"x").is_ok();
            *self.result.borrow_mut() = Some((addrs, sent_ok));
            Outcome::Filtered
        }
    }

    // The wrapper design's headline invariant: the take-out clears only the inner capture,
    // leaving the interface link resident, so `egress_addrs(ingress)` still resolves while
    // the capture is drained, and `send(ingress)` drops (`Ok`) rather than panicking. Both
    // are checked from inside the reflector's call, when the ingress entry's capture is
    // `None`. Skips without capture access (no CAP_NET_RAW).
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn ingress_resolves_and_drops_while_taken_out() -> io::Result<()> {
        let _serial = loopback_lock();
        let Some(ingress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_mid_drain")? else {
            return Ok(());
        };

        let (_receiver, target, sender) = probe_rig()?;

        let mut dispatcher = PacketDispatcher::new();
        let ingress = dispatcher.add_capture(ingress_cap)?;
        let result = Rc::new(RefCell::new(None));
        dispatcher.register(
            ingress,
            Filter {
                dst_port: Some(target.port().into()),
                ..Filter::default()
            },
            Box::new(MidDrainProbe {
                ingress,
                result: result.clone(),
            }),
        );

        let mut reactor = Reactor::new()?;
        sender.send_to(PROBE, target)?;
        pump_until(
            2,
            || result.borrow().is_some(),
            || dispatcher.drain_and_route(ingress, &mut reactor),
        );

        let recorded = *result.borrow();
        let (addrs, sent_ok) = recorded.expect("the probe never fired");
        assert_eq!(
            addrs,
            Some(Ipv4Addr::LOCALHOST),
            "ingress addresses must resolve while the capture is taken out"
        );
        assert!(
            sent_ok,
            "send to the taken-out ingress must drop (Ok), not panic"
        );
        Ok(())
    }

    // new() opens the routing socket; its fd joins the watch list under the sentinel tag,
    // distinct from any capture key. Best-effort: the watch appears only if the socket opened
    // (some sandboxes deny it), so an empty watch list means skip.
    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn monitor_fd_is_watched_under_the_sentinel_tag() {
        let dispatcher = PacketDispatcher::new();
        let watches = dispatcher.capture_watches();
        if watches.is_empty() {
            eprintln!("skip: the routing socket could not be opened in this environment");
            return;
        }
        // No captures were added, so the monitor fd is the sole watch, under MONITOR_TAG.
        assert_eq!(watches.len(), 1, "only the monitor fd should be watched");
        assert_eq!(
            watches[0].1, MONITOR_TAG,
            "the monitor fd must carry MONITOR_TAG"
        );
    }

    // A join_group on an unknown capture is logged and skipped, not an error or a panic.
    #[test]
    #[cfg_attr(miri, ignore = "needs a real socket")]
    fn join_group_ignores_an_unknown_capture() {
        let mut dispatcher = PacketDispatcher::new();
        let group = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251));
        assert!(dispatcher.join_group(CaptureKey(9999), group).is_ok());
    }

    #[test]
    fn oversize_context_rewords_only_emsgsize() {
        // The reworded message is the feature: it must name the frame length, the interface, and
        // the MTU when known.
        let e = oversize_context(
            io::Error::from_raw_os_error(libc::EMSGSIZE),
            "vxlan0",
            1500,
            Some(1370),
        );
        let text = e.to_string();
        assert!(
            text.contains("1500") && text.contains("vxlan0") && text.contains("1370"),
            "{text}"
        );
        // The custom message costs the errno representation (std's `io::Error` carries one or the
        // other, never both). Deliberate: nothing matches on EMSGSIZE downstream, and the message
        // is the only surface an operator sees.
        assert_eq!(e.raw_os_error(), None);
        // Any other error passes through untouched: its message is the plain strerror text, and
        // it keeps its errno (rewording builds a custom error, whose `raw_os_error` is `None`).
        let other = oversize_context(io::Error::from_raw_os_error(libc::ENETDOWN), "x0", 9, None);
        assert_eq!(
            other.to_string(),
            io::Error::from_raw_os_error(libc::ENETDOWN).to_string()
        );
        assert_eq!(other.raw_os_error(), Some(libc::ENETDOWN));
    }
}
