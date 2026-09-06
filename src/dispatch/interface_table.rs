//! The dispatcher's interface table: every interface with its multicast joiner, and every capture
//! linked to its interface, all addressed by `Copy` index keys.

use std::io;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, RawFd};

use crate::capture::Capture;
use crate::interface::{AddressChange, Interface, InterfaceAddresses, if_index_checked};

use super::CaptureKey;
use super::counters::{CaptureCounters, Outcome};
use super::multicast::{MulticastJoiner, RejoinCounts};

/// A `Copy` handle into the interface table's interface entries. An insert-only index like
/// [`CaptureKey`], but a distinct newtype so the two can't be confused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct InterfaceKey(u32);

/// One stale table entry from [`stale_interfaces`](InterfaceTable::stale_interfaces): its
/// kernel identity moved, or a capture's binding died behind an unchanged identity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct StaleInterface {
    pub(super) key: InterfaceKey,
    /// The identity the table still holds (0 = parked absent).
    pub(super) cached: u32,
    /// The index the entry's name resolves to now (0 = the name resolves to nothing).
    pub(super) cur: u32,
}

/// One capture, the interface it runs on, and its observability counts. The `capture` is `Option`
/// so the drain can take it OUT and restore it; the `interface` link and `counters` stay resident,
/// so a capture's addresses resolve and its routed outcomes still record mid-drain. `None` marks
/// "currently draining". Never removed, so the counts accrue for the whole run. Bundling the
/// counters here rather than a parallel `Vec` makes them impossible to desync: one push adds both.
struct CaptureEntry {
    capture: Option<Capture>,
    interface: InterfaceKey,
    counters: CaptureCounters,
    last_sent: SentFrame,
}

/// The last frame sent on a capture, tagged with the packet whose routing sent it. A packet's
/// routing sends one frame per egress, so an equal frame for the same packet is a second handler
/// relaying what the first already did. `packet` counts from 1, so the default never matches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct SentFrame {
    pub(super) packet: u64,
    pub(super) len: usize,
    pub(super) checksum: u16,
}

/// One interface paired with its multicast joiner. Bundling them keeps the two from desyncing (one
/// push adds both) and pins the relationship the joiner relies on: every join/rejoin passes THIS
/// interface's ifindex, so the [`Interface`] stays the single cached copy.
struct InterfaceEntry {
    interface: Interface,
    joiner: MulticastJoiner,
}

/// Owns every interface and every capture, linking each capture to its interface. Plain
/// `Vec`s (not generational arenas): both are insert-only, so an index is a stable identity
/// and the inner `Option<Capture>` alone marks the take-out.
pub(super) struct InterfaceTable {
    /// One entry per interface, indexed by [`InterfaceKey`].
    entries: Vec<InterfaceEntry>,
    captures: Vec<CaptureEntry>,
    /// Whether an added interface gets a joiner that joins.
    join_groups: bool,
}

impl InterfaceTable {
    pub(super) fn new() -> Self {
        Self {
            entries: Vec::new(),
            captures: Vec::new(),
            join_groups: true,
        }
    }

    /// A table whose interfaces join no multicast group: `--no-join`.
    pub(super) fn without_group_joins() -> Self {
        Self {
            join_groups: false,
            ..Self::new()
        }
    }

    /// Add an interface, returning its key. Startup-only.
    fn add_interface(&mut self, interface: Interface) -> InterfaceKey {
        let key =
            InterfaceKey(u32::try_from(self.entries.len()).expect("interface count fits a u32"));
        let joiner = if self.join_groups {
            MulticastJoiner::new()
        } else {
            MulticastJoiner::inert()
        };
        self.entries.push(InterfaceEntry { interface, joiner });
        key
    }

    /// Join `group`'s multicast membership on `interface`, recording it for re-attempt on a later
    /// address change. # Errors: propagates the joiner's OS error (an unavailable family is
    /// deferred to [`rejoin`](MulticastJoiner::rejoin), not an error).
    pub(super) fn join_on(&mut self, interface: InterfaceKey, group: IpAddr) -> io::Result<()> {
        // Startup-only with a freshly-minted key, so the index is always in range.
        let entry = &mut self.entries[interface.0 as usize];
        if let Some(ifindex) = NonZeroU32::new(entry.interface.ifindex) {
            entry.joiner.join(group, ifindex)
        } else {
            // Unreachable at startup (the capture opened, so the interface exists), but the
            // defensively right behavior: record for the rebuild's replay, never join index 0.
            entry.joiner.record(group);
            Ok(())
        }
    }

    /// The key of the interface named `name`, opening and resolving it if absent, so captures on
    /// the same interface share one record (and one monitor refresh later).
    ///
    /// # Errors
    /// Propagates a resolution syscall failure when first opening the interface.
    pub(super) fn find_or_add_interface(&mut self, name: &str) -> io::Result<InterfaceKey> {
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.interface.name == name)
        {
            return Ok(InterfaceKey(
                u32::try_from(index).expect("interface count fits a u32"),
            ));
        }
        Ok(self.add_interface(Interface::open(name)?))
    }

    /// Whether `frame` is the last one sent on `egress`. An unknown key never sent anything.
    pub(super) fn is_last_sent(&self, egress: CaptureKey, frame: SentFrame) -> bool {
        self.captures
            .get(egress.0 as usize)
            .is_some_and(|entry| entry.last_sent == frame)
    }

    /// Set `frame` as the last one sent on `egress`, once its send succeeded.
    pub(super) fn set_last_sent(&mut self, egress: CaptureKey, frame: SentFrame) {
        if let Some(entry) = self.captures.get_mut(egress.0 as usize) {
            entry.last_sent = frame;
        }
    }

    /// Add a capture bound to `interface`, returning its key. Startup-only.
    pub(super) fn add_capture(&mut self, capture: Capture, interface: InterfaceKey) -> CaptureKey {
        let key = CaptureKey(u32::try_from(self.captures.len()).expect("capture count fits a u32"));
        self.captures.push(CaptureEntry {
            capture: Some(capture),
            interface,
            counters: CaptureCounters::default(),
            last_sent: SentFrame::default(),
        });
        key
    }

    /// The interface a capture runs on. Resolves even while the capture is taken out: the link is
    /// a sibling field of the take-out `Option`.
    pub(super) fn interface_of(&self, capture: CaptureKey) -> Option<InterfaceKey> {
        self.captures
            .get(capture.0 as usize)
            .map(|entry| entry.interface)
    }

    /// An interface's current source addresses, by key.
    fn addrs(&self, interface: InterfaceKey) -> Option<&InterfaceAddresses> {
        self.entries
            .get(interface.0 as usize)
            .map(|entry| &entry.interface.addrs)
    }

    /// The kernel ifindex of the interface `capture` runs on: cached at open, re-pointed by the
    /// reconcile on recreation (0 while parked absent).
    pub(super) fn ifindex_of(&self, capture: CaptureKey) -> Option<u32> {
        self.interface_index(self.interface_of(capture)?)
    }

    /// The name of the interface `interface` keys, if present.
    pub(super) fn interface_name(&self, interface: InterfaceKey) -> Option<&str> {
        self.entries
            .get(interface.0 as usize)
            .map(|entry| entry.interface.name.as_str())
    }

    /// The index of the interface `interface` keys, if present.
    pub(super) fn interface_index(&self, interface: InterfaceKey) -> Option<u32> {
        self.entries
            .get(interface.0 as usize)
            .map(|entry| entry.interface.ifindex)
    }

    /// The current source addresses behind a capture.
    pub(super) fn egress_addrs(&self, capture: CaptureKey) -> Option<&InterfaceAddresses> {
        self.addrs(self.interface_of(capture)?)
    }

    /// The MTU of the interface behind `capture`, as of its last resolution.
    pub(super) fn mtu_of(&self, capture: CaptureKey) -> Option<u32> {
        self.entries
            .get(self.interface_of(capture)?.0 as usize)?
            .interface
            .mtu
    }

    /// A shared borrow of a present capture, for [`send`](super::PacketDispatcher::send).
    pub(super) fn capture(&self, capture: CaptureKey) -> Option<&Capture> {
        self.captures.get(capture.0 as usize)?.capture.as_ref()
    }

    /// Whether `capture` names a known (in-range) capture. Distinguishes a forged key from one
    /// merely taken out, for the drain's guard.
    pub(super) fn contains(&self, capture: CaptureKey) -> bool {
        (capture.0 as usize) < self.captures.len()
    }

    /// Take a capture OUT for its drain; restore with [`restore`](Self::restore). `None`
    /// means out of range, or already taken out (currently draining).
    pub(super) fn take(&mut self, capture: CaptureKey) -> Option<Capture> {
        self.captures.get_mut(capture.0 as usize)?.capture.take()
    }

    /// Restore a drained capture, reporting whether its slot was present. Keeps logging out of the
    /// table, like [`take`](Self::take). The miss can't actually happen (restore follows a
    /// successful `take` on a Vec that never shrinks); on one, the capture drops.
    #[must_use]
    pub(super) fn restore(&mut self, capture: CaptureKey, value: Capture) -> bool {
        if let Some(entry) = self.captures.get_mut(capture.0 as usize) {
            entry.capture = Some(value);
            true
        } else {
            false
        }
    }

    /// Count a routed packet's folded [`Outcome`] on `capture`'s counter row. Indexed directly:
    /// recording is reached only from `route`, with the ingress key of a real, in-range capture (the
    /// drain's take-out guard rejects any other), so the row always exists.
    pub(super) fn record(&mut self, capture: CaptureKey, outcome: Outcome) {
        self.captures[capture.0 as usize].counters.record(outcome);
    }

    /// Count a completed recovery on a capture's row (see [`CaptureCounters::record_recovery`]).
    /// Indexed directly, like [`record`](Self::record): the keys come from
    /// [`captures_of`](Self::captures_of) in the reconcile, so the row always exists.
    pub(super) fn record_recovery(&mut self, capture: CaptureKey) {
        self.captures[capture.0 as usize].counters.record_recovery();
    }

    /// Count `n` oversized-frame drops on a capture's row (see
    /// [`CaptureCounters::record_oversized`]). Indexed directly, like [`record`](Self::record):
    /// the drain that produced the count holds the row's own capture.
    pub(super) fn record_oversized(&mut self, capture: CaptureKey, n: u64) {
        self.captures[capture.0 as usize]
            .counters
            .record_oversized(n);
    }

    /// Count one of our own re-emits handed back on a capture's row (see
    /// [`CaptureCounters::record_echo`]). Indexed directly, like [`record`](Self::record): reached
    /// only from `route` with a real ingress key.
    pub(super) fn record_echo(&mut self, capture: CaptureKey) {
        self.captures[capture.0 as usize].counters.record_echo();
    }

    /// Each capture's `(interface name, counter row)` for the periodic report. The table owns the
    /// capture→interface-name mapping and stays log-free (the dispatcher does the logging).
    pub(super) fn counter_rows(&self) -> impl Iterator<Item = (&str, &CaptureCounters)> {
        self.captures
            .iter()
            .filter_map(move |entry| Some((self.interface_name(entry.interface)?, &entry.counters)))
    }

    /// Re-resolve the interface with kernel index `ifindex`, in place. A real index matches at
    /// most one interface (they dedup by name, and the kernel gives each a distinct index), so this
    /// finds rather than scans. Returns the fields that changed if one matched, or `None` for a
    /// change on an interface we don't watch. Log-free, like [`take`](Self::take); the dispatcher
    /// reports the outcome. `ifindex` is always a real index here: both monitor backends drop an
    /// index-0 notification before forwarding it, and a buffer overflow arrives as its own
    /// [`InterfaceEvent::Overflow`](crate::interface::InterfaceEvent), which the dispatcher routes
    /// to [`refresh_all`]. A 0 reaching this would match the first parked entry, which caches 0.
    ///
    /// [`refresh_all`]: Self::refresh_all
    ///
    /// # Errors
    /// Propagates a resolution syscall failure.
    pub(super) fn refresh_by_ifindex(&mut self, ifindex: u32) -> io::Result<Option<AddressChange>> {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.interface.ifindex == ifindex)
        else {
            return Ok(None);
        };
        let change = entry.interface.refresh()?;
        // Re-resolved addresses may have made a deferred join (a v4 group that had no address)
        // viable; re-attempt this interface's memberships. Always present here: the entry was
        // found by matching a real notification's index.
        if let Some(ifindex) = NonZeroU32::new(entry.interface.ifindex) {
            entry.joiner.rejoin(ifindex);
        }
        Ok(Some(change))
    }

    /// Every interface whose kernel identity no longer matches the cached state. Two disjoint
    /// staleness modes: the identity moved (recreation with a new index, deletion, rename-away),
    /// caught by the name lookup; or a capture's kernel binding died behind an unchanged
    /// identity (a recreated interface reusing its index, or a half-completed earlier rebuild),
    /// caught by the [`attached`](crate::capture::Capture::attached) probe. An entry parked
    /// absent (cached 0, name still resolving to nothing) is quiescent, not stale: its captures
    /// are known-dead and there is nothing to repair until the name returns. Cost: one name
    /// lookup per interface plus one probe per capture; the dispatcher gates how often this
    /// runs. Log-free, like the refresh methods.
    pub(super) fn stale_interfaces(&self) -> Vec<StaleInterface> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let key = InterfaceKey(u32::try_from(index).expect("interface count fits a u32"));
                let cached = entry.interface.ifindex;
                // A lookup that couldn't run says nothing about the interface. Reading it as 0
                // would park a healthy entry: leave it out of this pass and re-scan on the next
                // tick, by which point whatever exhausted the fds has usually let go.
                let cur = if_index_checked(&entry.interface.name).ok()?.unwrap_or(0);
                let dead_capture = |c: &CaptureEntry| {
                    c.interface == key && c.capture.as_ref().is_some_and(|cap| !cap.attached(cur))
                };
                (cur != cached || (cur != 0 && self.captures.iter().any(dead_capture)))
                    .then_some(StaleInterface { key, cached, cur })
            })
            .collect()
    }

    /// Whether every capture on the entry whose cached identity is `ifindex` is still attached
    /// to its live interface (vacuously true with no matching entry). The cheap staleness
    /// check for a matched notification -- one kernel probe per capture, no name lookups: it
    /// catches a recreation that reused the index right when the recreated interface's first
    /// events arrive, instead of waiting for the reconcile tick.
    pub(super) fn probe_by_ifindex(&self, ifindex: u32) -> bool {
        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.interface.ifindex == ifindex)
        else {
            return true;
        };
        let key = InterfaceKey(u32::try_from(index).expect("interface count fits a u32"));
        self.captures.iter().all(|entry| {
            entry.interface != key
                || entry
                    .capture
                    .as_ref()
                    .is_none_or(|capture| capture.attached(ifindex))
        })
    }

    /// Whether any interface is parked absent (its name resolved to nothing when it was last
    /// reconciled). The dispatcher keeps the fast reconcile cadence while one is, so the
    /// interface's return is picked up promptly even if every event for it is lost.
    pub(super) fn any_absent(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.interface.ifindex == 0)
    }

    /// Re-point interface `key` at the interface currently bearing its name (kernel index
    /// `cur`, from [`stale_interfaces`](Self::stale_interfaces)), re-resolve its addresses, and
    /// re-join its groups on fresh sockets (see [`MulticastJoiner::reset`]) -- the join skipped
    /// while absent (`cur == 0`): a join on index 0 would let the kernel pick an arbitrary
    /// interface. The refresh still runs while absent -- no backend errors for a missing
    /// interface (Linux short-circuits on index 0), and the all-absent result is the point:
    /// addresses clear, so the egress gate closes and the lost-address logs fire. The ifindex
    /// is updated first: the Linux resolver keys its dumps by it.
    /// Captures are re-bound separately ([`rebind_capture`](Self::rebind_capture)), so the
    /// caller can log and retry them per capture. Log-free.
    ///
    /// Returns the [`RejoinCounts`] split of joined vs deferred (see
    /// [`MulticastJoiner::rejoin`]); the deferrals heal on the interface's next address event, but
    /// the caller should surface a nonzero deferred count -- after a recreation, deaf groups are a
    /// real outage.
    ///
    /// # Errors
    /// Propagates a resolution syscall failure. The identity is then rolled back so the entry
    /// stays visibly stale and the retry re-runs the whole rebuild -- committed, it would read
    /// as healthy to the scan (the captures re-bind fine) while carrying the OLD interface's
    /// addresses. The joins are replayed before the rollback either way: they need only the
    /// identity, and a transient resolver error must not leave the interface deaf.
    pub(super) fn rebind_interface(
        &mut self,
        key: InterfaceKey,
        cur: u32,
    ) -> io::Result<RejoinCounts> {
        // Keys come from this table's own scan, so the index is always in range.
        let entry = &mut self.entries[key.0 as usize];
        let previous = entry.interface.ifindex;
        entry.interface.ifindex = cur;
        entry.joiner.reset();
        let refreshed = entry.interface.refresh(); // logs each family's gains and losses
        let counts = match NonZeroU32::new(cur) {
            // Parked: nothing to join now; the rebuild on the interface's return replays.
            None => RejoinCounts::default(),
            Some(ifindex) => entry.joiner.rejoin(ifindex),
        };
        if refreshed.is_err() {
            entry.interface.ifindex = previous;
        }
        refreshed.map(|_| counts)
    }

    /// The keys of the captures on `interface`, for a rebuild or eviction pass (the reverse of
    /// [`interface_of`](Self::interface_of); the table keeps no interface->captures index, so
    /// this is a linear scan over the few captures).
    pub(super) fn captures_of(&self, interface: InterfaceKey) -> Vec<CaptureKey> {
        self.captures
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.interface == interface)
            .map(|(index, _)| CaptureKey(u32::try_from(index).expect("capture count fits a u32")))
            .collect()
    }

    /// The captures on the interface currently at `ifindex`, or empty if none matches. The reverse
    /// of [`ifindex_of`](Self::ifindex_of): the refresh path knows the changed index and needs the
    /// stable capture keys to notify handlers, since the index itself is reusable.
    pub(super) fn captures_at_ifindex(&self, ifindex: u32) -> Vec<CaptureKey> {
        match self
            .entries
            .iter()
            .position(|entry| entry.interface.ifindex == ifindex)
        {
            Some(index) => self.captures_of(InterfaceKey(
                u32::try_from(index).expect("interface count fits a u32"),
            )),
            None => Vec::new(),
        }
    }

    /// Re-bind the capture behind `key` to its (recreated) interface, in place -- same fd, same
    /// slot, so every reflector-held key and the reactor's watch stay valid. `Ok(false)` means
    /// no capture sat in the slot (out of range, or taken out mid-drain) -- unreachable when
    /// `key` came from [`captures_of`](Self::captures_of) in the reconcile context, where no
    /// drain is in flight, so the caller should log it rather than treat it as success (the
    /// [`restore`](Self::restore) convention). Log-free; a failed re-bind retries via the
    /// [`attached`](crate::capture::Capture::attached) probe re-flagging the entry.
    ///
    /// # Errors
    /// Propagates the re-bind syscall failure.
    pub(super) fn rebind_capture(&mut self, key: CaptureKey) -> io::Result<bool> {
        match self
            .captures
            .get_mut(key.0 as usize)
            .and_then(|entry| entry.capture.as_mut())
        {
            Some(capture) => capture.rebind().map(|()| true),
            None => Ok(false),
        }
    }

    /// Re-resolve every interface in place. The response to an overflow signal, where dropped
    /// notifications mean any address could be stale. Returns each interface's ifindex paired with
    /// its refresh outcome (best-effort: a per-interface failure is reported, not fatal), so the
    /// caller logs failures and reacts to exactly the interfaces whose addresses moved. Log-free,
    /// like [`refresh_by_ifindex`](Self::refresh_by_ifindex).
    pub(super) fn refresh_all(&mut self) -> Vec<(u32, io::Result<AddressChange>)> {
        let results: Vec<(u32, io::Result<AddressChange>)> = self
            .entries
            .iter_mut()
            .map(|entry| (entry.interface.ifindex, entry.interface.refresh()))
            .collect();
        for entry in &mut self.entries {
            // A parked interface (index 0) has nothing to re-join; the rebuild on its return
            // replays the recorded groups.
            if let Some(ifindex) = NonZeroU32::new(entry.interface.ifindex) {
                entry.joiner.rejoin(ifindex);
            }
        }
        results
    }

    /// Each present capture's `(fd, user_data = CaptureKey)` for
    /// [`Reactor::register_with_fds`](crate::reactor::Reactor::register_with_fds).
    pub(super) fn capture_watches(&self) -> Vec<(RawFd, u64)> {
        self.captures
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let key = CaptureKey(u32::try_from(index).expect("capture count fits a u32"));
                entry
                    .capture
                    .as_ref()
                    .map(|capture| (capture.as_raw_fd(), key.to_u64()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::dispatch::MessageType;
    use crate::dispatch::multicast::join_unsupported;
    use crate::interface::{LOOPBACK_IFACE, if_index};

    impl InterfaceTable {
        /// Overwrite an entry's cached identity, standing in for the kernel recreating the
        /// interface out from under the table. For the dispatcher's reconcile tests.
        pub(in crate::dispatch) fn set_test_ifindex(
            &mut self,
            interface: InterfaceKey,
            ifindex: u32,
        ) {
            self.entries[interface.0 as usize].interface.ifindex = ifindex;
        }

        /// Rename an entry out from under its kernel interface, standing in for a vanished
        /// interface (the new name resolves to nothing). For the dispatcher's reconcile tests.
        pub(in crate::dispatch) fn set_test_name(&mut self, interface: InterfaceKey, name: &str) {
            self.entries[interface.0 as usize].interface.name = name.to_owned();
        }

        /// Push a capture-less entry (no fd) so a routing test can mint a valid [`CaptureKey`] and
        /// exercise the record path without opening a capture; the dangling [`InterfaceKey`] is
        /// never resolved. Reachable from the dispatcher's own tests, hence `pub(in crate::dispatch)`.
        pub(in crate::dispatch) fn add_test_capture(&mut self) -> CaptureKey {
            let key =
                CaptureKey(u32::try_from(self.captures.len()).expect("capture count fits a u32"));
            self.captures.push(CaptureEntry {
                capture: None,
                interface: InterfaceKey(0),
                counters: CaptureCounters::default(),
                last_sent: SentFrame::default(),
            });
            key
        }

        /// The `(reflected, skipped, dropped, stalled)` count recorded for `ty` on `capture`'s row.
        pub(in crate::dispatch) fn typed_counts(
            &self,
            capture: CaptureKey,
            ty: MessageType,
        ) -> (u64, u64, u64, u64) {
            self.captures[capture.0 as usize].counters.typed(ty)
        }

        /// The recovery count recorded on `capture`'s row, for the dispatcher's reconcile test.
        pub(in crate::dispatch) fn recoveries_of(&self, capture: CaptureKey) -> u64 {
            self.captures[capture.0 as usize].counters.recoveries()
        }

        /// The echo count recorded on `capture`'s row, for the dispatcher's echo-drop test.
        pub(in crate::dispatch) fn echoed_of(&self, capture: CaptureKey) -> u64 {
            self.captures[capture.0 as usize].counters.echoed()
        }

        /// Overwrite an interface's cached addresses, giving a routing test's ingress a known MAC
        /// without a real link. For the dispatcher's echo-drop test.
        pub(in crate::dispatch) fn set_test_addrs(
            &mut self,
            interface: InterfaceKey,
            addrs: InterfaceAddresses,
        ) {
            self.entries[interface.0 as usize].interface.addrs = addrs;
        }
    }

    // refresh_by_ifindex re-resolves only the interface(s) with the matching kernel index, reporting
    // the changed fields (`None` for an unwatched index). Resolution is unprivileged (no capture
    // needed), so this exercises the monitor's refresh path without CAP_NET_RAW.
    #[test]
    fn is_last_sent_matches_only_the_set_frame_for_the_same_packet() {
        let mut table = InterfaceTable::new();
        let egress = table.add_test_capture();
        let other = table.add_test_capture();
        let frame = SentFrame {
            packet: 1,
            len: 60,
            checksum: 0x1234,
        };
        // Nothing set yet: a failed send leaves it that way, so a retry goes out.
        assert!(!table.is_last_sent(egress, frame));
        table.set_last_sent(egress, frame);
        assert!(table.is_last_sent(egress, frame));
        // Another egress, another length or checksum, or the next packet: not the same frame.
        assert!(!table.is_last_sent(other, frame));
        assert!(!table.is_last_sent(egress, SentFrame { len: 61, ..frame }));
        assert!(!table.is_last_sent(
            egress,
            SentFrame {
                checksum: 0x1235,
                ..frame
            }
        ));
        assert!(!table.is_last_sent(egress, SentFrame { packet: 2, ..frame }));
        assert!(!table.is_last_sent(CaptureKey::from_u64(999), frame));
        table.set_last_sent(CaptureKey::from_u64(999), frame); // an unknown key is a no-op
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn refresh_by_ifindex_targets_the_matching_interface() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        table.find_or_add_interface(LOOPBACK_IFACE)?;
        let ifindex = if_index(LOOPBACK_IFACE).expect("loopback has an ifindex");
        let change = table
            .refresh_by_ifindex(ifindex)?
            .expect("the loopback interface matches its ifindex and re-resolves");
        assert!(
            !change.v4,
            "re-resolving the unchanged loopback reports no v4 move, the bit the DIAL eviction gates on",
        );
        assert!(
            table.refresh_by_ifindex(u32::MAX)?.is_none(),
            "an ifindex we don't watch should refresh nothing",
        );
        Ok(())
    }

    // join_on records a group on the interface's joiner and joins it; a later refresh re-attempts
    // the recorded memberships idempotently. Unprivileged: loopback accepts the join and resolving
    // the interface needs no CAP_NET_RAW.
    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn join_on_records_a_membership_and_refresh_re_attempts_it() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let iface = table.find_or_add_interface(LOOPBACK_IFACE)?;
        for group in [
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)),
        ] {
            // QEMU user-mode emulation doesn't implement the join setsockopt; self-skip there.
            if let Err(e) = table.join_on(iface, group) {
                if join_unsupported(&e) {
                    eprintln!("skip join_on_records: MCAST_JOIN_GROUP unsupported here ({e})");
                    return Ok(());
                }
                return Err(e);
            }
        }
        // The recorded memberships survive a refresh, re-attempted idempotently (each interface
        // resolves cleanly).
        let results = table.refresh_all();
        assert!(
            results.iter().all(|(_, r)| r.is_ok()),
            "re-resolving every interface succeeds",
        );
        Ok(())
    }

    // stale_interfaces flags an entry whose cached index no longer matches its name's, and
    // rebind_interface repairs it. Unprivileged: pure resolution, no captures, so the probe
    // half of the predicate stays vacuous here (pair tests cover it against real interfaces).
    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn stale_interfaces_flags_and_rebind_repairs_a_moved_index() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let key = table.find_or_add_interface(LOOPBACK_IFACE)?;
        assert!(
            table.stale_interfaces().is_empty(),
            "a fresh entry is healthy"
        );
        let real = if_index(LOOPBACK_IFACE).expect("loopback has an ifindex");
        // Simulate a recreation: the kernel identity moved while the cache kept the old index.
        table.entries[key.0 as usize].interface.ifindex = real + 1000;
        assert_eq!(
            table.stale_interfaces(),
            [StaleInterface {
                key,
                cached: real + 1000,
                cur: real
            }]
        );
        table.rebind_interface(key, real)?;
        assert!(
            table.stale_interfaces().is_empty(),
            "the rebuild repaired the identity"
        );
        assert_eq!(table.entries[key.0 as usize].interface.ifindex, real);
        Ok(())
    }

    // An entry whose name no longer resolves reports absent (0); rebinding to 0 parks it:
    // identity 0, addresses cleared (the egress gate closes), no join attempted (a join on
    // index 0 would let the kernel pick an arbitrary interface).
    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn rebind_to_absent_parks_the_entry() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let key = table.find_or_add_interface(LOOPBACK_IFACE)?;
        table.entries[key.0 as usize].interface.name = "netflector-gone0".into();
        let real = if_index(LOOPBACK_IFACE).expect("loopback has an ifindex");
        assert_eq!(
            table.stale_interfaces(),
            [StaleInterface {
                key,
                cached: real,
                cur: 0
            }]
        );
        table.rebind_interface(key, 0)?;
        assert!(
            table.entries[key.0 as usize].interface.addrs.v4().is_none(),
            "a parked entry's addresses clear, closing the egress gate"
        );
        assert!(
            table.stale_interfaces().is_empty(),
            "a parked entry matches its (absent) identity"
        );
        Ok(())
    }

    // The overflow response must not touch a parked interface's joiner: a rejoin there would
    // have targeted index 0, which the kernel resolves to an arbitrary interface. Socket-less
    // after the park, the joiner must stay socket-less through refresh_all.
    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn refresh_all_does_not_rejoin_a_parked_interface() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let key = table.find_or_add_interface(LOOPBACK_IFACE)?;
        if let Err(e) = table.join_on(key, IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251))) {
            if join_unsupported(&e) {
                eprintln!("skip refresh_all_does_not_rejoin: joins unsupported here ({e})");
                return Ok(());
            }
            return Err(e);
        }
        table.entries[key.0 as usize].interface.name = "netflector-gone0".into();
        table.rebind_interface(key, 0)?; // park: joiner reset, no rejoin
        table.refresh_all();
        assert!(
            table.entries[key.0 as usize].joiner.test_socketless(),
            "a parked interface's joiner stays socket-less through the overflow refresh"
        );
        Ok(())
    }

    #[test]
    fn captures_of_maps_the_reverse_link_and_empty_slots_rebind_as_noops() {
        let mut table = InterfaceTable::new();
        let a = table.add_test_capture(); // both link InterfaceKey(0)
        let b = table.add_test_capture();
        assert_eq!(table.captures_of(InterfaceKey(0)), [a, b]);
        assert!(table.captures_of(InterfaceKey(1)).is_empty());
        // Capture-less slots (drained, or test entries with no fd) and out-of-range keys
        // report Ok(false) -- a signal for the caller to log, not an error and not a success.
        assert!(matches!(table.rebind_capture(a), Ok(false)));
        assert!(matches!(table.rebind_capture(CaptureKey(99)), Ok(false)));
    }

    #[test]
    #[cfg_attr(miri, ignore = "resolves a real interface")]
    fn find_or_add_interface_dedups_by_name() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let first = table.find_or_add_interface(LOOPBACK_IFACE)?;
        let second = table.find_or_add_interface(LOOPBACK_IFACE)?;
        assert_eq!(first, second, "the same name resolves to one interface key");
        Ok(())
    }

    #[test]
    fn capture_accessors_reject_an_out_of_range_key() {
        let mut table = InterfaceTable::new();
        let forged = CaptureKey(0); // nothing added yet
        assert!(!table.contains(forged));
        assert!(table.interface_of(forged).is_none());
        assert!(table.ifindex_of(forged).is_none());
        assert!(table.capture(forged).is_none());
        assert!(table.egress_addrs(forged).is_none());
        assert!(table.take(forged).is_none());
    }
}
