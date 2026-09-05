//! The reflectors: per-protocol packet handlers that re-emit matched traffic on the opposite
//! interface. Each implements the dispatcher's `PacketHandler` and is registered by `run()`
//! from config.

pub(crate) mod dial;
pub(crate) mod mdns;
pub(crate) mod ssdp;
pub(crate) mod udp;
pub(crate) mod wol;
pub(crate) mod wsd;

mod search;
mod simple;

pub(crate) use search::SearchReflector;
pub(crate) use simple::{Classify, Emit, SimpleReflector};

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use thiserror::Error;

use crate::config::AddressFamily;
use crate::dispatch::{CaptureKey, MessageType, PacketDispatcher, join_capped, join_deferrable};
use crate::interface::InterfaceAddresses;
use crate::linear_map::LinearMap;
use crate::logging::WARN_WINDOW;
use crate::net::LinkType;
use crate::net::mac::MacSet;
use crate::reactor::Reactor;

/// A reflector's verdict on a captured payload, from its protocol's classifier. `Reflect`/`Skip` carry
/// the message's own [`MessageType`] (the packet's *intrinsic* type) so the handler can count it. See
/// [`From`] impls like `From<MdnsKind>` in each protocol reflector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// A message for this direction. Re-emit it.
    Reflect(MessageType),
    /// A message for the *other* direction; drop it silently. Dropping the opposite direction is
    /// the loop-breaker (atop the capture's own-egress drop and the dispatcher's echo drop): a
    /// reflected query re-emitted on the egress is still a query, which the egress side's
    /// response-only reflector skips.
    Skip(MessageType),
    /// A message this leg recognizes but is configured not to relay (a wake for a device outside
    /// the allow-set). The classifier logged why; drop it silently.
    Excluded,
    /// Not a recognizable protocol message on this dedicated group. Drop it with a debug log.
    Junk,
}

/// Transforms a datagram's payload before it is re-emitted: the SSDP DIAL `LOCATION` rewrite, applied
/// on both the advertisement direction and each search session's reply. Returns the rewrite, held in
/// the implementor's own reused scratch, or `None` to forward `payload` verbatim; the caller also
/// reads `None` as "still advertising the device's own addresses" for the unreachable-advertisement
/// suppression.
/// The `Fn` traits can't express that lending signature, which is why this is a trait rather than a
/// closure.
pub(crate) trait ReplyRewrite {
    fn rewrite<'a>(
        &'a mut self,
        payload: &[u8],
        egress: CaptureKey,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) -> Option<&'a [u8]>;
}

/// The identity transform: forward the payload verbatim. A ZST for the reflectors (mDNS, WSD, and SSDP
/// without DIAL) that re-emit unchanged.
pub(crate) struct NoRewrite;

impl ReplyRewrite for NoRewrite {
    fn rewrite<'a>(
        &'a mut self,
        _payload: &[u8],
        _egress: CaptureKey,
        _dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) -> Option<&'a [u8]> {
        None
    }
}

/// A concrete IP version: the family a reflector requires of an interface. Distinct from the
/// config's `AddressFamily` policy (which may name both at once).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpFamily {
    V4,
    V6,
}

impl fmt::Display for IpFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        })
    }
}

/// Maps each configured interface name to the capture `run()` opened for it, so a reflector's
/// `source_if` / `target_if` resolve to the ingress / egress [`CaptureKey`]s. `run()` opens one
/// capture per distinct interface and records it here; the per-protocol `build` functions look
/// names up.
#[derive(Default)]
pub(crate) struct InterfaceMap(LinearMap<String, CaptureKey>);

impl InterfaceMap {
    /// Record the capture `run()` opened for `name`.
    pub(crate) fn insert(&mut self, name: String, key: CaptureKey) {
        self.0.insert(name, key);
    }

    /// The capture key recorded for `name`, or `None` if none was.
    pub(crate) fn key_for(&self, name: &str) -> Option<CaptureKey> {
        self.0.get(name).copied()
    }

    /// The capture key for `name`, or [`BuildError::UnknownInterface`]. Build functions call this
    /// to resolve a configured interface name to its capture.
    pub(crate) fn require(&self, name: &str) -> Result<CaptureKey, BuildError> {
        self.key_for(name)
            .ok_or_else(|| BuildError::UnknownInterface(name.to_owned()))
    }
}

/// Why a reflector could not be built from its config.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum BuildError {
    /// Names a `source_if` / `target_if` that `run()` opened no capture for. A wiring bug.
    #[error("no capture for interface \"{0}\"")]
    UnknownInterface(String),
    /// An interface can't currently send a family the reflector requires, so it would reflect
    /// nothing for that family. A startup failure rather than a silent half-run. For a
    /// bidirectional reflector (mDNS/SSDP/WSD) the named interface may be the source or the target.
    #[error("interface \"{interface}\" cannot send {family}, required by the reflector")]
    RequiredFamilyUnavailable { interface: String, family: IpFamily },
    /// A `macs` filter on a target whose link framing carries no MAC addresses: it would match
    /// nothing, silently discarding every device-side packet.
    #[error("macs can never match on interface \"{0}\": its link carries no MAC addresses")]
    MacsUnmatchable(String),
    /// A group the reflector captures could not be joined, for a reason no later event clears,
    /// so its traffic would never arrive. A startup failure rather than a running daemon that
    /// reflects nothing for it.
    #[error("cannot join {group} on interface \"{interface}\": {reason}")]
    GroupJoin {
        group: IpAddr,
        interface: String,
        reason: String,
    },
}

/// Refuse a `macs` filter on a target whose link framing carries no MAC addresses:
/// [`Filter`](crate::dispatch::Filter)'s MAC fields never match a `DLT_NULL` frame. `WoL` never
/// calls this: it matches the MAC inside the magic packet's payload, not the frame's.
fn require_macs_matchable(
    dispatcher: &PacketDispatcher,
    macs: Option<&MacSet>,
    target: CaptureKey,
    target_if: &str,
) -> Result<(), BuildError> {
    if macs.is_some()
        && matches!(dispatcher.link_type(target), Some(link) if link != LinkType::Ethernet)
    {
        return Err(BuildError::MacsUnmatchable(target_if.to_owned()));
    }
    Ok(())
}

/// Whether `egress` currently has a source address of `dst`'s family, which `send_udp_group` needs
/// to build the frame. The per-packet gate a reflector applies before re-emitting, so a family
/// whose address has gone away is dropped rather than mis-sent.
fn egress_sources(dispatcher: &PacketDispatcher, egress: CaptureKey, dst: SocketAddr) -> bool {
    dispatcher
        .egress_addrs(egress)
        .is_some_and(|addrs| match dst {
            SocketAddr::V4(_) => addrs.has_v4(),
            SocketAddr::V6(_) => addrs.has_v6(),
        })
}

/// The family `addrs` cannot source but `family` requires, if any: the startup check's verdict.
/// `None` means every required family is available (a v6-best-effort `Default` with no v6 passes).
fn missing_required_family(family: AddressFamily, addrs: &InterfaceAddresses) -> Option<IpFamily> {
    if family.requires_ipv4() && !addrs.has_v4() {
        Some(IpFamily::V4)
    } else if family.requires_ipv6() && !addrs.has_v6() {
        Some(IpFamily::V6)
    } else {
        None
    }
}

/// Enforce that a bidirectional reflector can source every required family on BOTH interfaces.
/// mDNS, SSDP and WSD re-emit on the source *and* the target, so a family required by `address_family`
/// must be sendable on each. Checks each required family on both interfaces (v4 before v6, the
/// single-interface policy order) and blames the side that actually lacks it: the source when it's
/// the one missing, otherwise the target.
///
/// # Errors
/// [`BuildError::RequiredFamilyUnavailable`] naming the interface and the family it can't send.
fn require_bidirectional_families(
    dispatcher: &PacketDispatcher,
    address_family: AddressFamily,
    source: CaptureKey,
    source_if: &str,
    target: CaptureKey,
    target_if: &str,
) -> Result<(), BuildError> {
    let src = dispatcher.egress_addrs(source).copied().unwrap_or_default();
    let tgt = dispatcher.egress_addrs(target).copied().unwrap_or_default();
    let unavailable = |family, missing_on_source| BuildError::RequiredFamilyUnavailable {
        interface: if missing_on_source {
            source_if
        } else {
            target_if
        }
        .to_owned(),
        family,
    };
    if address_family.requires_ipv4() && !(src.has_v4() && tgt.has_v4()) {
        return Err(unavailable(IpFamily::V4, !src.has_v4()));
    }
    if address_family.requires_ipv6() && !(src.has_v6() && tgt.has_v6()) {
        return Err(unavailable(IpFamily::V6, !src.has_v6()));
    }
    Ok(())
}

/// Join `group` on `capture`, the capture of `interface`, for `protocol`. A
/// [deferrable](join_deferrable) failure logs at debug (it retries on the next address change);
/// any other fails the build.
///
/// # Errors
/// [`BuildError::GroupJoin`], naming the system's membership cap when that is the cause.
fn require_group_join(
    dispatcher: &mut PacketDispatcher,
    capture: CaptureKey,
    group: IpAddr,
    protocol: &str,
    interface: &str,
) -> Result<(), BuildError> {
    match dispatcher.join_group(capture, group) {
        Ok(()) => log::debug!("{protocol}: joined {group} on {interface}"),
        Err(e) if join_deferrable(&e) => {
            log::debug!(
                "{protocol}: join {group} on {interface} deferred (no address of its family yet): {e}"
            );
        }
        Err(e) => {
            let reason = if join_capped(&e) {
                format!(
                    "{e}; the interface holds as many memberships as the system allows \
                     (net.ipv4.igmp_max_memberships on Linux)"
                )
            } else {
                e.to_string()
            };
            return Err(BuildError::GroupJoin {
                group,
                interface: interface.to_owned(),
                reason,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::capture::{Capture, loopback_lock};
    use crate::interface::LOOPBACK_IFACE;
    use crate::net::mac::MacAddr;

    /// Open a loopback capture, or `None` (skip) without `CAP_NET_RAW`.
    fn open_loopback_or_skip() -> Option<Capture> {
        match Capture::open(LOOPBACK_IFACE) {
            Ok(cap) => Some(cap),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skip: no CAP_NET_RAW to open a loopback capture ({e})");
                None
            }
            Err(e) => panic!("unexpected loopback capture open failure: {e}"),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn macs_matchability_follows_the_target_link_framing() {
        let _serial = loopback_lock();
        let Some(cap) = open_loopback_or_skip() else {
            return;
        };
        let mut dispatcher = PacketDispatcher::new();
        let target = dispatcher
            .add_capture(cap)
            .expect("add the loopback capture");
        // No filter configured: nothing to refuse, whatever the framing.
        assert_eq!(
            require_macs_matchable(&dispatcher, None, target, LOOPBACK_IFACE),
            Ok(())
        );
        let macs = MacSet::from(MacAddr::from([2, 0, 0, 0, 0, 1]));
        let result = require_macs_matchable(&dispatcher, Some(&macs), target, LOOPBACK_IFACE);
        // Linux frames loopback as Ethernet, so MACs match there; the BSDs' loopback is
        // `DLT_NULL`, the framing the check refuses.
        #[cfg(target_os = "linux")]
        assert_eq!(result, Ok(()));
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        assert_eq!(
            result,
            Err(BuildError::MacsUnmatchable(LOOPBACK_IFACE.to_owned()))
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn a_join_failure_no_event_clears_fails_the_build() {
        let _serial = loopback_lock();
        let Some(cap) = open_loopback_or_skip() else {
            return;
        };
        let mut dispatcher = PacketDispatcher::new();
        let capture = dispatcher
            .add_capture(cap)
            .expect("add the loopback capture");
        // A unicast address is no group: the join is refused outright, whatever the platform.
        let not_a_group = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let result = require_group_join(
            &mut dispatcher,
            capture,
            not_a_group,
            "test",
            LOOPBACK_IFACE,
        );
        assert!(matches!(
            result,
            Err(BuildError::GroupJoin { group, ref interface, .. })
                if group == not_a_group && interface == LOOPBACK_IFACE
        ));
    }

    #[test]
    fn missing_required_family_enforces_the_requires_policy() {
        let none = InterfaceAddresses::default();
        let v4_only = InterfaceAddresses::new(None, Some(Ipv4Addr::LOCALHOST), None, None);
        // Default requires v4 only: a v4-less egress fails on v4, a v6-less one passes.
        assert_eq!(
            missing_required_family(AddressFamily::Default, &none),
            Some(IpFamily::V4)
        );
        assert_eq!(
            missing_required_family(AddressFamily::Default, &v4_only),
            None
        );
        // Dual requires both: a v4-only egress still misses v6.
        assert_eq!(
            missing_required_family(AddressFamily::Dual, &v4_only),
            Some(IpFamily::V6)
        );
        // Ipv6 requires v6.
        assert_eq!(
            missing_required_family(AddressFamily::Ipv6, &v4_only),
            Some(IpFamily::V6)
        );
    }
}
