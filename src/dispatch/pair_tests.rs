//! Interface-pair tests: inject through the production build/send path on one end of a connected
//! virtual pair and observe on the other, so the capture backend, frame builders, per-scope source
//! selection, and multicast joins run against a real non-loopback interface. The pair fixture is
//! the only platform-specific piece (veth on Linux, feth on macOS, epair on FreeBSD); the tests are
//! shared. Interface creation needs root, so every test skips with a note otherwise: run with
//! `sudo cargo test pair_` (or a container with `NET_ADMIN`).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::capture::{Capture, Read};
use crate::interface::{Interface, InterfaceAddresses, Ipv6Scope, if_index};
use crate::net::packet::Packet;
use crate::sys::socklen_of;
#[cfg(target_os = "linux")]
use crate::{
    libcex::{GroupReq, MCAST_JOIN_GROUP},
    sys::sockaddr_for,
};

use super::datagram::{DatagramSource, build_udp, ethernet_dst};
use super::interface_table::InterfaceTable;
use super::multicast::MulticastJoiner;

const INJECT_SRC_PORT: u16 = 40000;
const INJECT_DST_PORT: u16 = 40009;
const WAIT_BUDGET: Duration = Duration::from_secs(3);
const POLL_SLICE: Duration = Duration::from_millis(50);
/// Run `command` through the shell, succeeding only on exit 0; output is discarded.
fn run(command: &str) -> bool {
    Command::new("sh")
        .args(["-ec", command])
        .output()
        .is_ok_and(|output| output.status.success())
}

/// Run `command` and return its trimmed stdout, or `None` on failure or empty output. Captures
/// the interface name `ifconfig feth/epair create` prints.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn run_capture(command: &str) -> Option<String> {
    let output = Command::new("sh").args(["-ec", command]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let name = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!name.is_empty()).then_some(name)
}

/// Serializes the pair tests' interface create/destroy. They run in parallel and the feth/epair
/// fixtures take kernel-assigned names, so one test's destroy frees a name a parallel test's
/// create-by-name (in [`recreate`](InterfacePair::recreate)) then collides with. One creator at a
/// time keeps the naming deterministic. Poison is ignored: a panicking test must not wedge the rest.
static PAIR_LOCK: Mutex<()> = Mutex::new(());

/// A connected virtual-interface pair for the test's lifetime. `create` returns `None` (with a
/// skip note) without root or when the platform tooling refuses; `Drop` destroys only interfaces
/// this fixture created.
struct InterfacePair {
    inject: String,
    receive: String,
    /// This pair's slot in the per-pair address plan.
    subnet: u8,
}

// The address plan. Pairs run concurrently in one network stack (there is no namespace), so
// every pair gets its own v4 subnet and ULA prefix, keyed by `subnet`: an address shared between
// pairs would make the observer's join-by-address ambiguous and the source asserts unstable.
// The link-locals can repeat -- `fe80::` is scoped per link by definition.
impl InterfacePair {
    fn inject_v4(&self) -> Ipv4Addr {
        Ipv4Addr::new(10, 99, self.subnet, 1)
    }
    fn receive_v4(&self) -> Ipv4Addr {
        Ipv4Addr::new(10, 99, self.subnet, 2)
    }
    fn inject_ula(&self) -> Ipv6Addr {
        Ipv6Addr::new(0xfd00, 0x99, u16::from(self.subnet), 0, 0, 0, 0, 1)
    }
}

impl InterfacePair {
    fn create() -> Option<Self> {
        use std::sync::atomic::{AtomicU8, Ordering};
        static NEXT_SUBNET: AtomicU8 = AtomicU8::new(1);
        // The fixture is built on ifconfig shell-outs, and a plain std::process::Command spawn
        // SIGSEGVs in a statically-linked (+crt-static) binary on FreeBSD since rustc 1.96:
        // std resolves `environ` via dlsym (null without a dynamic symbol table) and
        // posix_spawn dereferences it to capture the inherited env -- the same std bug
        // sys::process_env works around for the daemon's config path. FreeBSD coverage comes
        // from the dynamic (debug) lane; the static lane keeps proving the +crt-static build
        // for the rest of the suite.
        if cfg!(all(target_os = "freebsd", target_feature = "crt-static")) {
            eprintln!("skip pair test: process spawning crashes static FreeBSD binaries");
            return None;
        }
        // SAFETY: geteuid takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skip pair test: interface creation requires root");
            return None;
        }
        // Held through create + settle so no parallel pair test creates an interface concurrently
        // (see PAIR_LOCK); released when this returns, before the test body runs.
        let _serialize = PAIR_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let pair = Self::create_platform(NEXT_SUBNET.fetch_add(1, Ordering::Relaxed))?;
        pair.settle();
        Some(pair)
    }

    /// Wait until both ends are up+running with their address plans resolved. A pair we just
    /// created as root not coming up is an anomaly, not a missing precondition -- it must fail
    /// the test (the panic unwinds through Drop, so the interfaces are still torn down), never
    /// skip it. Needed because a fresh pair drops frames until the carrier settles (with no
    /// retransmit), and manually-assigned v6 addresses are tentative until DAD completes (the
    /// resolver filters unusable ones). Tests can then open interfaces and use addresses
    /// without per-test settling logic.
    fn settle(&self) {
        let deadline = Instant::now() + WAIT_BUDGET;
        while !(link_running(&self.inject) && link_running(&self.receive))
            && Instant::now() < deadline
        {
            std::thread::sleep(POLL_SLICE);
        }
        assert!(
            link_running(&self.inject) && link_running(&self.receive),
            "{}/{} not up+running after {WAIT_BUDGET:?}",
            self.inject,
            self.receive
        );
        let mut inject = Interface::open(&self.inject).expect("resolve the inject interface");
        assert!(
            wait_for_source(&mut inject, |iface| {
                iface.addrs.has_v4()
                    && iface
                        .addrs
                        .v6(Ipv6Scope::LinkLocal)
                        .is_some_and(|addr| addr.is_unicast_link_local())
                    && iface
                        .addrs
                        .v6(Ipv6Scope::Routable)
                        .is_some_and(|addr| !addr.is_unicast_link_local())
            }),
            "{} never resolved its v4 + link-local + routable v6 plan",
            self.inject
        );
        let mut receive = Interface::open(&self.receive).expect("resolve the receive interface");
        assert!(
            wait_for_source(&mut receive, |iface| iface.addrs.has_v4()
                && iface.addrs.has_v6()),
            "{} never resolved its v4 + link-local plan",
            self.receive
        );
    }

    /// Destroy and recreate the pair's interfaces under the same names -- fresh kernel identities,
    /// as an operator's `PPPoE` reconnect or bridge rebuild would produce -- then reconfigure and
    /// settle. Panics on failure, like [`settle`](Self::settle): the pair was created, configured,
    /// and brought up once already, so the tooling and privileges are known good; a relink or
    /// reconfigure that fails now is an anomaly to surface, not a precondition to skip on.
    fn recreate(&self) {
        // Serialize against every other pair test's create/recreate (see PAIR_LOCK): the destroy
        // here frees a kernel-assigned name that a concurrent create-by-name would otherwise grab.
        let _serialize = PAIR_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        assert!(
            self.relink() && self.configure(),
            "recreating {}/{} failed after a successful create",
            self.inject,
            self.receive
        );
        self.settle();
    }

    /// Linux: veth names are caller-chosen, so derive them from the pid and a counter -- unique
    /// against other processes and against this process's concurrently-running tests.
    #[cfg(target_os = "linux")]
    fn create_platform(subnet: u8) -> Option<Self> {
        let inject = format!("rp{}x{subnet}a", std::process::id() % 100_000);
        let receive = format!("rp{}x{subnet}b", std::process::id() % 100_000);
        if !run(&format!(
            "ip link add {inject} type veth peer name {receive}"
        )) {
            eprintln!("skip pair test: could not create a veth pair");
            return None;
        }
        let pair = Self {
            inject,
            receive,
            subnet,
        }; // Drop cleans up from here on
        if !pair.configure() {
            eprintln!("skip pair test: could not configure the veth pair");
            return None;
        }
        Some(pair)
    }

    /// Assign the pair's address plan and bring both ends up. Manual link-locals with nodad so
    /// both ends are usable immediately, no DAD wait.
    #[cfg(target_os = "linux")]
    fn configure(&self) -> bool {
        run(&format!(
            "ip addr add {}/24 dev {}",
            self.inject_v4(),
            self.inject
        )) && run(&format!(
            "ip -6 addr add fe80::1/64 dev {} nodad",
            self.inject
        )) && run(&format!(
            "ip -6 addr add {}/64 dev {} nodad",
            self.inject_ula(),
            self.inject
        )) && run(&format!(
            "ip addr add {}/24 dev {}",
            self.receive_v4(),
            self.receive
        )) && run(&format!(
            "ip -6 addr add fe80::2/64 dev {} nodad",
            self.receive
        )) && run(&format!("ip link set {} up", self.inject))
            && run(&format!("ip link set {} up", self.receive))
            // Both ends sit in one stack, so every wire-crossing v4 packet carries a local
            // source address, and Linux's fib_validate_source drops those as martians before
            // socket delivery (tcpdump still sees them below IP). accept_local admits them;
            // the BSDs have no such gate. It is an ORCONF sysctl (conf/all OR conf/<iface>), so
            // a preset conf/all already covers every interface, including ones created later:
            // skip the per-interface write then, since it needs a writable /proc/sys, which
            // docker mounts read-only (docker_test.sh presets `all` via --sysctl instead of
            // unmasking /proc).
            && (Self::accept_local_preset()
                || (run(&format!(
                    "echo 1 > /proc/sys/net/ipv4/conf/{}/accept_local",
                    self.inject
                )) && run(&format!(
                    "echo 1 > /proc/sys/net/ipv4/conf/{}/accept_local",
                    self.receive
                ))))
    }

    /// Whether `net.ipv4.conf.all.accept_local` is already 1. Reading /proc/sys works even where
    /// writing it doesn't, so this lets a caller preset the ORCONF `all` knob out of band (the
    /// docker dev container does, via `--sysctl`) and keep /proc/sys read-only.
    #[cfg(target_os = "linux")]
    fn accept_local_preset() -> bool {
        std::fs::read_to_string("/proc/sys/net/ipv4/conf/all/accept_local")
            .is_ok_and(|value| value.trim() == "1")
    }

    /// Destroy the pair and recreate it under the same names (deleting one veth end removes
    /// both; the names are caller-chosen, so the re-add reuses them).
    #[cfg(target_os = "linux")]
    fn relink(&self) -> bool {
        run(&format!("ip link del {}", self.inject))
            && run(&format!(
                "ip link add {} type veth peer name {}",
                self.inject, self.receive
            ))
    }

    /// macOS: feth units are kernel-assigned (`ifconfig feth create` prints the name), so two
    /// creations never collide with an existing interface or a concurrent test.
    #[cfg(target_os = "macos")]
    fn create_platform(subnet: u8) -> Option<Self> {
        let inject = run_capture("ifconfig feth create")?;
        let Some(receive) = run_capture("ifconfig feth create") else {
            run(&format!("ifconfig {inject} destroy"));
            eprintln!("skip pair test: could not create the second feth");
            return None;
        };
        let pair = Self {
            inject,
            receive,
            subnet,
        }; // Drop cleans up from here on
        if !pair.configure() {
            eprintln!("skip pair test: could not configure the feth pair");
            return None;
        }
        Some(pair)
    }

    /// Peer the two feths, assign the pair's address plan, and bring both ends up. feth has no
    /// automatic IPv6 link-local, so assign one on each end explicitly.
    #[cfg(target_os = "macos")]
    fn configure(&self) -> bool {
        run(&format!("ifconfig {} peer {}", self.inject, self.receive))
            && run(&format!(
                "ifconfig {} inet {}/24 up",
                self.inject,
                self.inject_v4()
            ))
            && run(&format!(
                "ifconfig {} inet6 fe80::1 prefixlen 64",
                self.inject
            ))
            && run(&format!(
                "ifconfig {} inet6 {} prefixlen 64",
                self.inject,
                self.inject_ula()
            ))
            && run(&format!("ifconfig {} up", self.receive))
            && run(&format!(
                "ifconfig {} inet {}/24",
                self.receive,
                self.receive_v4()
            ))
            && run(&format!(
                "ifconfig {} inet6 fe80::2 prefixlen 64",
                self.receive
            ))
    }

    /// Destroy both feths and recreate them under the same names: a specific unit can be
    /// created by naming it (`ifconfig fethN create`), unlike the first create, which lets
    /// the kernel pick.
    #[cfg(target_os = "macos")]
    fn relink(&self) -> bool {
        run(&format!("ifconfig {} destroy", self.inject))
            && run(&format!("ifconfig {} destroy", self.receive))
            && run(&format!("ifconfig {} create", self.inject))
            && run(&format!("ifconfig {} create", self.receive))
    }

    /// FreeBSD: `ifconfig epair create` mints a connected pair and prints the `a` end; the peer
    /// is the same name with a trailing `b`. Destroying the `a` end removes both.
    #[cfg(target_os = "freebsd")]
    fn create_platform(subnet: u8) -> Option<Self> {
        let inject = run_capture("ifconfig epair create")?;
        if !inject.ends_with('a') {
            run(&format!("ifconfig {inject} destroy"));
            eprintln!("skip pair test: unexpected epair name {inject}");
            return None;
        }
        let receive = format!("{}b", &inject[..inject.len() - 1]);
        let pair = Self {
            inject,
            receive,
            subnet,
        }; // Drop cleans up from here on
        if !pair.configure() {
            eprintln!("skip pair test: could not configure the epair");
            return None;
        }
        Some(pair)
    }

    /// Assign the pair's address plan and bring both ends up.
    #[cfg(target_os = "freebsd")]
    fn configure(&self) -> bool {
        run(&format!(
            "ifconfig {} inet {}/24 up",
            self.inject,
            self.inject_v4()
        )) && run(&format!(
            "ifconfig {} inet6 fe80::1 prefixlen 64",
            self.inject
        )) && run(&format!(
            "ifconfig {} inet6 {} prefixlen 64",
            self.inject,
            self.inject_ula()
        )) && run(&format!("ifconfig {} up", self.receive))
            && run(&format!(
                "ifconfig {} inet {}/24",
                self.receive,
                self.receive_v4()
            ))
            && run(&format!(
                "ifconfig {} inet6 fe80::2 prefixlen 64",
                self.receive
            ))
    }

    /// Destroy the epair (removing both ends) and recreate it under the same names: the
    /// cloner accepts a specific unit (`ifconfig epairN create` mints `epairNa`+`epairNb`),
    /// unlike the first create, which lets the kernel pick.
    #[cfg(target_os = "freebsd")]
    fn relink(&self) -> bool {
        let base = &self.inject[..self.inject.len() - 1]; // "epairNa" -> "epairN"
        run(&format!("ifconfig {} destroy", self.inject)) && run(&format!("ifconfig {base} create"))
    }
}

impl Drop for InterfacePair {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        run(&format!("ip link del {}", self.inject)); // removes both ends
        #[cfg(target_os = "macos")]
        {
            run(&format!("ifconfig {} destroy", self.inject));
            run(&format!("ifconfig {} destroy", self.receive));
        }
        #[cfg(target_os = "freebsd")]
        run(&format!("ifconfig {} destroy", self.inject)); // removes both ends
    }
}

/// True once `name` is administratively up with a running link layer. `getifaddrs` is portable
/// across all three platforms and the flags repeat on each of an interface's entries, so one
/// matching entry suffices.
fn link_running(name: &str) -> bool {
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills a heap-allocated list; freed below with freeifaddrs.
    if unsafe { libc::getifaddrs(&raw mut addrs) } != 0 {
        return false;
    }
    let mut running = false;
    let mut cursor = addrs;
    while !cursor.is_null() {
        // SAFETY: `cursor` walks the list getifaddrs returned; entries stay valid until the
        // freeifaddrs below.
        let entry = unsafe { &*cursor };
        if !entry.ifa_name.is_null() {
            // SAFETY: ifa_name is a NUL-terminated string owned by the list.
            let ifa_name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) };
            if ifa_name.to_bytes() == name.as_bytes() {
                let up_and_running =
                    libc::IFF_UP.cast_unsigned() | libc::IFF_RUNNING.cast_unsigned();
                running = entry.ifa_flags & up_and_running == up_and_running;
                break;
            }
        }
        cursor = entry.ifa_next;
    }
    // SAFETY: `addrs` came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(addrs) };
    running
}

/// Re-resolve `iface` until `ready` holds, waiting out IPv6 DAD (a freshly-assigned address is
/// briefly tentative and filtered from resolution). False if the budget elapses.
fn wait_for_source(iface: &mut Interface, ready: impl Fn(&Interface) -> bool) -> bool {
    let deadline = Instant::now() + WAIT_BUDGET;
    loop {
        if ready(iface) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(POLL_SLICE);
        iface.refresh().ok();
    }
}

/// A parsed frame copied out of the capture's reused buffer, so assertions outlive the read.
struct CapturedDatagram {
    source: SocketAddr,
    dest: SocketAddr,
    payload: Vec<u8>,
}

/// Drain `peer` until it captures the datagram injected by this test (matched by source port and
/// destination address) or the budget runs out -- interfaces carry unrelated traffic too.
fn capture_injected(peer: &mut Capture, dest: IpAddr) -> io::Result<Option<CapturedDatagram>> {
    let link = peer.link_type();
    let deadline = Instant::now() + WAIT_BUDGET;
    while Instant::now() < deadline {
        match peer.next_frame()? {
            Some(Read::Oversized) => {}
            Some(Read::Frame(frame)) => {
                let Ok(packet) = Packet::parse(link, frame) else {
                    continue; // unrelated non-UDP or malformed traffic
                };
                if packet.source.port() == INJECT_SRC_PORT && packet.dest.ip() == dest {
                    return Ok(Some(CapturedDatagram {
                        source: packet.source,
                        dest: packet.dest,
                        payload: packet.payload.to_vec(),
                    }));
                }
            }
            None => std::thread::sleep(POLL_SLICE),
        }
    }
    Ok(None)
}

/// Build a datagram with the production builder (the egress's own addresses and MAC, per-scope
/// v6 source) and inject it through the production send path.
fn inject(
    addrs: &InterfaceAddresses,
    injector: &Capture,
    dst: SocketAddr,
    payload: &[u8],
) -> io::Result<()> {
    let mut scratch = [0u8; 2048];
    let n = build_udp(
        addrs,
        injector.link_type(),
        dst,
        ethernet_dst(dst.ip(), None).expect("broadcast/multicast destination"),
        DatagramSource::Egress {
            port: INJECT_SRC_PORT,
        },
        64,
        payload,
        &mut scratch,
    )
    .expect("build the injected frame")
    .len;
    injector.send(&scratch[..n])
}

// Injects a broadcast on one end and captures it on the other: the send and capture backends,
// framing, and checksums against a real (non-loopback, Ethernet-framed) interface. The peer
// observes through a capture, not a UDP socket: the kernel drops an arriving IPv4 datagram whose
// source is one of the host's own addresses (a local martian), but a capture taps below IP.
#[test]
fn pair_injected_broadcast_is_captured_on_the_peer() -> io::Result<()> {
    let Some(pair) = InterfacePair::create() else {
        return Ok(());
    };
    let iface = Interface::open(&pair.inject)?;
    let injector = Capture::open(&pair.inject)?;
    let mut peer = Capture::open(&pair.receive)?;

    let payload = b"pair-broadcast";
    let dst = SocketAddr::from((Ipv4Addr::BROADCAST, INJECT_DST_PORT));
    inject(&iface.addrs, &injector, dst, payload)?;

    let captured = capture_injected(&mut peer, dst.ip())?.expect("peer captured the broadcast");
    assert_eq!(captured.payload, payload);
    assert_eq!(captured.dest.port(), INJECT_DST_PORT);
    assert_eq!(captured.source.ip(), IpAddr::V4(pair.inject_v4()));
    Ok(())
}

// Interface recreation gives the name a fresh kernel identity, stranding the old capture:
// attached() flips false, rebind() re-attaches the same fd (Linux: bind(2) re-hooks the packet
// socket from its unregistered state; BSD: BIOCSETIF re-attaches the detached descriptor), and
// an injected broadcast proves delivery resumed end to end. This is the kernel-behavior
// verification the interface hot-swap recovery rests on.
#[test]
fn pair_capture_rebinds_after_interface_recreation() -> io::Result<()> {
    let Some(pair) = InterfacePair::create() else {
        return Ok(());
    };
    let mut peer = Capture::open(&pair.receive)?;
    let index = if_index(&pair.receive).expect("receive ifindex");
    assert!(peer.attached(index), "a fresh capture reports attached");

    pair.recreate();
    let index = if_index(&pair.receive).expect("recreated receive ifindex");
    assert!(
        !peer.attached(index),
        "a capture on the destroyed interface reports detached"
    );

    peer.rebind()?;
    assert!(
        peer.attached(index),
        "the re-bound capture reports attached"
    );

    // Delivery is live again: inject on the recreated far end, capture on the re-bound fd.
    let iface = Interface::open(&pair.inject)?;
    let injector = Capture::open(&pair.inject)?;
    let payload = b"pair-rebind";
    let dst = SocketAddr::from((Ipv4Addr::BROADCAST, INJECT_DST_PORT));
    inject(&iface.addrs, &injector, dst, payload)?;
    let captured =
        capture_injected(&mut peer, dst.ip())?.expect("the re-bound capture sees the broadcast");
    assert_eq!(captured.payload, payload);
    Ok(())
}

// The interface table's own recovery, end to end against a real recreation, driving BOTH ends of
// the pair at once -- the path the periodic reconcile follows (the only detection macOS has, its
// recreated ifnet keeping the index). Both interfaces sit in the table with a capture each, and a
// baseline injection proves delivery works first. After the pair is destroyed and recreated under
// its names, stale_interfaces flags BOTH entries through the captures' attached() probe -- the half
// the unprivileged unit test leaves vacuous, and the only half that fires when the index is reused.
// rebind_interface re-points each entry and replays its recorded joins on a fresh socket (none
// deferred), rebind_capture re-attaches each fd in place, and a second injection -- sent on the
// re-bound injector, observed on the re-bound receiver -- proves delivery resumed through the very
// captures that were stranded.
#[test]
fn pair_interface_table_recovers_after_interface_recreation() -> io::Result<()> {
    let Some(pair) = InterfacePair::create() else {
        return Ok(());
    };
    let mut table = InterfaceTable::new();
    let inject_key = table.find_or_add_interface(&pair.inject)?;
    let injector = table.add_capture(Capture::open(&pair.inject)?, inject_key);
    let receive_key = table.find_or_add_interface(&pair.receive)?;
    let receiver = table.add_capture(Capture::open(&pair.receive)?, receive_key);
    // Record memberships on the receive side so its rebuild has groups to replay on the fresh socket.
    table.join_on(receive_key, IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)))?;
    table.join_on(
        receive_key,
        IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)),
    )?;
    assert!(
        table.stale_interfaces().is_empty(),
        "a freshly-built table is healthy"
    );

    // Baseline: delivery works through both captures before any recreation. The frame's source
    // addresses come from the table's own resolved copy of the inject interface -- no second open.
    let payload = b"pair-table-recover";
    let dst = SocketAddr::from((Ipv4Addr::BROADCAST, INJECT_DST_PORT));
    inject(
        table
            .egress_addrs(injector)
            .expect("the inject interface's addresses"),
        table
            .capture(injector)
            .expect("the injector capture is present"),
        dst,
        payload,
    )?;
    let mut receiver_cap = table
        .take(receiver)
        .expect("the receiver capture is present");
    assert!(
        capture_injected(&mut receiver_cap, dst.ip())?.is_some(),
        "delivery works before the recreation"
    );
    assert!(
        table.restore(receiver, receiver_cap),
        "restore the receiver for the recovery"
    );

    pair.recreate();

    // Both interfaces are stranded. On a reused index only the attached() probe catches it; either
    // way both entries are flagged.
    let stale = table.stale_interfaces();
    assert_eq!(
        stale.len(),
        2,
        "both recreated interfaces are flagged stale"
    );

    // Drive the production recovery for each: re-point + replay its joins on a fresh socket (only
    // the receive side recorded any), then re-attach its capture fd in place.
    for s in &stale {
        let counts = table.rebind_interface(s.key, s.cur)?;
        let expected_joined = if s.key == receive_key { 2 } else { 0 };
        assert_eq!(
            (counts.joined, counts.deferred, counts.failed),
            (expected_joined, 0, 0),
            "the interface re-joined its recorded groups on the fresh socket, none deferred"
        );
        for capture in table.captures_of(s.key) {
            assert!(
                table.rebind_capture(capture)?,
                "the capture re-bound in place"
            );
        }
    }
    assert!(
        table.stale_interfaces().is_empty(),
        "the rebuild cleared all staleness"
    );

    // Delivery resumes through the very captures that were stranded: sent on the re-bound injector
    // (with the interface's re-resolved addresses, straight from the table), observed on the
    // re-bound receiver.
    inject(
        table
            .egress_addrs(injector)
            .expect("the re-bound inject interface's addresses"),
        table
            .capture(injector)
            .expect("the re-bound injector is present"),
        dst,
        payload,
    )?;
    let mut receiver_cap = table
        .take(receiver)
        .expect("the re-bound receiver is present");
    let captured = capture_injected(&mut receiver_cap, dst.ip())?
        .expect("delivery resumed after recovery, through both re-bound captures");
    assert_eq!(captured.payload, payload);
    Ok(())
}

// Injects an IPv6 multicast datagram and receives it on a real UDP socket joined on the peer:
// the kernel validates the UDP checksum before delivery (it silently drops a bad one), so this
// asserts the v6 checksum on the wire, which a capture-side check cannot.
#[test]
fn pair_injected_v6_multicast_reaches_a_joined_udp_socket() -> io::Result<()> {
    let Some(pair) = InterfacePair::create() else {
        return Ok(());
    };
    let iface = Interface::open(&pair.inject)?;
    let injector = Capture::open(&pair.inject)?;

    let receiver = UdpSocket::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))?;
    let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    receiver.join_multicast_v6(
        &all_nodes,
        if_index(&pair.receive).expect("receive ifindex"),
    )?;
    receiver.set_read_timeout(Some(WAIT_BUDGET))?;
    let port = receiver.local_addr()?.port();

    let payload = b"pair-v6-multicast";
    inject(
        &iface.addrs,
        &injector,
        SocketAddr::from((all_nodes, port)),
        payload,
    )?;

    let mut buffer = [0u8; 64];
    let (length, _) = receiver.recv_from(&mut buffer)?;
    assert_eq!(&buffer[..length], payload);
    Ok(())
}

// The per-scope IPv6 source selection on the wire: a site-local-scoped group is sourced from the
// pair's ULA, a link-local-scoped group from a link-local address, asserted on the frames the
// peer captures.
#[test]
fn pair_sources_v6_multicast_by_destination_scope() -> io::Result<()> {
    let Some(pair) = InterfacePair::create() else {
        return Ok(());
    };
    let iface = Interface::open(&pair.inject)?;
    let injector = Capture::open(&pair.inject)?;
    let mut peer = Capture::open(&pair.receive)?;
    let payload = b"pair-scope";

    let site_group = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0x0c);
    inject(
        &iface.addrs,
        &injector,
        SocketAddr::from((site_group, INJECT_DST_PORT)),
        payload,
    )?;
    let site = capture_injected(&mut peer, IpAddr::V6(site_group))?
        .expect("captured the site-local-scoped datagram");
    assert_eq!(
        site.source.ip(),
        IpAddr::V6(pair.inject_ula()),
        "ff05:: sourced from the routable address"
    );

    let link_group = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0c);
    inject(
        &iface.addrs,
        &injector,
        SocketAddr::from((link_group, INJECT_DST_PORT)),
        payload,
    )?;
    let link = capture_injected(&mut peer, IpAddr::V6(link_group))?
        .expect("captured the link-local-scoped datagram");
    // Class, not identity: the kernel may auto-generate an EUI-64 link-local next to the manual
    // fe80::1, and which one resolution picks is not ours to pin.
    let IpAddr::V6(link_source) = link.source.ip() else {
        panic!("v6 datagram parsed with a v4 source");
    };
    assert!(
        link_source.is_unicast_link_local(),
        "ff02:: sourced from a link-local address, got {link_source}"
    );
    Ok(())
}

/// Subscribe a raw observer socket to `group` on `ifindex`: Linux gates multicast delivery to
/// raw sockets by the socket's own memberships (`ip_mc_sf_allow`), so the observer must join
/// what it wants to see. The BSDs deliver raw packets by protocol alone -- and macOS rejects
/// `MCAST_JOIN_GROUP` on raw sockets outright -- so there this is neither needed nor possible.
#[cfg(target_os = "linux")]
fn subscribe(fd: &OwnedFd, group: IpAddr, ifindex: u32) -> io::Result<()> {
    let level = match group {
        IpAddr::V4(_) => libc::IPPROTO_IP,
        IpAddr::V6(_) => libc::IPPROTO_IPV6,
    };
    // Zero first, as the production joiner does: setsockopt reads the whole struct, padding
    // included.
    // SAFETY: `group_req` is plain data; all-zero is valid.
    let mut request: GroupReq = unsafe { std::mem::zeroed() };
    request.gr_interface = ifindex;
    request.gr_group = sockaddr_for(group, 0, 0).0;
    // SAFETY: `request` is a fully-initialised `group_req`, passed by address and size.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            MCAST_JOIN_GROUP,
            (&raw const request).cast::<libc::c_void>(),
            socklen_of::<GroupReq>(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// A raw socket observing every `protocol` packet the stack accepts, with a short read timeout
/// so the scan loop stays simple. It holds no memberships itself: multicast acceptance is the
/// receiving DEVICE's membership, which the caller provides through the production joiner (plus,
/// on Linux, a per-socket [`subscribe`]).
fn raw_observer(family: libc::c_int, protocol: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: `socket` returns a fresh descriptor or -1, checked below.
    let raw = unsafe { libc::socket(family, libc::SOCK_RAW, protocol) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh, owned, valid descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 100_000,
    };
    // SAFETY: `timeout` is a valid timeval, passed by address and size.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const timeout).cast::<libc::c_void>(),
            socklen_of::<libc::timeval>(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Drain `observer` until a packet carries `group_octets` or the budget elapses. An IGMPv3/MLDv2
/// report names the group in a record; the older v1/v2 report forms are addressed to the group
/// itself, which the scan still matches via the IPv4 header raw v4 sockets include. Unrelated
/// reports (other daemons' groups) simply never match.
fn saw_membership_report(observer: &OwnedFd, group_octets: &[u8]) -> bool {
    let mut buffer = [0u8; 512];
    let deadline = Instant::now() + WAIT_BUDGET;
    while Instant::now() < deadline {
        // SAFETY: `buffer` is a valid, writable region of the given length for this open fd.
        let received = unsafe {
            libc::recv(
                observer.as_raw_fd(),
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
                0,
            )
        };
        let Ok(received) = usize::try_from(received) else {
            continue; // timeout slice elapsed without a packet; the deadline bounds the loop
        };
        if buffer[..received]
            .windows(group_octets.len())
            .any(|window| window == group_octets)
        {
            return true;
        }
    }
    false
}

// Joining must do more than return success: the kernel has to announce the membership on the
// wire -- an IGMP report for v4, an MLD report for v6 -- because that announcement is what
// switch snooping and querier routers act on (and what accompanies a real NIC's filter
// programming). Raw-socket observers joined on the receive side catch the reports the inject
// side's join emits across the pair. The groups are test-unique so other daemons' reports
// never match.
#[test]
fn pair_join_announces_membership_on_the_wire() -> io::Result<()> {
    let Some(pair) = InterfacePair::create() else {
        return Ok(());
    };
    let receive_ifindex = if_index(&pair.receive).expect("receive ifindex");

    let group_v4 = Ipv4Addr::new(239, 199, 99, 9);
    let group_v6 = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x9d99);
    // IGMPv3 reports go to 224.0.0.22, MLDv2 reports to ff02::16. The receive side joins those
    // (and only those) through the production joiner, so its device accepts the arriving report
    // packets for the observers. Its own joins announce 224.0.0.22/ff02::16 -- never the test
    // groups -- so a test-group match below can only come from the inject side's announcements.
    let receive_join_ix = NonZeroU32::new(receive_ifindex).expect("receive ifindex is nonzero");
    let mut receive_joiner = MulticastJoiner::new();
    receive_joiner.join(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 22)), receive_join_ix)?;
    receive_joiner.join(
        IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16)),
        receive_join_ix,
    )?;
    let igmp = raw_observer(libc::AF_INET, libc::IPPROTO_IGMP)?;
    let mld = raw_observer(libc::AF_INET6, libc::IPPROTO_ICMPV6)?;
    #[cfg(target_os = "linux")]
    {
        subscribe(
            &igmp,
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 22)),
            receive_ifindex,
        )?;
        subscribe(
            &mld,
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x16)),
            receive_ifindex,
        )?;
    }

    let mut joiner = MulticastJoiner::new();
    let inject_ifindex = NonZeroU32::new(if_index(&pair.inject).expect("inject ifindex"))
        .expect("inject ifindex is nonzero");
    joiner.join(IpAddr::V4(group_v4), inject_ifindex)?;
    joiner.join(IpAddr::V6(group_v6), inject_ifindex)?;

    assert!(
        saw_membership_report(&igmp, &group_v4.octets()),
        "an IGMP report for {group_v4} crossed the wire"
    );
    assert!(
        saw_membership_report(&mld, &group_v6.octets()),
        "an MLD report for {group_v6} crossed the wire"
    );
    Ok(())
}

// Joins both families' groups on a real multicast-capable interface, then joins them again: the
// kernel keys memberships by (group, ifindex), so the repeats succeed through the already-member
// path. On a virtual pair multicast reaches the capture regardless of membership, so this asserts
// the joins *succeed*; the wire-level announcement is the test above.
#[test]
fn pair_joins_multicast_groups_idempotently() -> io::Result<()> {
    let Some(pair) = InterfacePair::create() else {
        return Ok(());
    };
    let mut joiner = MulticastJoiner::new();
    let inject_ifindex = NonZeroU32::new(if_index(&pair.inject).expect("inject ifindex"))
        .expect("inject ifindex is nonzero");
    let mdns_v4: IpAddr = "224.0.0.251".parse().expect("mDNS v4 group");
    let mdns_v6: IpAddr = "ff02::fb".parse().expect("mDNS v6 group");
    joiner.join(mdns_v4, inject_ifindex)?;
    joiner.join(mdns_v6, inject_ifindex)?;
    joiner.join(mdns_v4, inject_ifindex)?;
    joiner.join(mdns_v6, inject_ifindex)?;
    Ok(())
}
