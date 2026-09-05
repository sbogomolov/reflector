//! `AF_PACKET` packet capture (Linux).
//!
//! Unlike the BSD BPF backend, one `recv` returns exactly one frame, with no batch to walk.
//!
//! Init order matters: the socket opens with protocol 0, capturing nothing, so the
//! filter and the loop-prevention option install before `bind` sets the real
//! protocol and starts delivery. No window exists in which unfiltered frames
//! (e.g. IGMP from a multicast join) queue. The BSD backend instead binds first
//! and relies on `BIOCSETF` flushing the kernel buffer.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use libc::{c_int, c_void};

use super::Read;
use super::filter::{BpfInsn, DROP_OUTGOING_PROLOGUE, ETHERNET_UDP_FILTER};
use crate::interface::if_index;
use crate::logging::{WARN_WINDOW, log_rate};
use crate::net::LinkType;
use crate::sys::{IoStatus, socklen_of};

/// The fallback filter length: the egress-drop prologue plus the UDP classifier.
const DROP_OUTGOING_FILTER_LEN: usize = DROP_OUTGOING_PROLOGUE.len() + ETHERNET_UDP_FILTER.len();

/// A raw-capture handle on one interface. The socket's bind is the only holder of the
/// interface's kernel index: sends rely on it, so nothing here goes stale if the index changes.
pub(crate) struct Capture {
    fd: OwnedFd,
    buf: Box<[u8]>,
    name: String,
    /// Frames dropped for exceeding the receive buffer since the last
    /// [`take_oversized`](Self::take_oversized) drain.
    oversized: u64,
}

impl Capture {
    /// Open an `AF_PACKET` capture bound to `if_name`.
    ///
    /// # Errors
    /// Returns an error if the interface is unknown, the socket can't be created,
    /// the filter can't be attached, or the bind fails.
    pub(crate) fn open(if_name: &str) -> io::Result<Self> {
        let ifindex = resolve_ifindex(if_name)?;

        // Protocol 0: capture nothing until the filter + loop-prevention are in place.
        // SAFETY: a `socket` call with a valid domain/type/protocol returns a fresh fd or -1.
        let fd = crate::sys::owned_fd_from(unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        })?;

        // Loop prevention: stop the kernel from handing us our own injected frames. A link that
        // returns them as received frames (a hairpin bridge port) gets past this; the dispatcher's
        // echo drop catches those. PACKET_IGNORE_OUTGOING (Linux 4.20+) drops them at the socket;
        // if the kernel lacks it (or user-mode QEMU rejects it), prepend an in-filter drop instead.
        match set_ignore_outgoing(&fd) {
            Ok(()) => attach_filter(&fd, &ETHERNET_UDP_FILTER)?,
            Err(e) => {
                log::info!(
                    "PACKET_IGNORE_OUTGOING unavailable ({e}); dropping our own frames in the \
                     BPF filter"
                );
                attach_filter(&fd, &drop_outgoing_filter())?;
            }
        }

        // Bind with ETH_P_ALL to start capturing. The filter is already installed, so
        // there is no unfiltered-capture window.
        bind_interface(&fd, link_addr(ifindex))?;

        log::debug!(
            "opened AF_PACKET capture on {if_name} (fd {}, ifindex {ifindex})",
            fd.as_raw_fd()
        );
        Ok(Self {
            fd,
            buf: vec![0u8; crate::net::MAX_FRAME_LEN].into_boxed_slice(),
            name: if_name.into(),
            oversized: 0,
        })
    }

    /// Re-bind the socket to the interface currently named at open, re-hooking delivery to its
    /// (possibly recreated) kernel object. The fd, filter, and loop prevention all persist
    /// across a `bind(2)`, so the filter-before-bind init invariant holds with no unfiltered
    /// window, and the reactor's watch stays valid.
    ///
    /// # Errors
    /// [`io::ErrorKind::NotFound`] while no interface bears the name; otherwise the `bind`
    /// failure.
    pub(crate) fn rebind(&mut self) -> io::Result<()> {
        let ifindex = resolve_ifindex(&self.name)?;
        bind_interface(&self.fd, link_addr(ifindex))?;
        // The kernel parked ENETDOWN on the socket when the old interface died; consume it so
        // the first post-rebind recv surfaces frames, not the stale failure.
        match crate::sys::so_error(self.fd.as_raw_fd()) {
            Ok(0) => {}
            Ok(errno) => log::debug!(
                "cleared a pending error on the re-bound capture for {}: {}",
                self.name,
                io::Error::from_raw_os_error(errno)
            ),
            // Can't happen (SO_ERROR is a generic socket option on a live fd); if it somehow
            // does, the stale error was left unconsumed and the next read will surface it.
            Err(e) => log::warn!(
                "could not clear the pending error on the re-bound capture for {}: {e}",
                self.name
            ),
        }
        log::debug!(
            "re-bound AF_PACKET capture to {} (ifindex {ifindex})",
            self.name
        );
        Ok(())
    }

    /// Whether the socket is still hooked to the live interface with kernel index `ifindex`.
    /// `getsockname` reports the bound index, which the kernel resets to -1 when the bound
    /// interface is unregistered, so a destroyed (or destroyed-and-recreated) interface
    /// compares unequal. A `getsockname` failure counts as detached.
    pub(crate) fn attached(&self, ifindex: u32) -> bool {
        // SAFETY: an all-zero sockaddr_ll is a valid out-param; the kernel fills it up to `len`.
        let mut addr: libc::sockaddr_ll = unsafe { core::mem::zeroed() };
        let mut len = socklen_of::<libc::sockaddr_ll>();
        // SAFETY: `addr`/`len` are valid out-params for the socket's own address.
        let rc = unsafe {
            libc::getsockname(
                self.fd.as_raw_fd(),
                (&raw mut addr).cast::<libc::sockaddr>(),
                &raw mut len,
            )
        };
        rc == 0 && u32::try_from(addr.sll_ifindex).is_ok_and(|bound| bound == ifindex)
    }

    /// The link framing: always Ethernet on Linux, loopback included.
    #[allow(clippy::unused_self)] // uniform Capture API; the BPF backend reads self
    pub(crate) fn link_type(&self) -> LinkType {
        LinkType::Ethernet
    }

    pub(crate) fn if_name(&self) -> &str {
        &self.name
    }

    /// The next read: a frame, or an oversized one (larger than the receive buffer) dropped
    /// and counted; `Ok(None)` when a read would block.
    ///
    /// # Errors
    /// Returns an error if the `recv` fails for any reason other than would-block.
    pub(crate) fn next_frame(&mut self) -> io::Result<Option<Read<'_>>> {
        let Some(bytes) = self.recv_once()? else {
            return Ok(None);
        };
        // MSG_TRUNC reports the frame's real length even past the buffer, so an
        // oversized frame is detectable (and dropped) instead of silently cut.
        if bytes > self.buf.len() {
            // Rate-limited: this is the per-frame drain loop, and a remote peer can flood
            // oversized frames.
            log_rate!(
                log::Level::Warn,
                WARN_WINDOW,
                "{}: dropping oversized frame: {bytes} bytes exceeds the {}-byte receive \
                 buffer",
                self.name,
                self.buf.len()
            );
            self.oversized += 1;
            return Ok(Some(Read::Oversized));
        }
        Ok(Some(Read::Frame(&self.buf[..bytes])))
    }

    /// Whether frames are buffered locally. Never, for `AF_PACKET`: each `recv` is
    /// one frame, so a level-triggered wait re-fires while the socket has more.
    #[allow(clippy::unused_self)] // uniform Capture API; the BPF backend reads self
    pub(crate) fn has_buffered(&self) -> bool {
        false
    }

    /// The oversized-frame drops since the last call, resetting the count: the dispatcher folds
    /// them into the interface's counter row after each drain.
    pub(crate) fn take_oversized(&mut self) -> u64 {
        std::mem::take(&mut self.oversized)
    }

    /// Inject a fully-built link-layer `frame` on this interface.
    ///
    /// # Errors
    /// Returns an error if the send fails or is short.
    pub(crate) fn send(&self, frame: &[u8]) -> io::Result<()> {
        // SOCK_RAW carries the whole L2 frame and the socket is bound to its interface, so a
        // plain `send` suffices: the kernel takes the egress from the bind, and the
        // destination MAC is in the frame.
        // SAFETY: `frame` is a valid readable slice of `frame.len()` bytes.
        let sent = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                frame.as_ptr().cast::<c_void>(),
                frame.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if usize::try_from(sent).expect("send result is non-negative") != frame.len() {
            return Err(io::Error::other("short send to AF_PACKET socket"));
        }
        Ok(())
    }

    /// One `recv` into the buffer. Returns `Ok(None)` when it would block, or the frame's real
    /// length. The length may exceed the buffer, since `MSG_TRUNC` is set; the caller treats
    /// that as an oversized frame.
    fn recv_once(&mut self) -> io::Result<Option<usize>> {
        // SAFETY: `recv` writes up to `buf.len()` bytes into our own buffer.
        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                self.buf.as_mut_ptr().cast::<c_void>(),
                self.buf.len(),
                libc::MSG_TRUNC,
            )
        };
        match IoStatus::from_syscall(n)? {
            IoStatus::Ready(len) => Ok(Some(len)),
            IoStatus::WouldBlock => Ok(None),
        }
    }
}

impl AsRawFd for Capture {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// [`DROP_OUTGOING_PROLOGUE`] followed by [`ETHERNET_UDP_FILTER`]: the
/// loop-prevention fallback for kernels without `PACKET_IGNORE_OUTGOING`.
fn drop_outgoing_filter() -> [BpfInsn; DROP_OUTGOING_FILTER_LEN] {
    std::array::from_fn(|i| match DROP_OUTGOING_PROLOGUE.get(i) {
        Some(&prologue_insn) => prologue_insn,
        None => ETHERNET_UDP_FILTER[i - DROP_OUTGOING_PROLOGUE.len()],
    })
}

/// Resolve `if_name` to its kernel index as the `c_int` a `sockaddr_ll` carries, with a clear
/// error while no interface bears the name.
fn resolve_ifindex(if_name: &str) -> io::Result<c_int> {
    let ifindex = if_index(if_name).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface {if_name} not found"),
        )
    })?;
    c_int::try_from(ifindex).map_err(|_| io::Error::other("interface index too large"))
}

/// A zeroed `sockaddr_ll` addressed to `ifindex` for the bind (family set, protocol left zero;
/// [`bind_interface`] adds it).
fn link_addr(ifindex: c_int) -> libc::sockaddr_ll {
    // SAFETY: all-zero is a valid `sockaddr_ll`: integer and byte-array fields only.
    let mut addr: libc::sockaddr_ll = unsafe { core::mem::zeroed() };
    addr.sll_family = u16::try_from(libc::AF_PACKET).expect("AF_PACKET fits u16");
    addr.sll_ifindex = ifindex;
    addr
}

/// Ask the kernel to drop locally-sent frames on this socket (`PACKET_IGNORE_OUTGOING`).
fn set_ignore_outgoing(fd: &OwnedFd) -> io::Result<()> {
    let on: c_int = 1;
    // SAFETY: a `setsockopt` with a `c_int` option value and its matching length.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_PACKET,
            libc::PACKET_IGNORE_OUTGOING,
            (&raw const on).cast::<c_void>(),
            socklen_of::<c_int>(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Attach a classic-BPF `filter` to the socket via `SO_ATTACH_FILTER`.
fn attach_filter(fd: &OwnedFd, filter: &[BpfInsn]) -> io::Result<()> {
    let program = libc::sock_fprog {
        len: u16::try_from(filter.len()).expect("filter length fits u16"),
        // The kernel only reads the program, so the const-to-mut cast is sound.
        filter: filter.as_ptr().cast_mut(),
    };
    // SAFETY: a `setsockopt` with a `sock_fprog` pointing at `filter`, valid for the
    // duration of the call.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&raw const program).cast::<c_void>(),
            socklen_of::<libc::sock_fprog>(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Bind to the interface in `addr`, adding the capture protocol `ETH_P_ALL`.
fn bind_interface(fd: &OwnedFd, mut addr: libc::sockaddr_ll) -> io::Result<()> {
    addr.sll_protocol = u16::try_from(libc::ETH_P_ALL)
        .expect("ETH_P_ALL fits u16")
        .to_be();
    // SAFETY: `addr` is a fully-initialized `sockaddr_ll` of the given length.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&raw const addr).cast::<libc::sockaddr>(),
            socklen_of::<libc::sockaddr_ll>(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

    use super::*;
    use crate::capture::{loopback_lock, open_or_skip};
    use crate::net::frame;
    use crate::net::mac::MacAddr;

    /// `BpfInsn` is libc's type, which derives no `PartialEq`/`Debug`; compare as field tuples.
    fn as_tuples(insns: &[BpfInsn]) -> Vec<(u16, u8, u8, u32)> {
        insns.iter().map(|i| (i.code, i.jt, i.jf, i.k)).collect()
    }

    #[test]
    fn drop_outgoing_filter_prepends_the_prologue() {
        let filter = drop_outgoing_filter();
        assert_eq!(
            as_tuples(&filter[..DROP_OUTGOING_PROLOGUE.len()]),
            as_tuples(&DROP_OUTGOING_PROLOGUE)
        );
        assert_eq!(
            as_tuples(&filter[DROP_OUTGOING_PROLOGUE.len()..]),
            as_tuples(&ETHERNET_UDP_FILTER)
        );
    }

    // Live capture against the real kernel: send UDP to 127.0.0.1 and capture the
    // looped frame off `lo`. Validates the open/filter/bind/recv path and that lo
    // is Ethernet-framed. PACKET_IGNORE_OUTGOING drops the TX copy; we see the RX one.
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn captures_a_known_frame_on_lo() -> io::Result<()> {
        const PROBE: &[u8] = b"netflector-afpacket-capture-probe";
        let _serial = loopback_lock();
        let Some(mut capture) = open_or_skip("lo", "afpacket_capture")? else {
            return Ok(());
        };
        assert_eq!(capture.link_type(), LinkType::Ethernet);

        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();

        // An lo frame is [14-byte Ethernet][IPv4][UDP][payload]; finding our payload
        // at the tail behind an IPv4/IPv6 ethertype proves the layout decoded. The
        // capture is armed before the send, and the looped frame waits in the socket
        // buffer until drained, so one send then polling captures it.
        sender.send_to(PROBE, target).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut decoded = false;
        while !decoded && std::time::Instant::now() < deadline {
            while let Some(read) = capture.next_frame()? {
                let Read::Frame(frame) = read else {
                    continue;
                };
                if frame.len() >= 14 && frame.ends_with(PROBE) {
                    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
                    assert!(ethertype == 0x0800 || ethertype == 0x86dd);
                    decoded = true;
                    break;
                }
            }
            if !decoded {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        assert!(decoded, "did not capture our UDP probe on lo");
        Ok(())
    }

    // A frame past the receive buffer is dropped, but it still costs a read, so the drain
    // budget counts it: one oversized datagram on lo yields one `Read::Oversized`.
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn an_oversized_frame_costs_a_read() -> io::Result<()> {
        let _serial = loopback_lock();
        let Some(mut capture) = open_or_skip("lo", "afpacket_oversized")? else {
            return Ok(());
        };
        let receiver = UdpSocket::bind("127.0.0.1:0")?;
        let sender = UdpSocket::bind("127.0.0.1:0")?;
        // lo's MTU carries it whole, so it arrives as one frame past MAX_FRAME_LEN.
        sender.send_to(
            &[0u8; 2 * crate::net::MAX_FRAME_LEN],
            receiver.local_addr()?,
        )?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match capture.next_frame()? {
                Some(Read::Oversized) => break,
                Some(Read::Frame(_)) => {} // unrelated loopback traffic
                None if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                None => panic!("did not capture the oversized datagram on lo"),
            }
        }
        assert!(capture.take_oversized() >= 1);
        Ok(())
    }

    // Live send: inject a built Ethernet frame on `lo` via send(), then capture it
    // back. lo loops every transmitted frame to its input tap, and we keep the RX
    // copy (PACKET_IGNORE_OUTGOING drops only the TX copy), so this validates that
    // send() actually puts the frame on the wire. (Whether the local IP stack then
    // delivers a raw-injected loopback frame to a socket is kernel-specific, and not
    // what send() is for: on a real interface it reaches other hosts, not us.)
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn send_loops_back_on_lo() -> io::Result<()> {
        const PROBE: &[u8] = b"netflector-afpacket-send-probe";
        let _serial = loopback_lock();
        let Some(mut capture) = open_or_skip("lo", "afpacket_send")? else {
            return Ok(());
        };

        let src = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40000);
        let dst = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40001);
        let mac = MacAddr::broadcast();
        let mut buf = [0u8; 256];
        let n = frame::ethernet_ipv4_udp(mac, mac, src, dst, 64, PROBE, &mut buf)
            .expect("build Ethernet frame");

        // The injected frame loops to the input tap and waits there until drained, so
        // one send then polling captures it.
        capture.send(&buf[..n]).expect("send on lo");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut looped = false;
        while !looped && std::time::Instant::now() < deadline {
            while let Some(read) = capture.next_frame()? {
                let Read::Frame(frame) = read else {
                    continue;
                };
                if frame.ends_with(PROBE) {
                    looped = true;
                    break;
                }
            }
            if !looped {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        assert!(
            looped,
            "did not capture our injected frame looped back on lo"
        );
        Ok(())
    }
}
