//! BPF packet capture (macOS and FreeBSD).
//!
//! Opens `/dev/bpfN`, binds it to an interface, installs a UDP-only classic-BPF
//! filter, and reads link-layer frames. One `read` returns a *batch* of frames,
//! each prefixed by a variable-length `bpf_hdr` and padded so the next record
//! starts on a `BPF_ALIGNMENT` boundary; [`Capture::next_frame`] walks that batch.
//!
//! Init order matters: bind (`BIOCSETIF`) happens before the filter (`BIOCSETF`).
//! That's safe only because `BIOCSETF` flushes the kernel buffer, so the brief
//! pre-filter window leaves nothing behind. (Linux's `SO_ATTACH_FILTER` does not
//! flush, so its backend filters before bind instead.)

use std::io;
use std::ops::Range;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use libc::{c_uint, c_ulong, c_void};

use super::Read;
use super::filter::{BpfInsn, DLT_NULL_UDP_FILTER, ETHERNET_UDP_FILTER};
use crate::libcex::bpf_wordalign;
use crate::logging::{WARN_WINDOW, log_rate};
use crate::net::LinkType;
use crate::sys::IoStatus;

/// A raw-capture handle on one interface.
pub(crate) struct Capture {
    fd: OwnedFd,
    buf: Box<[u8]>,
    filled: usize,
    offset: usize,
    link_type: LinkType,
    name: String,
    /// Frames dropped for exceeding the forwarding limit since the last
    /// [`take_oversized`](Self::take_oversized) drain.
    oversized: u64,
}

impl Capture {
    /// Open a BPF capture bound to `if_name`.
    ///
    /// # Errors
    /// Returns an error if no BPF device is available, the interface can't be
    /// bound, the link type is neither Ethernet nor `DLT_NULL`, or any
    /// setup ioctl fails.
    pub(crate) fn open(if_name: &str) -> io::Result<Self> {
        let fd = open_bpf_device()?;

        // Bind to the interface. Capture starts here; the filter installed by `attach`
        // flushes the buffer, so nothing slips through unfiltered.
        let link_type = attach(&fd, if_name)?;

        // Deliver each frame as it arrives instead of blocking until the buffer fills.
        let mut immediate: c_uint = 1;
        ioctl(&fd, libc::BIOCIMMEDIATE, (&raw mut immediate).cast())?;

        // Size the read buffer to the kernel's preferred BPF buffer length.
        let mut blen: c_uint = 0;
        ioctl(&fd, libc::BIOCGBLEN, (&raw mut blen).cast())?;

        crate::sys::set_nonblock(fd.as_raw_fd())?;

        log::debug!(
            "opened BPF capture on {if_name} (fd {}, {link_type:?}, {blen}-byte buffer)",
            fd.as_raw_fd()
        );
        Ok(Self {
            fd,
            buf: vec![0u8; blen as usize].into_boxed_slice(),
            filled: 0,
            offset: 0,
            link_type,
            name: if_name.into(),
            oversized: 0,
        })
    }

    /// Re-attach the descriptor to the interface currently named at open. The kernel detaches
    /// it when its interface is destroyed and never re-attaches it on its own, so this is the
    /// recovery path after a recreation: `BIOCSETIF` from the detached state is the same path
    /// as the initial attach, and it resets the kernel buffer. The fd is unchanged, so the
    /// reactor's watch stays valid; the framing (and with it the filter and see-sent policy)
    /// is re-derived in case the interface came back different.
    ///
    /// # Errors
    /// The attach ioctl failure while no interface bears the name, or an unsupported link type.
    pub(crate) fn rebind(&mut self) -> io::Result<()> {
        self.link_type = attach(&self.fd, &self.name)?;
        // The kernel reset its buffer at the re-attach; drop the drained-batch state to
        // match, discarding any stale frames from the old interface.
        self.filled = 0;
        self.offset = 0;
        log::debug!(
            "re-bound BPF capture to {} ({:?})",
            self.name,
            self.link_type
        );
        Ok(())
    }

    /// Whether the descriptor is still attached to a live interface. The kernel clears the
    /// attachment when the interface is destroyed, after which per-attachment ioctls fail --
    /// and a recreated interface (same name, even a reused index) never re-attaches the old
    /// descriptor, so this probe catches recreation where index comparison can't. `ifindex`
    /// is unused: BPF attachment is to the kernel object itself; the parameter keeps the
    /// signature uniform with the `AF_PACKET` backend, which compares bound indexes.
    pub(crate) fn attached(&self, _ifindex: u32) -> bool {
        let mut dlt: c_uint = 0;
        ioctl(&self.fd, libc::BIOCGDLT, (&raw mut dlt).cast()).is_ok()
    }

    /// The link-layer framing of the captured frames, so a consumer can strip the
    /// right link header (Ethernet vs `DLT_NULL`) before parsing L3.
    pub(crate) fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// The interface this capture is bound to.
    pub(crate) fn if_name(&self) -> &str {
        &self.name
    }

    /// The next read, refilling from the kernel when the current batch is drained: a frame,
    /// or a truncated/oversized record dropped and counted. Returns `Ok(None)` when nothing
    /// more is ready (the batch is empty and a read would block).
    ///
    /// # Errors
    /// Returns an error if the read fails, or the kernel batch is malformed (the
    /// rest of that batch is then abandoned).
    pub(crate) fn next_frame(&mut self) -> io::Result<Option<Read<'_>>> {
        if self.offset >= self.filled && !self.refill()? {
            return Ok(None);
        }
        let start = self.offset;
        let (record, advance) = match parse_record(&self.buf[start..self.filled]) {
            Ok(parsed) => parsed,
            Err(e) => {
                self.offset = self.filled; // abandon the malformed batch
                return Err(e);
            }
        };
        self.offset = start + advance;
        match record {
            Record::Frame(frame) => Ok(Some(Read::Frame(
                &self.buf[start + frame.start..start + frame.end],
            ))),
            // Rate-limited: this is the per-frame drain loop, and a remote peer can flood
            // oversized frames.
            Record::Oversized { datalen } => {
                log_rate!(
                    log::Level::Warn,
                    WARN_WINDOW,
                    "{}: dropping oversized frame: {datalen} bytes exceeds the {}-byte \
                     forwarding limit",
                    self.name,
                    crate::net::MAX_FRAME_LEN
                );
                self.oversized += 1;
                Ok(Some(Read::Oversized))
            }
        }
    }

    /// Whether the current batch still holds unread records: the cue to keep
    /// draining, since a level-triggered wait won't re-fire until new kernel data.
    pub(crate) fn has_buffered(&self) -> bool {
        self.offset < self.filled
    }

    /// The oversized-frame drops since the last call, resetting the count: the dispatcher folds
    /// them into the interface's counter row after each drain.
    pub(crate) fn take_oversized(&mut self) -> u64 {
        std::mem::take(&mut self.oversized)
    }

    /// Inject a fully-built link-layer `frame` on this interface.
    ///
    /// # Errors
    /// Returns an error if the write fails or is short.
    pub(crate) fn send(&self, frame: &[u8]) -> io::Result<()> {
        // SAFETY: `frame` is a valid readable slice; the BPF fd accepts full frames.
        let written =
            unsafe { libc::write(self.fd.as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        if usize::try_from(written).expect("write result is non-negative") != frame.len() {
            return Err(io::Error::other("short write to BPF device"));
        }
        Ok(())
    }

    /// Read one kernel batch into `buf`. Returns `false` if nothing is available
    /// (would block) or the device reported EOF.
    fn refill(&mut self) -> io::Result<bool> {
        // SAFETY: writing up to `buf.len()` bytes into our own buffer.
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                self.buf.as_mut_ptr().cast(),
                self.buf.len(),
            )
        };
        let bytes = match IoStatus::from_syscall(n)? {
            IoStatus::Ready(len) => len,
            IoStatus::WouldBlock => return Ok(false),
        };
        if bytes == 0 {
            return Ok(false);
        }
        self.filled = bytes;
        self.offset = 0;
        Ok(true)
    }
}

impl AsRawFd for Capture {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Outcome of parsing one BPF record: a good frame's byte range, or an oversized
/// capture to drop (carrying its original length, for the trace log).
enum Record {
    Frame(Range<usize>),
    Oversized { datalen: u32 },
}

/// Parse the BPF record at the front of `record` (the still-unread slice of the
/// current batch), returning it plus how many bytes to advance past it (its
/// `libc::bpf_hdr` + frame, padded to `BPF_ALIGNMENT`). The frame range is
/// relative to `record`. Pure (no I/O) so the batch walk, the fiddliest part,
/// is unit-testable against synthetic buffers.
fn parse_record(record: &[u8]) -> io::Result<(Record, usize)> {
    if size_of::<libc::bpf_hdr>() > record.len() {
        return Err(io::Error::other("BPF batch ended mid-header"));
    }
    // SAFETY: the bound above keeps the header within `record`; `libc::bpf_hdr`
    // is plain repr(C) data and `read_unaligned` tolerates any record alignment.
    let header = unsafe { record.as_ptr().cast::<libc::bpf_hdr>().read_unaligned() };

    let frame_start = header.bh_hdrlen as usize;
    let frame_end = frame_start + header.bh_caplen as usize;
    if frame_end > record.len() {
        return Err(io::Error::other("BPF frame extends past batch end"));
    }
    let advance = bpf_wordalign(frame_end);
    if advance == 0 {
        // A record that doesn't advance would stall the drain loop forever. The
        // kernel never emits one (bh_hdrlen is always >= the header size), so
        // treat it as a malformed batch.
        return Err(io::Error::other("BPF record did not advance"));
    }

    // Truncated by the kernel, or whole but past what we can re-emit. BPF sizes its buffer from
    // BIOCGBLEN, not from MAX_FRAME_LEN, so it can hand up frames the send path would go on to
    // reject once per packet.
    if header.bh_datalen > header.bh_caplen || header.bh_caplen as usize > crate::net::MAX_FRAME_LEN
    {
        return Ok((
            Record::Oversized {
                datalen: header.bh_datalen,
            },
            advance,
        ));
    }
    Ok((Record::Frame(frame_start..frame_end), advance))
}

/// Attach `fd` to `if_name` and normalize the per-attachment state: read the link framing,
/// set the see-sent policy for it, and install the matching UDP filter (`BIOCSETF` also
/// flushes anything captured since the bind, so nothing slips through unfiltered). Shared by
/// [`Capture::open`] and [`Capture::rebind`]; per-descriptor settings (immediate mode, buffer
/// size) stay in `open`, since they survive re-attachment.
fn attach(fd: &OwnedFd, if_name: &str) -> io::Result<LinkType> {
    // SAFETY: all-zero is a valid `ifreq`: `ifr_name` is a byte array and the `ifr_ifru`
    // union holds only integers/pointers/sockaddr, none with an invalid zero bit pattern.
    let mut ifr: libc::ifreq = unsafe { core::mem::zeroed() };
    let name = if_name.as_bytes();
    if name.len() >= ifr.ifr_name.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    // SAFETY: `ifr_name` is a `[c_char; IFNAMSIZ]`; we checked `name` fits with
    // room for the zero terminator the zeroed `ifr` already provides.
    unsafe {
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            ifr.ifr_name.as_mut_ptr().cast::<u8>(),
            name.len(),
        );
    }
    ioctl(fd, libc::BIOCSETIF, (&raw mut ifr).cast())?;

    // The link framing selects the filter and the see-sent handling below.
    let mut dlt: c_uint = 0;
    ioctl(fd, libc::BIOCGDLT, (&raw mut dlt).cast())?;
    let link_type = match dlt {
        libc::DLT_EN10MB => LinkType::Ethernet,
        libc::DLT_NULL => LinkType::DltNull,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported BPF link type {other} (need DLT_EN10MB or DLT_NULL)"),
            ));
        }
    };

    // Loop prevention on Ethernet: don't hand us our own egress. A link that returns it
    // as received frames gets past this; the dispatcher's echo drop catches those. On
    // DLT_NULL links see-sent stays on: the BSD lo driver taps each frame once (and tags
    // it outbound), so default BPF already delivers it; receive-only would instead silence
    // the interface entirely. Set explicitly both ways so a rebind onto different framing
    // restores the right mode.
    let mut see_sent: c_uint = c_uint::from(link_type == LinkType::DltNull);
    ioctl(fd, libc::BIOCSSEESENT, (&raw mut see_sent).cast())?;

    // Install the link-appropriate UDP filter (and flush whatever queued before it).
    let filter: &[BpfInsn] = match link_type {
        LinkType::Ethernet => &ETHERNET_UDP_FILTER,
        LinkType::DltNull => &DLT_NULL_UDP_FILTER,
    };
    let mut program = libc::bpf_program {
        bf_len: c_uint::try_from(filter.len()).expect("filter length fits c_uint"),
        bf_insns: filter.as_ptr().cast_mut(),
    };
    ioctl(fd, libc::BIOCSETF, (&raw mut program).cast())?;
    Ok(link_type)
}

/// Open the first available `/dev/bpfN`.
fn open_bpf_device() -> io::Result<OwnedFd> {
    for n in 0..256 {
        let path = format!("/dev/bpf{n}\0");
        // SAFETY: `path` is NUL-terminated.
        let raw = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDWR | libc::O_CLOEXEC) };
        if raw >= 0 {
            // SAFETY: `open` returned a fresh owned fd.
            return Ok(unsafe { OwnedFd::from_raw_fd(raw) });
        }
        // EBUSY just means this device is taken; try the next. Anything else is real.
        if io::Error::last_os_error().raw_os_error() != Some(libc::EBUSY) {
            return Err(io::Error::last_os_error());
        }
    }
    Err(io::Error::other("all /dev/bpf devices are busy"))
}

/// One `ioctl` with a typed-but-opaque argument pointer, mapping failure to an error.
fn ioctl(fd: &OwnedFd, request: c_ulong, arg: *mut c_void) -> io::Result<()> {
    // SAFETY: `request` matches `arg`'s type per the BIOC* definitions; `fd` is valid.
    if unsafe { libc::ioctl(fd.as_raw_fd(), request, arg) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::mem::offset_of;

    use super::*;
    use crate::capture::{loopback_lock, open_or_skip};
    use crate::libcex::BPF_ALIGN;

    /// Append one synthetic BPF record (header + frame + word-align padding) to
    /// `batch`. Serializes the header field-by-field at its repr(C) offsets rather
    /// than transmuting a `libc::bpf_hdr` (whose tail padding would be uninitialized).
    fn push_record(batch: &mut Vec<u8>, caplen: u32, datalen: u32, fill: u8) {
        let hdrlen = u16::try_from(size_of::<libc::bpf_hdr>()).expect("header fits u16");
        let mut header = [0u8; size_of::<libc::bpf_hdr>()];
        header[offset_of!(libc::bpf_hdr, bh_caplen)..][..4].copy_from_slice(&caplen.to_ne_bytes());
        header[offset_of!(libc::bpf_hdr, bh_datalen)..][..4]
            .copy_from_slice(&datalen.to_ne_bytes());
        header[offset_of!(libc::bpf_hdr, bh_hdrlen)..][..2].copy_from_slice(&hdrlen.to_ne_bytes());
        batch.extend_from_slice(&header);
        batch.extend(std::iter::repeat_n(fill, caplen as usize));
        while !batch.len().is_multiple_of(BPF_ALIGN) {
            batch.push(0);
        }
    }

    #[test]
    fn walks_a_multi_frame_batch() {
        let mut batch = Vec::new();
        push_record(&mut batch, 3, 3, 0xaa);
        push_record(&mut batch, 5, 5, 0xbb);
        push_record(&mut batch, 1, 1, 0xcc);

        let mut offset = 0;
        let mut frames: Vec<Vec<u8>> = Vec::new();
        while offset < batch.len() {
            let (record, advance) = parse_record(&batch[offset..]).unwrap();
            if let Record::Frame(frame) = record {
                frames.push(batch[offset + frame.start..offset + frame.end].to_vec());
            }
            offset += advance;
        }
        assert_eq!(frames, vec![vec![0xaa; 3], vec![0xbb; 5], vec![0xcc; 1]]);
    }

    #[test]
    fn skips_a_frame_past_the_forwarding_limit() {
        // Whole, not truncated: this one would otherwise route and then fail in build_udp.
        let over = u32::try_from(crate::net::MAX_FRAME_LEN + 1).expect("fits u32");
        let mut batch = Vec::new();
        push_record(&mut batch, over, over, 0xaa);
        push_record(&mut batch, 2, 2, 0xbb);

        let (first, advance) = parse_record(&batch).unwrap();
        assert!(matches!(first, Record::Oversized { datalen } if datalen == over));
        let (second, _) = parse_record(&batch[advance..]).unwrap();
        assert!(
            matches!(second, Record::Frame(_)),
            "the next record still parses"
        );
    }

    #[test]
    fn keeps_a_frame_at_the_forwarding_limit() {
        let at = u32::try_from(crate::net::MAX_FRAME_LEN).expect("fits u32");
        let mut batch = Vec::new();
        push_record(&mut batch, at, at, 0xaa);
        assert!(matches!(parse_record(&batch).unwrap().0, Record::Frame(_)));
    }

    #[test]
    fn skips_a_truncated_record() {
        let mut batch = Vec::new();
        push_record(&mut batch, 4, 9, 0xaa); // captured 4 of a 9-byte frame -> skip
        push_record(&mut batch, 2, 2, 0xbb); // good frame after it

        let (first, advance) = parse_record(&batch).unwrap();
        assert!(matches!(first, Record::Oversized { .. }));
        let (second, _) = parse_record(&batch[advance..]).unwrap();
        match second {
            Record::Frame(frame) => {
                assert_eq!(
                    &batch[advance + frame.start..advance + frame.end],
                    &[0xbb, 0xbb]
                );
            }
            Record::Oversized { .. } => panic!("second record should be a frame"),
        }
    }

    #[test]
    fn rejects_a_header_past_the_batch_end() {
        let batch = vec![0u8; size_of::<libc::bpf_hdr>() - 1];
        assert!(parse_record(&batch).is_err());
    }

    #[test]
    fn rejects_a_non_advancing_record() {
        // bh_hdrlen == 0 && bh_caplen == 0 would leave the cursor in place and spin
        // the drain loop; parse_record must reject it instead.
        let mut batch = [0u8; size_of::<libc::bpf_hdr>()];
        batch[offset_of!(libc::bpf_hdr, bh_datalen)..][..4].copy_from_slice(&1u32.to_ne_bytes());
        assert!(parse_record(&batch).is_err());
    }

    #[test]
    fn rejects_a_frame_extending_past_the_batch() {
        // A header whose bh_caplen claims more frame bytes than the batch holds.
        let hdrlen = u16::try_from(size_of::<libc::bpf_hdr>()).unwrap();
        let mut batch = vec![0u8; size_of::<libc::bpf_hdr>() + 2];
        batch[offset_of!(libc::bpf_hdr, bh_hdrlen)..][..2].copy_from_slice(&hdrlen.to_ne_bytes());
        batch[offset_of!(libc::bpf_hdr, bh_caplen)..][..4].copy_from_slice(&100u32.to_ne_bytes());
        batch[offset_of!(libc::bpf_hdr, bh_datalen)..][..4].copy_from_slice(&100u32.to_ne_bytes());
        assert!(parse_record(&batch).is_err());
    }

    /// Send a UDP probe to `bind` (a v4 or v6 loopback address) and confirm the BPF
    /// backend captures it as a `DLT_NULL` frame: a 4-byte host-order `family`, then
    /// an IP header whose version nibble is `version` (so the link header is exactly
    /// 4 bytes), then our payload at the tail. Returns false if nothing matching
    /// arrives within a short window.
    fn captures_loopback_probe(
        capture: &mut Capture,
        bind: &str,
        family: u32,
        version: u8,
    ) -> bool {
        const PROBE: &[u8] = b"netflector-loopback-probe";
        let receiver = std::net::UdpSocket::bind(bind).unwrap();
        let target = receiver.local_addr().unwrap();
        let sender = std::net::UdpSocket::bind(bind).unwrap();

        // The capture is armed before the send and BIOCIMMEDIATE delivers the looped
        // frame at once, where it waits until read, so one send then polling captures it.
        sender.send_to(PROBE, target).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            while let Some(read) = capture.next_frame().unwrap() {
                let Read::Frame(frame) = read else {
                    continue;
                };
                if frame.len() > 4
                    && u32::from_ne_bytes(frame[..4].try_into().unwrap()) == family
                    && frame[4] >> 4 == version
                    && frame.ends_with(PROBE)
                {
                    return true;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        false
    }

    // A record past the forwarding limit is dropped, but it still costs a read, so the drain
    // budget counts it: one oversized datagram on lo0 yields one `Read::Oversized`.
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn an_oversized_record_costs_a_read() -> io::Result<()> {
        let _serial = loopback_lock();
        let Some(mut capture) = open_or_skip("lo0", "bpf_oversized")? else {
            return Ok(());
        };
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let sender = std::net::UdpSocket::bind("127.0.0.1:0")?;
        // lo0's MTU carries it whole, so it arrives as one record past MAX_FRAME_LEN.
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
                None => panic!("did not capture the oversized datagram on lo0"),
            }
        }
        assert!(capture.take_oversized() >= 1);
        Ok(())
    }

    // Live loopback capture: `lo0` reports DLT_NULL, so this exercises `link_type()`,
    // both branches of the DLT_NULL filter (the per-OS AF_INET/AF_INET6 constants and
    // their host-order byte-swap, at different header offsets), and the see-sent skip.
    // Traffic to 127.0.0.1 / ::1 is deterministic, no env var needed. Dynamically
    // skips when BPF (or IPv6 loopback) is unavailable; fails on real errors.
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn loopback_capture_decodes_known_frames() -> io::Result<()> {
        let _serial = loopback_lock();
        let Some(mut capture) = open_or_skip("lo0", "loopback_capture")? else {
            return Ok(());
        };
        assert_eq!(capture.link_type(), LinkType::DltNull);

        assert!(
            captures_loopback_probe(
                &mut capture,
                "127.0.0.1:0",
                libc::AF_INET.cast_unsigned(),
                4
            ),
            "did not capture a DLT_NULL IPv4 UDP probe on lo0",
        );

        // IPv6 loopback isn't guaranteed everywhere; cover the AF_INET6 branch only
        // where ::1 is usable.
        if std::net::UdpSocket::bind("[::1]:0").is_ok() {
            assert!(
                captures_loopback_probe(&mut capture, "[::1]:0", libc::AF_INET6.cast_unsigned(), 6),
                "did not capture a DLT_NULL IPv6 UDP probe on lo0",
            );
        } else {
            eprintln!("skip loopback IPv6: ::1 unavailable");
        }
        Ok(())
    }

    // Probe whether FreeBSD loops a BPF-injected frame back into the local stack.
    // macOS does not (verified: send() is accepted but the frame is never delivered
    // to a capture or a socket), but FreeBSD's loopback path is a separate
    // implementation, so this builds valid DLT_NULL IPv4 and IPv6 UDP datagrams,
    // injects each on lo0, and asserts a bound UDP socket receives it. FreeBSD-only;
    // skips without BPF access (and IPv6 when ::1 is unavailable). A failure here
    // means FreeBSD behaves like macOS: loopback send isn't observable this way.
    #[cfg(target_os = "freebsd")]
    #[test]
    #[cfg_attr(miri, ignore = "needs a real capture device")]
    fn loopback_send_reaches_a_local_socket() -> io::Result<()> {
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, UdpSocket};

        const PROBE: &[u8] = b"netflector-loopback-send-probe";

        let _serial = loopback_lock();
        let Some(cap) = open_or_skip("lo0", "loopback_send")? else {
            return Ok(());
        };

        // IPv4 is always available on lo0.
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dst_port = receiver.local_addr().unwrap().port();
        let src = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40000);
        let dst = SocketAddrV4::new(Ipv4Addr::LOCALHOST, dst_port);
        let mut frame = [0u8; 256];
        let n = crate::net::frame::dlt_null_ipv4_udp(src, dst, 64, PROBE, &mut frame)
            .expect("build DLT_NULL IPv4 frame");
        expect_send_delivered(&cap, &receiver, &frame[..n], PROBE);

        // IPv6 loopback isn't guaranteed everywhere; cover it only when ::1 is usable.
        if let Ok(receiver) = UdpSocket::bind("[::1]:0") {
            let dst_port = receiver.local_addr().unwrap().port();
            let src = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 40000, 0, 0);
            let dst = SocketAddrV6::new(Ipv6Addr::LOCALHOST, dst_port, 0, 0);
            let mut frame = [0u8; 256];
            let n = crate::net::frame::dlt_null_ipv6_udp(src, dst, 64, PROBE, &mut frame)
                .expect("build DLT_NULL IPv6 frame");
            expect_send_delivered(&cap, &receiver, &frame[..n], PROBE);
        } else {
            eprintln!("skip loopback_send IPv6: ::1 unavailable");
        }
        Ok(())
    }

    /// Inject `frame` on `cap`'s interface and assert the bound `receiver` gets
    /// `probe` within a short window. Shared by both the IPv4 and IPv6 probes.
    #[cfg(target_os = "freebsd")]
    fn expect_send_delivered(
        cap: &Capture,
        receiver: &std::net::UdpSocket,
        frame: &[u8],
        probe: &[u8],
    ) {
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        cap.send(frame).expect("send on lo0");

        let mut buf = [0u8; 256];
        match receiver.recv_from(&mut buf) {
            Ok((n, _)) => assert_eq!(&buf[..n], probe),
            Err(e) => panic!(
                "lo0 did not deliver the injected frame to {}: {e}",
                receiver.local_addr().unwrap()
            ),
        }
    }
}
