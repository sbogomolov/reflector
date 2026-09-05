//! Raw L2 packet capture: a per-interface handle the reactor can poll.
//!
//! One backend per platform behind a uniform `Capture`: BPF on macOS/FreeBSD,
//! `AF_PACKET` on Linux. The handle owns a pollable fd, reads link-layer frames
//! into a reused buffer (no per-frame allocation), and injects built frames.

mod filter;

#[cfg(target_os = "linux")]
mod af_packet;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bpf;

/// The platform `Capture` under one name, so consumers and tests need not name the backend.
#[cfg(target_os = "linux")]
pub(crate) use self::af_packet::Capture;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) use self::bpf::Capture;

/// One read of a capture.
#[derive(Debug)]
pub(crate) enum Read<'a> {
    Frame(&'a [u8]),
    /// A frame too large to forward, dropped and counted.
    Oversized,
}

/// Open a capture on `if_name`, returning `Ok(None)` (and noting why) when the host
/// can't: no BPF access / `CAP_NET_RAW`, or the interface is absent. Other errors
/// propagate for the caller to `?`.
#[cfg(test)]
pub(crate) fn open_or_skip(if_name: &str, what: &str) -> std::io::Result<Option<Capture>> {
    match Capture::open(if_name) {
        Ok(capture) => Ok(Some(capture)),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
            ) || e.raw_os_error() == Some(libc::EACCES)
                || e.raw_os_error() == Some(libc::EPERM) =>
        {
            eprintln!("skip {what}: cannot capture on {if_name} ({e})");
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// The tests that open a capture on the loopback interface hold this for their duration: every
/// descriptor attached there sees every frame, and the kernel's small double buffer drops what
/// a concurrent test's traffic leaves no room for.
#[cfg(test)]
pub(crate) fn loopback_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::{Read, open_or_skip};
    use crate::net::LinkType;

    // Live capture against a real interface (`NETFLECTOR_TEST_IFACE`). Backend-neutral
    // because a real interface is Ethernet-framed on both backends: BPF reports
    // DLT_EN10MB, AF_PACKET delivers the Ethernet header.
    #[test]
    fn live_capture_decodes_real_frames() -> std::io::Result<()> {
        let Some(iface) = std::env::var_os("NETFLECTOR_TEST_IFACE") else {
            eprintln!("skip live_capture: set NETFLECTOR_TEST_IFACE to an Ethernet interface");
            return Ok(());
        };
        let iface = iface.to_string_lossy();
        let Some(mut capture) = open_or_skip(&iface, "live_capture")? else {
            return Ok(());
        };
        assert_eq!(capture.link_type(), LinkType::Ethernet);

        // Every frame the kernel filter passed must be an IPv4/IPv6 Ethernet frame, so a
        // mis-sliced header would corrupt these.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut validated = 0u32;
        while validated < 8 && std::time::Instant::now() < deadline {
            match capture.next_frame()? {
                Some(Read::Oversized) => {}
                Some(Read::Frame(frame)) => {
                    assert!(frame.len() >= 14, "frame shorter than an Ethernet header");
                    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
                    assert!(
                        ethertype == 0x0800 || ethertype == 0x86dd,
                        "filter passed a non-IP ethertype {ethertype:#06x}",
                    );
                    validated += 1;
                }
                None => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
        eprintln!("live_capture: validated {validated} frame(s) on {iface}");
        Ok(())
    }
}
