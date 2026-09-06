//! Single-threaded reactor: a registration arena dispatched against I/O readiness.
//!
//! Registrations are addressed by a `Copy` [`Key`] into a generational-index
//! [`arena`], not a pointer. A handler can thus reach back into the reactor
//! (register/unregister others, arm write interest) without aliasing the storage
//! it lives in. A freed slot bumps its generation, so a stale key fails safe
//! (resolves to nothing) instead of dangling.
//!
//! A [`Handler`] is registered once and **owns** the fds it [`watch`](Reactor::watch)es;
//! each fd is watched under its own [`RegKey`], so an event names the exact fd and
//! dispatches the owning handler. Unwatching (or unregistering) removes the kernel
//! interest *first*, then the handler drops and closes the fds. Interest is always
//! gone before a fd closes: no stale-interest window, and no fd the reactor
//! double-owns (a capture socket the handler also needs for I/O stays the handler's).
//!
//! Dispatch **takes the handler out of its slot** for its call, so `&mut Reactor` is
//! free to hand to it. It can watch/unwatch fds and register/unregister others, which
//! a loop holding an iterator into the storage would risk invalidating mid-iteration.
//! Nothing borrows the arenas during the call.

mod arena;
mod poll;
mod signal;

pub(crate) use self::arena::{Arena, Key};

use std::io;
use std::num::NonZeroUsize;
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

use self::poll::Poller;

/// How many ready fds one [`wait`](poll::Poller::wait) reports. netflector watches
/// only a handful of fds; level-triggering re-reports any overflow on the next wait,
/// so a small buffer never loses events.
const EVENT_CAPACITY: NonZeroUsize = NonZeroUsize::new(64).unwrap();

/// A `Copy` handle to a registered handler: what [`register`](Reactor::register)
/// returns and [`unregister`](Reactor::unregister) takes. A newtype over the arena
/// [`Key`] so it can't be confused with a [`RegKey`] (a different arena).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct HandlerKey(Key);

/// A `Copy` handle to one watched fd of a handler: what [`watch`](Reactor::watch)
/// returns. It names a single fd, so it is the handle for [`set_write_interest`] and
/// [`unwatch`], and is handed back to dispatch so a handler learns *which* of its fds fired.
///
/// [`set_write_interest`]: Reactor::set_write_interest
/// [`unwatch`]: Reactor::unwatch
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct RegKey(Key);

/// Callbacks for a registered handler. The handler **owns** the fds it watches and keeps
/// them open while watched; the reactor only watches them. Each fd is watched under its
/// own [`RegKey`], so readiness on any one dispatches the handler with the `fd` that fired.
///
/// `on_readable` is required; `on_writable` defaults to a no-op and only fires while
/// write interest is armed for that fd (see [`Reactor::set_write_interest`]). Each is
/// handed `&mut Reactor`, so a handler can watch/unwatch fds, register/unregister others,
/// arm/disarm its own write interest.
pub(crate) trait Handler {
    fn on_readable(&mut self, event: ReadyEvent, reactor: &mut Reactor);

    /// The fd `event.fd` is writable and its write interest is armed.
    fn on_writable(&mut self, _event: ReadyEvent, _reactor: &mut Reactor) {}

    /// The earliest instant this handler wants [`on_deadline`](Self::on_deadline) called, or `None`
    /// if it has no pending timer. The run loop blocks no longer than the soonest across handlers,
    /// so a handler is called back at (or after) the instant it reports here.
    fn next_deadline(&self) -> Option<Instant> {
        None
    }

    /// `now` has reached this handler's [`next_deadline`](Self::next_deadline); its timer fired.
    /// `now` is the run loop's single read of the clock, passed in so the sweep is testable without
    /// a real clock.
    fn on_deadline(&mut self, _now: Instant, _reactor: &mut Reactor) {}

    /// The run loop is broadcasting a [`ControlEvent`] to every handler: an out-of-band request
    /// (currently a SIGUSR1 diagnostics dump), distinct from fd readiness and timers. Defaulted to a
    /// no-op; a handler with state worth dumping overrides it.
    fn on_control(&mut self, _event: ControlEvent, _reactor: &mut Reactor) {}

    /// Called once, right after [`register`](Reactor::register) inserts this handler, handing it its
    /// own [`HandlerKey`]. A handler that later watches fds it opens, or unregisters itself, records
    /// the key here. Defaulted to a no-op: most handlers act only through the `event` they are handed.
    fn adopt_key(&mut self, _key: HandlerKey) {}
}

/// What a registration is ready for in a given dispatch: the event a poll loop
/// (or a test) feeds the reactor.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Readiness {
    pub(crate) readable: bool,
    pub(crate) writable: bool,
}

/// What fired, handed to [`Handler::on_readable`] / [`Handler::on_writable`]: the fd, and the opaque
/// `user_data` the handler attached at [`watch`](Reactor::watch). The reactor never interprets
/// `user_data`; a handler can pack a key or an index into it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReadyEvent {
    pub(crate) fd: RawFd,
    /// The opaque value the handler passed to [`watch`](Reactor::watch).
    pub(crate) user_data: u64,
}

/// An out-of-band control request the run loop broadcasts to every handler, separate from fd
/// readiness and timer deadlines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlEvent {
    /// Dump diagnostics: each handler logs whatever operational state it holds. Raised by SIGUSR1.
    Dump,
}

/// A registered handler plus the keys of the fd-registrations that dispatch to it (so
/// [`unregister`](Reactor::unregister) can tear them all down). `handler` is `None` only
/// transiently, while it is mid-dispatch.
struct HandlerEntry {
    handler: Option<Box<dyn Handler>>,
    regs: Vec<RegKey>,
}

/// One watched fd: the fd, the handler it dispatches to, and whether its read/write interest
/// is armed. The poll layer tags the fd with this registration's [`RegKey`], so an event
/// names the exact fd.
struct Registration {
    fd: RawFd,
    handler_key: HandlerKey,
    read_interest: bool,
    write_interest: bool,
    user_data: u64,
}

/// The single-threaded reactor: owns the handlers and their per-fd registrations plus
/// the poller, and dispatches readiness to handlers.
pub(crate) struct Reactor {
    handlers: Arena<HandlerEntry>,
    registrations: Arena<Registration>,
    /// Reused across dispatch sweeps (deadline firing and control broadcasts) for the swept handlers'
    /// keys, snapshotted so a handler firing mid-sweep can touch the reactor without the buffer aliasing
    /// `&mut self`. Kept allocated so a sweep doesn't allocate.
    dispatch_keys: Vec<Key>,
    poll: Poller,
    shutdown: bool,
    /// Set by [`request_dump`](Self::request_dump) (the signal pipe, on SIGUSR1); the run loop
    /// broadcasts a [`ControlEvent::Dump`] and clears it.
    dump_pending: bool,
}

impl Reactor {
    /// A new reactor with no handlers and a fresh poller.
    ///
    /// # Errors
    /// Returns an error if the poller's backing fd (epoll/kqueue) cannot be created.
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            handlers: Arena::new(),
            registrations: Arena::new(),
            dispatch_keys: Vec::new(),
            poll: Poller::new(EVENT_CAPACITY)?,
            shutdown: false,
            dump_pending: false,
        })
    }

    /// Register `handler`, returning its key. It watches no fds yet; attach them with
    /// [`watch`](Self::watch), or use [`register_with_fds`](Self::register_with_fds) for
    /// a handler whose fds are known up front. The handler's [`adopt_key`](Handler::adopt_key) is
    /// called with the new key before this returns.
    pub(crate) fn register(&mut self, mut handler: Box<dyn Handler>) -> HandlerKey {
        HandlerKey(self.handlers.insert_from(|key| {
            // Hand the handler its own key before it is stored, so one that later watches fds it opens
            // (or self-unregisters) has it recorded.
            handler.adopt_key(HandlerKey(key));
            HandlerEntry {
                handler: Some(handler),
                regs: Vec::new(),
            }
        }))
    }

    /// Register `handler` and [`watch`](Self::watch) each `(fd, user_data)` under it in one
    /// step. On a failure the handler and any fds already attached are rolled back, so
    /// nothing is left behind.
    ///
    /// # Errors
    /// Returns an error if watching any fd fails.
    pub(crate) fn register_with_fds(
        &mut self,
        handler: Box<dyn Handler>,
        fds: &[(RawFd, u64)],
    ) -> io::Result<HandlerKey> {
        let handler_key = self.register(handler);
        for &(fd, user_data) in fds {
            if let Err(e) = self.watch(handler_key, fd, user_data) {
                self.unregister(handler_key).ok();
                return Err(e);
            }
        }
        Ok(handler_key)
    }

    /// Watch `fd` for readability on behalf of the handler `handler_key` addresses,
    /// returning the registration key: the handle to [`unwatch`](Self::unwatch) it or arm
    /// its write interest. `user_data` is opaque: the reactor stores it and hands it back
    /// in the [`ReadyEvent`] (a handler typically packs its own key there). The handler
    /// keeps owning the fd; the reactor only watches it.
    ///
    /// # Errors
    /// Returns an error if `handler_key` is not a live handler, or if the kernel
    /// registration fails (the arena insert is rolled back so no partial watch remains).
    pub(crate) fn watch(
        &mut self,
        handler_key: HandlerKey,
        fd: RawFd,
        user_data: u64,
    ) -> io::Result<RegKey> {
        // Borrow the handler up front; its `regs` get the new reg key at the end. `handlers`,
        // `registrations`, and `poll` are disjoint fields, so this borrow stays live across the
        // insert and the poll syscall.
        let Some(handler_entry) = self.handlers.get_mut(handler_key.0) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "watch: no such handler",
            ));
        };
        // Enforce add-once here, not in the Poller: kqueue's EV_ADD silently modifies an existing
        // filter instead of reporting a re-add, so a double-watch would retag one fd's routing and
        // let a later unwatch strip both regs' kernel interest. A caller bug, rejected uniformly.
        if self.registrations.iter().any(|(_, reg)| reg.fd == fd) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "watch: fd already watched",
            ));
        }
        let reg_key = RegKey(self.registrations.insert(Registration {
            fd,
            handler_key,
            read_interest: true,
            write_interest: false,
            user_data,
        }));
        if let Err(e) = self.poll.add(fd, reg_key.0) {
            self.registrations.remove(reg_key.0);
            return Err(e);
        }
        // Record it on the handler so `unregister` can find every fd to tear down.
        handler_entry.regs.push(reg_key);
        log::debug!("watch fd {fd} for {handler_key:?} as {reg_key:?}");
        Ok(reg_key)
    }

    /// Stop watching the fd that `reg_key` addresses, removing its kernel interest. The fd
    /// is *not* closed (the handler still owns it). Returns whether it was still live.
    ///
    /// # Errors
    /// Returns an error if removing the kernel interest fails.
    pub(crate) fn unwatch(&mut self, reg_key: RegKey) -> io::Result<bool> {
        let Some(registration) = self.registrations.remove(reg_key.0) else {
            log::trace!("unwatch: {reg_key:?} already gone");
            return Ok(false);
        };
        // Unlink it from its handler's list, then drop the kernel interest.
        if let Some(handler_entry) = self.handlers.get_mut(registration.handler_key.0) {
            handler_entry.regs.retain(|&r| r != reg_key);
        }
        self.poll.remove(registration.fd)?;
        log::debug!("unwatch fd {} ({reg_key:?})", registration.fd);
        Ok(true)
    }

    /// Drop the handler `handler_key` addresses and stop watching every fd registered to
    /// it, removing each fd's kernel interest *first*, before the handler drops and closes
    /// them. Returns whether it was still live.
    ///
    /// # Errors
    /// Returns the first error from removing a kernel interest; the rest are still
    /// removed (best-effort) so no fd is left watched.
    pub(crate) fn unregister(&mut self, handler_key: HandlerKey) -> io::Result<bool> {
        let Some(handler_entry) = self.handlers.remove(handler_key.0) else {
            log::trace!("unregister: {handler_key:?} already gone");
            return Ok(false);
        };
        // `handler_entry` keeps the handler (and its fds) alive until this returns, so each fd's
        // kernel interest is removed before the fd drops and closes.
        let mut first_err = None;
        for reg_key in handler_entry.regs {
            if let Some(registration) = self.registrations.remove(reg_key.0)
                && let Err(e) = self.poll.remove(registration.fd)
            {
                first_err.get_or_insert(e);
            }
        }
        log::debug!("unregistered {handler_key:?}");
        match first_err {
            Some(e) => Err(e),
            None => Ok(true),
        }
    }

    /// Arm or disarm delivery of write readiness for the fd that `reg_key` addresses.
    /// Returns whether the registration was live.
    ///
    /// # Errors
    /// Returns an error if updating the kernel's write interest fails.
    pub(crate) fn set_write_interest(
        &mut self,
        reg_key: RegKey,
        enabled: bool,
    ) -> io::Result<bool> {
        let Some(registration) = self.registrations.get_mut(reg_key.0) else {
            log::trace!("set_write_interest: {reg_key:?} already gone");
            return Ok(false);
        };
        // Already in the wanted state: skip the redundant epoll_ctl/kevent.
        if registration.write_interest == enabled {
            return Ok(true);
        }
        // Program the kernel first; flip the in-memory flag only on success, so the arena and
        // kernel never disagree about interest. (`self.poll` and `self.registrations` are disjoint
        // fields, so the `registration` borrow stays live across the syscall.)
        self.poll.set_interest(
            registration.fd,
            reg_key.0,
            registration.read_interest,
            enabled,
        )?;
        registration.write_interest = enabled;
        log::trace!(
            "fd {}: write interest {}",
            registration.fd,
            if enabled { "armed" } else { "disarmed" }
        );
        Ok(true)
    }

    /// Arm or disarm delivery of read readiness for the fd that `reg_key` addresses (armed at
    /// [`watch`](Self::watch)). Returns whether the registration was live. Disarming stops data and a
    /// peer's half-close (FIN) from waking the handler. epoll reports a hangup or error as readable
    /// whatever the mask says, so it always surfaces there; kqueue does not, since `EV_DISABLE` on the
    /// read filter suppresses `EV_EOF` and the write filter is deleted when write interest is off. A
    /// handler that disarms read must therefore keep write interest armed or a `next_deadline` set, or
    /// it will not hear about the fd again.
    ///
    /// # Errors
    /// Returns an error if updating the kernel's read interest fails.
    pub(crate) fn set_read_interest(&mut self, reg_key: RegKey, enabled: bool) -> io::Result<bool> {
        let Some(registration) = self.registrations.get_mut(reg_key.0) else {
            log::trace!("set_read_interest: {reg_key:?} already gone");
            return Ok(false);
        };
        self.poll.set_interest(
            registration.fd,
            reg_key.0,
            enabled,
            registration.write_interest,
        )?;
        registration.read_interest = enabled;
        log::trace!(
            "fd {}: read interest {}",
            registration.fd,
            if enabled { "armed" } else { "disarmed" }
        );
        Ok(true)
    }

    /// Whether `handler_key` still addresses a live handler.
    #[must_use]
    pub(crate) fn is_registered(&self, handler_key: HandlerKey) -> bool {
        self.handlers.contains(handler_key.0)
    }

    /// Wait for readiness (until `timeout`, or block if `None`) and dispatch each
    /// ready fd. The single step a run loop repeats.
    ///
    /// # Errors
    /// Returns an error if the underlying wait fails. An interrupted wait reports
    /// no events rather than erroring.
    pub(crate) fn poll_once(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.poll.wait(timeout)?;
        // `next_event` returns an owned (`Copy`) event, so the `self.poll` borrow ends before
        // `dispatch` needs `&mut self`.
        while let Some(event) = self.poll.next_event() {
            self.dispatch(RegKey(event.key), event.readiness);
        }
        Ok(())
    }

    /// Run until a shutdown signal (SIGINT/SIGTERM) arrives, dispatching readiness
    /// in between. A self-pipe shutdown handler is installed for the duration and
    /// the previous signal dispositions are restored before returning.
    ///
    /// # Errors
    /// Returns an error if the shutdown handler cannot be installed or a wait fails.
    pub(crate) fn run(&mut self) -> io::Result<()> {
        let (guard, pipe) = signal::SignalGuard::install()?;
        let fd = pipe.read_fd();
        // The signal pipe is read-only with no per-fd token, so `user_data` is unused (0).
        let handler_key = self.register_with_fds(Box::new(pipe), &[(fd, 0)])?;
        self.shutdown = false;
        self.dump_pending = false;
        let result = self.run_loop();
        // Restore the signal handlers and unpublish the write fd *before* closing
        // the read end, so a late signal can't write to a reader-less pipe.
        drop(guard);
        self.unregister(handler_key).ok();
        result
    }

    /// Dispatch readiness until [`request_shutdown`](Self::request_shutdown) is called, waking no
    /// later than the soonest handler deadline to run its timer. With no deadline pending it blocks
    /// indefinitely, so it still idles at zero cost between events.
    fn run_loop(&mut self) -> io::Result<()> {
        while !self.shutdown {
            let deadline = self.next_deadline();
            let timeout = deadline.map(|d| d.saturating_duration_since(Instant::now()));
            self.poll_once(timeout)?;
            // A signal handler may have set this via the signal pipe just dispatched; broadcast it now.
            if self.dump_pending {
                self.dump_pending = false;
                self.dispatch_control(ControlEvent::Dump);
            }
            // Sweep only if a deadline has actually come due. An fd wakeup before it leaves
            // `now < deadline`, so no scan.
            let now = Instant::now();
            if deadline.is_some_and(|d| now >= d) {
                self.dispatch_deadlines(now);
            }
        }
        Ok(())
    }

    /// The soonest deadline any handler is waiting on, or `None` if none has a pending timer.
    fn next_deadline(&self) -> Option<Instant> {
        self.handlers
            .iter()
            .filter_map(|(_, entry)| entry.handler.as_ref().and_then(|h| h.next_deadline()))
            .min()
    }

    /// Fire [`Handler::on_deadline`] on every handler whose deadline has reached `now`. Each handler
    /// is taken out for its call (as in [`dispatch`](Self::dispatch)) so it can touch the reactor;
    /// one that removes itself mid-call is simply not restored.
    fn dispatch_deadlines(&mut self, now: Instant) {
        // Snapshot the due handlers into the reused buffer, then fire them with the same take-and-
        // restore as `dispatch` so each can touch the reactor. Indexing by `Key` (Copy) drops the
        // buffer borrow before the `&mut self` call; a handler that removes itself (or another due
        // handler) mid-sweep leaves a stale key, and the `get_mut` miss makes take and restore no-ops.
        // Deadline sweeps never nest, so one shared buffer suffices.
        self.dispatch_keys.clear();
        self.dispatch_keys.extend(
            self.handlers
                .iter()
                .filter(|(_, entry)| {
                    entry
                        .handler
                        .as_ref()
                        .and_then(|h| h.next_deadline())
                        .is_some_and(|d| d <= now)
                })
                .map(|(key, _)| key),
        );
        for i in 0..self.dispatch_keys.len() {
            let key = self.dispatch_keys[i];
            // Gone if an earlier sweep in this pass removed it (its key went stale); benign.
            let Some(mut handler) = self
                .handlers
                .get_mut(key)
                .and_then(|entry| entry.handler.take())
            else {
                log::trace!("dispatch_deadlines: handler for {key:?} gone mid-sweep, skipped");
                continue;
            };
            log::trace!("deadline fired for {key:?}");
            handler.on_deadline(now, self);
            if let Some(entry) = self.handlers.get_mut(key) {
                entry.handler = Some(handler);
            }
        }
    }

    /// Broadcast `event` to every handler, taking each out for its call (as [`dispatch_deadlines`] and
    /// [`dispatch`] do) so it can touch the reactor. Unconditional: a control request isn't tied to
    /// any one handler. Shares the [`dispatch_keys`](Self::dispatch_keys) snapshot buffer with the
    /// deadline sweep; the two never nest (the run loop runs them in sequence), so one buffer suffices.
    ///
    /// [`dispatch_deadlines`]: Self::dispatch_deadlines
    /// [`dispatch`]: Self::dispatch
    fn dispatch_control(&mut self, event: ControlEvent) {
        self.dispatch_keys.clear();
        self.dispatch_keys
            .extend(self.handlers.iter().map(|(key, _)| key));
        for i in 0..self.dispatch_keys.len() {
            let key = self.dispatch_keys[i];
            // Gone if an earlier handler in this pass removed it (its key went stale); benign.
            let Some(mut handler) = self
                .handlers
                .get_mut(key)
                .and_then(|entry| entry.handler.take())
            else {
                log::trace!("dispatch_control: handler for {key:?} gone mid-broadcast, skipped");
                continue;
            };
            handler.on_control(event, self);
            if let Some(entry) = self.handlers.get_mut(key) {
                entry.handler = Some(handler);
            }
        }
    }

    /// Ask the run loop to stop before its next iteration. The flag is only the `while` condition,
    /// and a handler sets it mid-body, past this iteration's check, so the iteration underway
    /// completes: the batch's remaining events, a pending dump broadcast, and a due deadline sweep
    /// all still dispatch. Handlers call this (the self-pipe handler does, on a shutdown signal).
    /// Calling it outside a run loop has no lasting effect: [`run`](Self::run) clears the flag
    /// before entering the loop.
    pub(crate) fn request_shutdown(&mut self) {
        self.shutdown = true;
    }

    /// Ask the run loop to broadcast a [`ControlEvent::Dump`] to every handler once the current
    /// dispatch returns. The signal pipe calls this on SIGUSR1.
    pub(crate) fn request_dump(&mut self) {
        self.dump_pending = true;
    }

    /// Deliver `readiness` to the fd that `reg_key` addresses: the seam
    /// [`poll_once`](Self::poll_once) drives the reactor through. A stale `reg_key` (its fd
    /// was unwatched) is a safe no-op.
    fn dispatch(&mut self, reg_key: RegKey, readiness: Readiness) {
        let Some(registration) = self.registrations.get(reg_key.0) else {
            // stale reg_key: the fd was unwatched
            log::trace!("dispatch: {reg_key:?} is stale, ignored");
            return;
        };
        let handler_key = registration.handler_key;
        let event = ReadyEvent {
            fd: registration.fd,
            user_data: registration.user_data,
        };
        // Take the handler out so `self` is free to pass to it; the slot stays put, so
        // `handler_key` stays valid and the handler is returned after the call.
        let Some(handler_entry) = self.handlers.get_mut(handler_key.0) else {
            log::trace!("dispatch: {reg_key:?} -> {handler_key:?} gone, ignored");
            return;
        };
        let Some(mut handler) = handler_entry.handler.take() else {
            // reentrant dispatch of a handler already in flight
            log::trace!("dispatch: {handler_key:?} already in flight, ignored");
            return;
        };

        log::trace!(
            "dispatch {reg_key:?} (fd {}): readable={} writable={}",
            event.fd,
            readiness.readable,
            readiness.writable
        );

        if readiness.readable {
            handler.on_readable(event, self);
        }
        // Write is re-gated after the read phase: the read handler may have unwatched the
        // fd or disarmed its write interest in between.
        if readiness.writable {
            if self
                .registrations
                .get(reg_key.0)
                .is_some_and(|r| r.write_interest)
            {
                handler.on_writable(event, self);
            } else {
                log::trace!("dispatch {reg_key:?}: write suppressed after read phase");
            }
        }

        // Return the handler, unless it was removed during the call, in which case its
        // entry is gone and the handler is dropped.
        if let Some(handler_entry) = self.handlers.get_mut(handler_key.0) {
            handler_entry.handler = Some(handler);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::io::Write;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;

    const READABLE: Readiness = Readiness {
        readable: true,
        writable: false,
    };
    const WRITABLE: Readiness = Readiness {
        readable: false,
        writable: true,
    };
    const BOTH: Readiness = Readiness {
        readable: true,
        writable: true,
    };

    fn short() -> Duration {
        Duration::from_millis(50)
    }

    /// A connected socketpair: the owned end (to register) plus its peer (kept
    /// alive; write to it to make the registered end readable).
    fn pair() -> (OwnedFd, UnixStream) {
        let (a, b) = UnixStream::pair().unwrap();
        (OwnedFd::from(a), b)
    }

    /// A [`TestHandler`] callback: each test supplies behavior as a closure over the
    /// [`ReadyEvent`] that fired plus the reactor.
    type Action = Box<dyn FnMut(ReadyEvent, &mut Reactor)>;

    /// A [`TimerHandler`]'s fire callback, aliased like [`Action`] to keep the field type simple.
    type TimerAction = Box<dyn FnMut(Instant, &mut Reactor)>;

    struct TestHandler {
        /// Owned only to keep the watched fd open for the handler's life (its `Drop` closes it).
        _fd: OwnedFd,
        on_read: Action,
        on_write: Option<Action>,
    }

    impl TestHandler {
        fn read(
            fd: OwnedFd,
            action: impl FnMut(ReadyEvent, &mut Reactor) + 'static,
        ) -> Box<dyn Handler> {
            Box::new(Self {
                _fd: fd,
                on_read: Box::new(action),
                on_write: None,
            })
        }

        fn read_write(
            fd: OwnedFd,
            read: impl FnMut(ReadyEvent, &mut Reactor) + 'static,
            write: impl FnMut(ReadyEvent, &mut Reactor) + 'static,
        ) -> Box<dyn Handler> {
            Box::new(Self {
                _fd: fd,
                on_read: Box::new(read),
                on_write: Some(Box::new(write)),
            })
        }
    }

    impl Handler for TestHandler {
        fn on_readable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
            (self.on_read)(event, reactor);
        }

        fn on_writable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
            if let Some(write) = &mut self.on_write {
                write(event, reactor);
            }
        }
    }

    /// Register a single-fd handler and watch its fd (no user data); return both keys:
    /// the handler key (for `is_registered`/`unregister`) and the reg key (for
    /// `dispatch`/write interest).
    fn watch1(reactor: &mut Reactor, handler: Box<dyn Handler>, fd: RawFd) -> (HandlerKey, RegKey) {
        let hk = reactor.register(handler);
        let rk = reactor.watch(hk, fd, 0).unwrap();
        (hk, rk)
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn dispatch_calls_on_readable() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let raw = a.as_raw_fd();
        let seen = Rc::new(Cell::new(false));
        let handler = {
            let seen = seen.clone();
            TestHandler::read(a, move |_event, _reactor| seen.set(true))
        };
        let (_hk, rk) = watch1(&mut reactor, handler, raw);
        reactor.dispatch(rk, READABLE);
        assert!(seen.get());
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn handler_can_unregister_itself() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let raw = a.as_raw_fd();
        let hits = Rc::new(Cell::new(0u32));
        let self_key: Rc<Cell<Option<HandlerKey>>> = Rc::new(Cell::new(None));
        let handler = {
            let hits = hits.clone();
            let self_key = self_key.clone();
            TestHandler::read(a, move |_event, reactor| {
                hits.set(hits.get() + 1);
                if let Some(k) = self_key.get() {
                    reactor.unregister(k).unwrap();
                }
            })
        };
        let (hk, rk) = watch1(&mut reactor, handler, raw);
        self_key.set(Some(hk));

        reactor.dispatch(rk, READABLE);
        assert_eq!(hits.get(), 1);
        assert!(!reactor.is_registered(hk));

        // The now-stale reg dispatches to nothing.
        reactor.dispatch(rk, READABLE);
        assert_eq!(hits.get(), 1);
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn handler_can_register_during_dispatch() {
        // The classic mid-dispatch hazard: registering a new handler while dispatching.
        // Nothing borrows the arenas during the call, so it is simply allowed.
        let mut reactor = Reactor::new().unwrap();
        let (a, _pa) = pair();
        let raw = a.as_raw_fd();
        let (c, _pc) = pair();
        let added: Rc<Cell<Option<HandlerKey>>> = Rc::new(Cell::new(None));
        // The handler takes ownership of `c` out of this slot when it fires.
        let to_add = Rc::new(RefCell::new(Some(c)));
        let handler = {
            let added = added.clone();
            let to_add = to_add.clone();
            TestHandler::read(a, move |_event, reactor| {
                let c = to_add.borrow_mut().take().unwrap();
                let c_raw = c.as_raw_fd();
                let new_key = reactor
                    .register_with_fds(TestHandler::read(c, |_, _| {}), &[(c_raw, 0)])
                    .unwrap();
                added.set(Some(new_key));
            })
        };
        let (hk, rk) = watch1(&mut reactor, handler, raw);
        reactor.dispatch(rk, READABLE);
        assert!(reactor.is_registered(added.get().unwrap()));
        assert!(reactor.is_registered(hk));
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn handler_can_unregister_another() {
        let mut reactor = Reactor::new().unwrap();
        let (victim_fd, _pv) = pair();
        let victim_raw = victim_fd.as_raw_fd();
        let (actor_fd, _pa) = pair();
        let actor_raw = actor_fd.as_raw_fd();
        let victim_hits = Rc::new(Cell::new(0u32));
        let victim_handler = {
            let victim_hits = victim_hits.clone();
            TestHandler::read(victim_fd, move |_event, _reactor| {
                victim_hits.set(victim_hits.get() + 1);
            })
        };
        let (victim, victim_rk) = watch1(&mut reactor, victim_handler, victim_raw);
        let victim_cell = Rc::new(Cell::new(Some(victim)));
        let actor_handler = {
            let victim_cell = victim_cell.clone();
            TestHandler::read(actor_fd, move |_event, reactor| {
                if let Some(v) = victim_cell.get() {
                    reactor.unregister(v).unwrap();
                }
            })
        };
        let (_actor, actor_rk) = watch1(&mut reactor, actor_handler, actor_raw);

        reactor.dispatch(actor_rk, READABLE);
        assert!(!reactor.is_registered(victim));

        // Dispatching the stale victim reg is a safe no-op.
        reactor.dispatch(victim_rk, READABLE);
        assert_eq!(victim_hits.get(), 0);
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn write_interest_gates_on_writable() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let raw = a.as_raw_fd();
        let writes = Rc::new(Cell::new(0u32));
        let handler = TestHandler::read_write(a, |_, _| {}, {
            let writes = writes.clone();
            move |_event, _reactor| writes.set(writes.get() + 1)
        });
        let (_hk, rk) = watch1(&mut reactor, handler, raw);

        // Disarmed: writable readiness does nothing.
        reactor.dispatch(rk, WRITABLE);
        assert_eq!(writes.get(), 0);

        assert!(reactor.set_write_interest(rk, true).unwrap());
        reactor.dispatch(rk, WRITABLE);
        assert_eq!(writes.get(), 1);
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn read_handler_disarming_write_skips_the_write_phase() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let raw = a.as_raw_fd();
        let writes = Rc::new(Cell::new(0u32));
        let reg: Rc<Cell<Option<RegKey>>> = Rc::new(Cell::new(None));
        // The read phase disarms write interest on its own reg before the write phase.
        let handler = TestHandler::read_write(
            a,
            {
                let reg = reg.clone();
                move |_event, reactor| {
                    reactor
                        .set_write_interest(reg.get().unwrap(), false)
                        .unwrap();
                }
            },
            {
                let writes = writes.clone();
                move |_event, _reactor| writes.set(writes.get() + 1)
            },
        );
        let (_hk, rk) = watch1(&mut reactor, handler, raw);
        reg.set(Some(rk));
        reactor.set_write_interest(rk, true).unwrap();

        // Both ready, but the read handler disarms write before the write phase.
        reactor.dispatch(rk, BOTH);
        assert_eq!(writes.get(), 0);
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn read_handler_unregistering_itself_skips_the_write_phase() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let raw = a.as_raw_fd();
        let writes = Rc::new(Cell::new(0u32));
        let self_key: Rc<Cell<Option<HandlerKey>>> = Rc::new(Cell::new(None));
        let handler = TestHandler::read_write(
            a,
            {
                let self_key = self_key.clone();
                move |_event, reactor| {
                    if let Some(k) = self_key.get() {
                        reactor.unregister(k).unwrap();
                    }
                }
            },
            {
                let writes = writes.clone();
                move |_event, _reactor| writes.set(writes.get() + 1)
            },
        );
        let (hk, rk) = watch1(&mut reactor, handler, raw);
        self_key.set(Some(hk));
        reactor.set_write_interest(rk, true).unwrap();

        reactor.dispatch(rk, BOTH);
        assert_eq!(writes.get(), 0); // handler gone after read, write skipped
        assert!(!reactor.is_registered(hk));
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn dispatching_a_stale_reg_is_a_noop() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let raw = a.as_raw_fd();
        let handler = TestHandler::read(a, |_, _| panic!("must not fire"));
        let (hk, rk) = watch1(&mut reactor, handler, raw);
        assert!(reactor.unregister(hk).unwrap());
        reactor.dispatch(rk, READABLE); // no panic, no effect
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real poll backend")]
    fn poll_once_dispatches_a_ready_fd() {
        let mut reactor = Reactor::new().unwrap();
        let (a, peer) = pair();
        let raw = a.as_raw_fd();
        let fired = Rc::new(Cell::new(false));
        let handler = {
            let fired = fired.clone();
            TestHandler::read(a, move |_event, _reactor| fired.set(true))
        };
        watch1(&mut reactor, handler, raw);

        // Nothing ready yet: poll_once dispatches nothing.
        reactor.poll_once(Some(short())).unwrap();
        assert!(!fired.get());

        // Make the registered fd readable, then poll: the handler fires.
        (&peer).write_all(b"x").unwrap();
        reactor.poll_once(Some(short())).unwrap();
        assert!(fired.get());
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real poll backend")]
    fn run_loop_stops_when_a_handler_requests_shutdown() {
        let mut reactor = Reactor::new().unwrap();
        let (a, peer) = pair();
        let raw = a.as_raw_fd();
        let handler = TestHandler::read(a, |_event, reactor| reactor.request_shutdown());
        watch1(&mut reactor, handler, raw);
        // Readable before looping, so the first (blocking) wait returns at once.
        (&peer).write_all(b"x").unwrap();
        reactor.run_loop().unwrap();
        assert!(reactor.shutdown);
    }

    /// Counts [`Handler::on_control`] broadcasts, for the SIGUSR1 dump fan-out tests.
    struct ControlCounter(Rc<Cell<u32>>);

    impl Handler for ControlCounter {
        fn on_readable(&mut self, _event: ReadyEvent, _reactor: &mut Reactor) {}
        fn on_control(&mut self, _event: ControlEvent, _reactor: &mut Reactor) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn dispatch_control_reaches_every_handler() {
        let mut reactor = Reactor::new().unwrap();
        let count = Rc::new(Cell::new(0u32));
        reactor.register(Box::new(ControlCounter(count.clone())));
        reactor.register(Box::new(ControlCounter(count.clone())));
        reactor.dispatch_control(ControlEvent::Dump);
        assert_eq!(
            count.get(),
            2,
            "every registered handler gets the control event"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "needs a real poll backend")]
    fn run_loop_broadcasts_a_pending_dump() {
        let mut reactor = Reactor::new().unwrap();
        let (a, peer) = pair();
        let raw = a.as_raw_fd();
        // On its read the trigger requests a dump and a shutdown, so the loop broadcasts once and exits.
        let trigger = TestHandler::read(a, |_event, reactor| {
            reactor.request_dump();
            reactor.request_shutdown();
        });
        watch1(&mut reactor, trigger, raw);
        let dumps = Rc::new(Cell::new(0u32));
        reactor.register(Box::new(ControlCounter(dumps.clone())));
        (&peer).write_all(b"x").unwrap();
        reactor.run_loop().unwrap();
        assert_eq!(
            dumps.get(),
            1,
            "the pending dump broadcasts once before the loop stops"
        );
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn unwatch_removes_one_fd_and_leaves_the_handler() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _pa) = pair();
        let a_raw = a.as_raw_fd();
        let (b, _pb) = pair();
        let b_raw = b.as_raw_fd();
        let hits = Rc::new(Cell::new(0u32));
        // One handler watching two fds (it owns `a`; the test keeps `b` alive).
        let handler = {
            let hits = hits.clone();
            TestHandler::read(a, move |_event, _reactor| hits.set(hits.get() + 1))
        };
        let hk = reactor.register(handler);
        let reg_a = reactor.watch(hk, a_raw, 0).unwrap();
        let reg_b = reactor.watch(hk, b_raw, 0).unwrap();

        reactor.dispatch(reg_a, READABLE);
        reactor.dispatch(reg_b, READABLE);
        assert_eq!(hits.get(), 2);

        // Unwatch one fd: it goes stale, but the handler and its other fd stay live.
        assert!(reactor.unwatch(reg_a).unwrap());
        reactor.dispatch(reg_a, READABLE); // stale, no-op
        reactor.dispatch(reg_b, READABLE);
        assert_eq!(hits.get(), 3);
        assert!(reactor.is_registered(hk));

        // Unwatching an already-gone reg is a benign false.
        assert!(!reactor.unwatch(reg_a).unwrap());
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn watch_hands_back_the_ready_event() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let raw = a.as_raw_fd();
        let seen: Rc<Cell<Option<ReadyEvent>>> = Rc::new(Cell::new(None));
        let handler = {
            let seen = seen.clone();
            TestHandler::read(a, move |event, _reactor| seen.set(Some(event)))
        };
        let hk = reactor.register(handler);
        let rk = reactor.watch(hk, raw, 0xdead_beef).unwrap();

        reactor.dispatch(rk, READABLE);
        let event = seen.get().expect("handler fired");
        assert_eq!(event.user_data, 0xdead_beef); // the token round-trips
        assert_eq!(event.fd, raw);
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn register_hands_the_handler_its_own_key() {
        // A handler that records the key it is adopted with, so we can check it matches `register`'s.
        struct KeyRecorder(Rc<Cell<Option<HandlerKey>>>);
        impl Handler for KeyRecorder {
            fn on_readable(&mut self, _event: ReadyEvent, _reactor: &mut Reactor) {}
            fn adopt_key(&mut self, key: HandlerKey) {
                self.0.set(Some(key));
            }
        }
        let mut reactor = Reactor::new().unwrap();
        let seen = Rc::new(Cell::new(None));
        let key = reactor.register(Box::new(KeyRecorder(seen.clone())));
        assert_eq!(
            seen.get(),
            Some(key),
            "adopt_key received the handler's own key"
        );
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn watch_on_a_stale_handler_errors() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _pa) = pair();
        let hk = reactor.register(TestHandler::read(a, |_, _| {}));
        assert!(reactor.unregister(hk).unwrap());
        // A live fd, so the rejection is due to the stale handler key, not a bad fd.
        let (b, _pb) = pair();
        assert!(reactor.watch(hk, b.as_raw_fd(), 0).is_err());
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn watch_rejects_a_duplicate_fd() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _pa) = pair();
        let raw = a.as_raw_fd();
        let (hk, _rk) = watch1(&mut reactor, TestHandler::read(a, |_, _| {}), raw);
        // A second watch of the same fd is a caller bug the reactor rejects uniformly: kqueue's
        // EV_ADD can't report the re-add, so without this the BSD backend would retag the fd and a
        // later unwatch would strip both regs' interest.
        assert!(reactor.watch(hk, raw, 0).is_err());
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn watch_failure_errors_and_leaves_the_handler_usable() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _pa) = pair();
        let hk = reactor.register(TestHandler::read(a, |_, _| {}));
        // The largest descriptor number is never open, so the kernel add fails with EBADF; a
        // closed one would not do, as another test thread can reuse its number before the watch.
        assert!(reactor.watch(hk, RawFd::MAX, 0).is_err());
        // The handler is intact and can still watch a good fd afterward.
        assert!(reactor.is_registered(hk));
        let (b, _pb) = pair();
        assert!(reactor.watch(hk, b.as_raw_fd(), 0).is_ok());
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn setting_interest_on_a_stale_reg_is_a_benign_false() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let raw = a.as_raw_fd();
        let (hk, rk) = watch1(&mut reactor, TestHandler::read(a, |_, _| {}), raw);
        assert!(reactor.unwatch(rk).unwrap());
        assert!(!reactor.set_write_interest(rk, true).unwrap());
        assert!(!reactor.set_read_interest(rk, true).unwrap());
        assert!(reactor.is_registered(hk)); // the handler itself is untouched
    }

    /// A handler with no fd that only carries a timer: it reports `deadline` and runs `on_fire`
    /// when the reactor sweeps it. Lets the deadline path be tested without a real clock or fds.
    struct TimerHandler {
        deadline: Option<Instant>,
        on_fire: TimerAction,
    }

    impl Handler for TimerHandler {
        fn on_readable(&mut self, _event: ReadyEvent, _reactor: &mut Reactor) {}
        fn next_deadline(&self) -> Option<Instant> {
            self.deadline
        }
        fn on_deadline(&mut self, now: Instant, reactor: &mut Reactor) {
            (self.on_fire)(now, reactor);
        }
    }

    fn timer(
        deadline: Option<Instant>,
        on_fire: impl FnMut(Instant, &mut Reactor) + 'static,
    ) -> Box<dyn Handler> {
        Box::new(TimerHandler {
            deadline,
            on_fire: Box::new(on_fire),
        })
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn next_deadline_reports_the_soonest_across_handlers() {
        let mut reactor = Reactor::new().unwrap();
        let base = Instant::now();
        reactor.register(timer(Some(base + short() * 2), |_, _| {}));
        reactor.register(timer(Some(base + short()), |_, _| {}));
        reactor.register(timer(None, |_, _| {})); // no timer, ignored by the min
        assert_eq!(reactor.next_deadline(), Some(base + short()));
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn dispatch_deadlines_fires_only_the_handlers_that_are_due() {
        let mut reactor = Reactor::new().unwrap();
        let base = Instant::now();
        let due = Rc::new(Cell::new(false));
        let early = Rc::new(Cell::new(false));
        reactor.register(timer(Some(base), {
            let due = due.clone();
            move |_, _| due.set(true)
        }));
        reactor.register(timer(Some(base + short() * 10), {
            let early = early.clone();
            move |_, _| early.set(true)
        }));
        reactor.dispatch_deadlines(base + short());
        assert!(due.get(), "a deadline at or before now fires");
        assert!(!early.get(), "a deadline in the future does not");
    }

    #[test]
    #[cfg_attr(all(miri, not(target_os = "linux")), ignore = "needs a real kqueue")]
    fn run_loop_wakes_at_a_deadline_and_runs_the_timer() {
        let mut reactor = Reactor::new().unwrap();
        let fired = Rc::new(Cell::new(false));
        reactor.register(timer(Some(Instant::now() + short()), {
            let fired = fired.clone();
            move |_now, reactor| {
                fired.set(true);
                reactor.request_shutdown();
            }
        }));
        // No fds are watched, so nothing but the timer elapsing can end the wait.
        reactor.run_loop().unwrap();
        assert!(fired.get());
    }
}
