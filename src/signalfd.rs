//! A signal notifier that uses Linux's signalfd API.

macro_rules! syscall {
    ($syscall:ident($($arg:expr),*)) => {{
        let res = unsafe { libc::$syscall($($arg),*) };
        if res == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

use crate::Signal;
use async_io::Async;
use concurrent_queue::ConcurrentQueue;

use std::fmt;
use std::io;
use std::mem;
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::sync::Arc;
use std::task::{Context, Poll};

const MAX_SIGNALS: usize = 16;

/// The notifier that uses Linux's signalfd API.
pub(super) struct Notifier {
    /// The signalfd.
    fd: Async<Signalfd>,

    /// The current signal set.
    mask: libc::sigset_t,

    /// Shared queue of signals.
    queue: Arc<ConcurrentQueue<Signal>>,
}

impl fmt::Debug for Notifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Notifier")
            .field("fd", &self.fd)
            .field("mask", &"libc::sigset_t")
            .finish()
    }
}

impl Notifier {
    /// Create a new signal notifier.
    pub(super) fn new() -> io::Result<Self> {
        let mut mask = mem::MaybeUninit::uninit();
        syscall!(sigemptyset(mask.as_mut_ptr()))?;
        let mask = unsafe { mask.assume_init() };

        let fd = Signalfd::new(&mask)?;
        let queue = Arc::new(ConcurrentQueue::bounded(MAX_SIGNALS));

        Ok(Self {
            fd: Async::new(fd)?,
            mask,
            queue,
        })
    }

    /// Add a signal to the notifier.
    ///
    /// Returns a closure to be passed to signal-hook.
    pub(super) fn add_signal(
        &mut self,
        signal: Signal,
    ) -> io::Result<impl Fn() + Send + Sync + 'static> {
        let number = signal.number();

        syscall!(sigaddset(&mut self.mask, number))?;
        self.fd.get_ref().set_mask(&self.mask)?;

        // Push the signal onto the queue.
        // SAFETY: The current bounded queue implementation is signal safe.
        let queue = self.queue.clone();
        Ok(move || {
            let _ = queue.push(signal);
        })
    }

    /// Remove a signal from the notifier.
    pub(super) fn remove_signal(&mut self, signal: Signal) -> io::Result<()> {
        let number = signal.number();

        syscall!(sigdelset(&mut self.mask, number))?;
        self.fd.get_ref().set_mask(&self.mask)?;

        Ok(())
    }

    /// Get the next signal.
    pub(super) fn poll_next(&self, cx: &mut Context<'_>) -> Poll<io::Result<Signal>> {
        let mut first_time = true;

        loop {
            // Read the next signal from the queue.
            if let Ok(signal) = self.queue.pop() {
                return Poll::Ready(Ok(signal));
            }

            match self.fd.get_ref().read_signal() {
                Ok(info) => {
                    let signal = Signal::from_number(info.ssi_signo as _).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "signalfd returned invalid signal",
                        )
                    })?;

                    return Poll::Ready(Ok(signal));
                }

                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}

                Err(e) => return Poll::Ready(Err(e)),
            }

            if first_time {
                // If this is the first time, then we don't need to wait for the fd to be readable.
                first_time = false;
                continue;
            }

            // Wait for the fd to be readable.
            ready!(self.fd.poll_readable(cx))?;
        }
    }
}

impl AsRawFd for Notifier {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for Notifier {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

struct Signalfd(RawFd);

impl fmt::Debug for Signalfd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Signalfd").field(&self.0).finish()
    }
}

impl Signalfd {
    /// Create a new signal fd with the provided mask.
    fn new(mask: &libc::sigset_t) -> io::Result<Self> {
        let fd = syscall!(signalfd(-1, mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC))?;
        Ok(Self(fd))
    }

    /// Set the mask of the signal fd.
    fn set_mask(&self, mask: &libc::sigset_t) -> io::Result<()> {
        syscall!(signalfd(
            self.0,
            mask,
            libc::SFD_NONBLOCK | libc::SFD_CLOEXEC
        ))?;
        Ok(())
    }

    /// Read a signal from the signal fd.
    fn read_signal(&self) -> io::Result<libc::signalfd_siginfo> {
        let mut info = mem::MaybeUninit::uninit();
        let res = syscall!(read(
            self.0,
            info.as_mut_ptr() as *mut _,
            mem::size_of::<libc::signalfd_siginfo>()
        ))?;
        if res != mem::size_of::<libc::signalfd_siginfo>() as _ {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "signalfd read returned invalid size",
            ))
        } else {
            Ok(unsafe { info.assume_init() })
        }
    }
}

impl AsRawFd for Signalfd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl AsFd for Signalfd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(self.0) }
    }
}

impl Drop for Signalfd {
    fn drop(&mut self) {
        let _ = syscall!(close(self.0));
    }
}
