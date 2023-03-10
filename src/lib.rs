//! Asynchronous signal handling.
//!
//! This crate provides the [`Signals`] type, which can be used to listen for POSIX signals asynchronously.
//! It can be seen as an asynchronous version of [`signal_hook::iterator::Signals`].
//!
//! As of the time of writing, this crate is `unix`-only.
//!
//! [`signal_hook::iterator::Signals`]: https://docs.rs/signal-hook/latest/signal_hook/iterator/struct.Signals.html
//!
//! # Implementation
//!
//! This crate uses the [`signal_hook_registry`] crate to register a listener for each signal. That
//! listener will then send a message through a Unix socket to the [`Signals`] type, which will
//! receive it and notify the user. Asynchronous notification is done through the [`async-io`] crate.
//!
//! Note that the internal pipe has a limited capacity. Once it has reached capacity, additional
//! signals will be dropped.
//!
//! [`signal_hook_registry`]: https://crates.io/crates/signal-hook-registry
//! [`async-io`]: https://crates.io/crates/async-io
//!
//! # Examples
//!
//! ```no_run
//! use async_signal::{Signal, Signals};
//! use futures_lite::prelude::*;
//! use signal_hook::low_level;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # async_io::block_on(async {
//! // Register the signals we want to receive.
//! let mut signals = Signals::new(&[
//!     Signal::Term,
//!     Signal::Quit,
//!     Signal::Int,
//! ])?;
//!
//! // Wait for a signal to be received.
//! while let Some(signal) = signals.next().await {
//!     // Print the signal.
//!     eprintln!("Received signal {:?}", signal);
//!
//!     // After printing it, do whatever the signal was supposed to do in the first place.
//!     low_level::emulate_default_handler(signal.unwrap() as i32).unwrap();
//! }
//! # Ok(())
//! # })
//! # }
//! ```

#![cfg(unix)]

use async_io::Async;
use futures_core::stream::Stream;
use futures_io::AsyncRead;
use signal_hook_registry::SigId;

use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt;
use std::io::{self, prelude::*};
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(not(async_signal_no_io_safety))]
use std::os::unix::io::{AsFd, BorrowedFd};

macro_rules! ready {
    ($e: expr) => {
        match $e {
            Poll::Ready(t) => t,
            Poll::Pending => return Poll::Pending,
        }
    };
}

macro_rules! define_signal_enum {
    (
        $(#[$outer:meta])*
        pub enum Signal {
            $(
                $(#[$inner:meta])*
                $name:ident = $value:ident,
            )*
        }
    ) => {
        $(#[$outer])*
        #[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
        #[repr(i32)]
        pub enum Signal {
            $(
                $(#[$inner])*
                $name = libc::$value,
            )*
        }

        impl Signal {
            /// Returns the signal number.
            fn number(self) -> libc::c_int {
                match self {
                    $(
                        Signal::$name => libc::$value,
                    )*
                }
            }

            /// Parse a signal from its number.
            fn from_number(number: libc::c_int) -> Option<Self> {
                match number {
                    $(
                        libc::$value => Some(Signal::$name),
                    )*
                    _ => None,
                }
            }
        }
    }
}

define_signal_enum! {
    // Copied from https://github.com/bytecodealliance/rustix/blob/main/src/backend/linux_raw/process/types.rs#L81-L161

    /// The signal types that we are able to listen for.
    pub enum Signal {
        /// `SIGHUP`
        Hup = SIGHUP,
        /// `SIGINT`
        Int = SIGINT,
        /// `SIGQUIT`
        Quit = SIGQUIT,
        /// `SIGILL`
        Ill = SIGILL,
        /// `SIGTRAP`
        Trap = SIGTRAP,
        /// `SIGABRT`, aka `SIGIOT`
        #[doc(alias = "Iot")]
        #[doc(alias = "Abrt")]
        Abort = SIGABRT,
        /// `SIGBUS`
        Bus = SIGBUS,
        /// `SIGFPE`
        Fpe = SIGFPE,
        /// `SIGKILL`
        Kill = SIGKILL,
        /// `SIGUSR1`
        Usr1 = SIGUSR1,
        /// `SIGSEGV`
        Segv = SIGSEGV,
        /// `SIGUSR2`
        Usr2 = SIGUSR2,
        /// `SIGPIPE`
        Pipe = SIGPIPE,
        /// `SIGALRM`
        #[doc(alias = "Alrm")]
        Alarm = SIGALRM,
        /// `SIGTERM`
        Term = SIGTERM,
        /// `SIGCHLD`
        #[doc(alias = "Chld")]
        Child = SIGCHLD,
        /// `SIGCONT`
        Cont = SIGCONT,
        /// `SIGSTOP`
        Stop = SIGSTOP,
        /// `SIGTSTP`
        Tstp = SIGTSTP,
        /// `SIGTTIN`
        Ttin = SIGTTIN,
        /// `SIGTTOU`
        Ttou = SIGTTOU,
        /// `SIGURG`
        Urg = SIGURG,
        /// `SIGXCPU`
        Xcpu = SIGXCPU,
        /// `SIGXFSZ`
        Xfsz = SIGXFSZ,
        /// `SIGVTALRM`
        #[doc(alias = "Vtalrm")]
        Vtalarm = SIGVTALRM,
        /// `SIGPROF`
        Prof = SIGPROF,
        /// `SIGWINCH`
        Winch = SIGWINCH,
        /// `SIGIO`, aka `SIGPOLL`
        #[doc(alias = "Poll")]
        Io = SIGIO,
        /// `SIGSYS`, aka `SIGUNUSED`
        #[doc(alias = "Unused")]
        Sys = SIGSYS,
    }
}

const BUFFER_LEN: usize = mem::size_of::<libc::c_int>();

/// Wait for a specific set of signals.
///
/// See the [module-level documentation](index.html) for more details.
pub struct Signals {
    /// The read end of the signal pipe.
    read: Async<UnixStream>,

    /// The write end of the signal pipe.
    write: UnixStream,

    /// The map between signal numbers and signal IDs.
    signal_ids: HashMap<Signal, SigId>,
}

impl Drop for Signals {
    fn drop(&mut self) {
        for signal in self.signal_ids.values() {
            signal_hook_registry::unregister(*signal);
        }
    }
}

impl fmt::Debug for Signals {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct RegisteredSignals<'a>(&'a HashMap<Signal, SigId>);

        impl fmt::Debug for RegisteredSignals<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_set().entries(self.0.keys()).finish()
            }
        }

        f.debug_struct("Signals")
            .field("read", &self.read)
            .field("write", &self.write)
            .field("signal_ids", &RegisteredSignals(&self.signal_ids))
            .finish()
    }
}

impl Signals {
    /// Create a new `Signals` instance with a set of signals.
    pub fn new<B>(signals: impl IntoIterator<Item = B>) -> io::Result<Self>
    where
        B: Borrow<Signal>,
    {
        // Use another function to avoid monomorphization code bloat.
        let mut this = Self::_new()?;

        // Add the signals to the set of signals to wait for.
        this.add_signals(signals)?;

        Ok(this)
    }

    fn _new() -> io::Result<Self> {
        let (read, write) = UnixStream::pair()?;
        let read = Async::new(read)?;
        write.set_nonblocking(true)?;

        Ok(Self {
            read,
            write,
            signal_ids: HashMap::new(),
        })
    }

    /// Add signals to the set of signals to wait for.
    ///
    /// One signal cannot be added twice. If a signal that has already been added is passed to this
    /// method, it will be ignored.
    ///
    /// Registering a signal prevents the default behavior of that signal from occurring. For
    /// example, if you register `SIGINT`, pressing `Ctrl+C` will no longer terminate the process.
    /// To run the default signal handler, use [`signal_hook::low_level::emulate_default_handler`]
    /// instead.
    ///
    /// [`signal_hook::low_level::emulate_default_handler`]: https://docs.rs/signal-hook/latest/signal_hook/low_level/fn.emulate_default_handler.html
    pub fn add_signals<B>(&mut self, signals: impl IntoIterator<Item = B>) -> io::Result<()>
    where
        B: Borrow<Signal>,
    {
        for signal in signals {
            let signal = signal.borrow();

            // If we've already registered this signal, skip it.
            if self.signal_ids.contains_key(signal) {
                continue;
            }

            // Use `signal-hook-registry` to register the signal.
            let number = signal.number();

            // Duplicate the write end of the signal pipe.
            let write = self.write.try_clone()?;

            let id = unsafe {
                signal_hook_registry::register(number, move || {
                    // SAFETY: to_ne_bytes() and write() are both signal safe
                    let bytes = number.to_ne_bytes();
                    let _ = (&write).write(&bytes);
                })?
            };

            // Add the signal ID to the map.
            self.signal_ids.insert(*signal, id);
        }

        Ok(())
    }

    /// Remove signals from the set of signals to wait for.
    ///
    /// This function can be used to opt out of listening to signals previously registered via
    /// [`add_signals`](Self::add_signals) or [`new`](Self::new). If a signal that has not been
    /// registered is passed to this method, it will be ignored.
    pub fn remove_signals<B>(&mut self, signals: impl IntoIterator<Item = B>) -> io::Result<()>
    where
        B: Borrow<Signal>,
    {
        for signal in signals {
            let signal = signal.borrow();

            // If we haven't registered this signal, skip it.
            let id = match self.signal_ids.remove(signal) {
                Some(id) => id,
                None => continue,
            };

            // Use `signal-hook-registry` to unregister the signal.
            signal_hook_registry::unregister(id);
        }

        Ok(())
    }
}

impl AsRawFd for Signals {
    fn as_raw_fd(&self) -> RawFd {
        self.read.as_raw_fd()
    }
}

#[cfg(not(async_signal_no_io_safety))]
impl AsFd for Signals {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.read.as_fd()
    }
}

impl Unpin for Signals {}

impl Stream for Signals {
    type Item = io::Result<Signal>;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut &*self).poll_next(cx)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        // This stream is expected to never end.
        (std::usize::MAX, None)
    }
}

impl Stream for &Signals {
    type Item = io::Result<Signal>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        let mut buffer = [0; BUFFER_LEN];
        let mut buffer_len = 0;

        // Read into the buffer.
        loop {
            if buffer_len >= BUFFER_LEN {
                break;
            }

            // Try to fill up the entire buffer.
            let buf_range = buffer_len..BUFFER_LEN;
            let res = ready!(Pin::new(&mut &this.read).poll_read(cx, &mut buffer[buf_range]));

            match res {
                Ok(0) => {
                    return Poll::Ready(Some(Err(io::Error::from(io::ErrorKind::UnexpectedEof))))
                }
                Ok(n) => buffer_len += n,
                Err(e) => return Poll::Ready(Some(Err(e))),
            }
        }

        // Convert the buffer into a signal number.
        let number = i32::from_ne_bytes(buffer);

        // Convert the signal number into a signal.
        let signal = match Signal::from_number(number) {
            Some(signal) => signal,
            None => return Poll::Ready(Some(Err(io::Error::from(io::ErrorKind::InvalidData)))),
        };

        // Return the signal.
        Poll::Ready(Some(Ok(signal)))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        // This stream is expected to never end.
        (std::usize::MAX, None)
    }
}
