//! Thread-scoped control of Darwin's automatic dataless file materialization.

use std::{error::Error, fmt, io, marker::PhantomData};

mod darwin;
#[cfg(test)]
mod tests;

/// The materialization setting of a Darwin thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ThreadPolicy {
	/// The thread inherits the process setting.
	Inherited,
	/// The thread opts out of automatic materialization.
	Disabled,
	/// The thread opts into automatic materialization.
	Enabled,
}

/// A native policy could not be read, set, or verified.
#[derive(Debug)]
#[non_exhaustive]
pub enum PolicyError {
	Io(io::Error),
	UnknownPolicy(i32),
	UnexpectedPolicy {
		expected: ThreadPolicy,
		observed: ThreadPolicy,
	},
}

impl fmt::Display for PolicyError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Io(error) => error.fmt(formatter),
			Self::UnknownPolicy(value) => {
				write!(formatter, "unknown Darwin materialization policy {value}")
			}
			Self::UnexpectedPolicy { expected, observed } => write!(
				formatter,
				"expected thread materialization policy {expected:?}, observed {observed:?}"
			),
		}
	}
}

impl Error for PolicyError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Io(error) => Some(error),
			_ => None,
		}
	}
}

/// A failure to establish or restore the thread's materialization scope.
#[non_exhaustive]
pub enum ScopeError<T> {
	/// The operation was skipped. `restoration` records any additional rollback failure.
	Configure {
		error: PolicyError,
		restoration: Option<PolicyError>,
	},
	/// The operation ran. Its complete outcome remains available to the caller.
	Restore { outcome: T, error: PolicyError },
}

impl<T> fmt::Debug for ScopeError<T> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Configure { error, restoration } => formatter
				.debug_struct("Configure")
				.field("error", error)
				.field("restoration", restoration)
				.finish(),
			Self::Restore { error, .. } => formatter
				.debug_struct("Restore")
				.field("error", error)
				.finish_non_exhaustive(),
		}
	}
}

impl<T> fmt::Display for ScopeError<T> {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Configure { error, restoration } => {
				write!(formatter, "could not disable materialization ({error})")?;
				if let Some(restoration) = restoration {
					write!(formatter, ", and policy rollback failed ({restoration})")?;
				}
				Ok(())
			}
			Self::Restore { error, .. } => write!(
				formatter,
				"could not restore thread materialization policy ({error})"
			),
		}
	}
}

impl<T> Error for ScopeError<T> {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		let (Self::Configure { error, .. } | Self::Restore { error, .. }) = self;
		Some(error)
	}
}

/// Failure accessing file data with automatic materialization disabled.
#[derive(Debug)]
#[non_exhaustive]
pub enum ContentError {
	/// Darwin reported that accessing the data would require materialization.
	Unavailable(io::Error),
	Io(io::Error),
}

impl ContentError {
	/// Classify an error from content access under a verified disabled policy.
	///
	/// [Apple TN3150] describes `EDEADLK` for this use. Other failures retain
	/// their original I/O error. Pass only errors from the content operation.
	///
	/// [Apple TN3150]: https://developer.apple.com/documentation/technotes/tn3150-getting-ready-for-data-less-files
	#[must_use]
	pub fn while_materialization_disabled(error: io::Error) -> Self {
		match error.raw_os_error() {
			Some(libc::EDEADLK) => Self::Unavailable(error),
			_ => Self::Io(error),
		}
	}
}

impl fmt::Display for ContentError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Unavailable(_) => {
				formatter.write_str("content unavailable with materialization disabled")
			}
			Self::Io(error) => error.fmt(formatter),
		}
	}
}

impl Error for ContentError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		let (Self::Unavailable(error) | Self::Io(error)) = self;
		Some(error)
	}
}

/// Observe the materialization setting of the calling thread.
///
/// # Errors
/// Returns an error if Darwin rejects the query or reports an unknown value.
pub fn thread_policy() -> Result<ThreadPolicy, PolicyError> {
	darwin::Native.current()
}

/// Run a synchronous operation on the calling thread with automatic
/// materialization disabled.
///
/// The scope applies to file and metadata work performed synchronously by the
/// callback on this thread. The scope restores the exact previous setting on
/// return and attempts restoration on unwind. If restoration errors, drop makes a final
/// best-effort attempt while the error reports the unsuccessful normal return.
///
/// # Errors
/// `Configure` means the callback did not run. `Restore` retains the callback
/// outcome, including any successful filesystem effect or operation error.
pub fn with_materialization_disabled<T>(operation: impl FnOnce() -> T) -> Result<T, ScopeError<T>> {
	with_policy(&darwin::Native, operation)
}

trait PolicyIo {
	fn current(&self) -> Result<ThreadPolicy, PolicyError>;
	fn set(&self, policy: ThreadPolicy) -> Result<(), PolicyError>;
}

fn with_policy<T>(io: &impl PolicyIo, operation: impl FnOnce() -> T) -> Result<T, ScopeError<T>> {
	let previous = io.current().map_err(|error| ScopeError::Configure {
		error,
		restoration: None,
	})?;
	// Arm restoration before setting policy, including when the setter fails.
	let mut guard = RestorePolicy {
		io,
		previous: Some(previous),
		_thread_bound: PhantomData,
	};
	if previous != ThreadPolicy::Disabled
		&& let Err(error) = io
			.set(ThreadPolicy::Disabled)
			.and_then(|()| verify(io, ThreadPolicy::Disabled))
	{
		return Err(ScopeError::Configure {
			error,
			restoration: guard.restore().err(),
		});
	}
	let outcome = operation();
	match guard.restore() {
		Ok(()) => Ok(outcome),
		Err(error) => Err(ScopeError::Restore { outcome, error }),
	}
}

struct RestorePolicy<'scope, I: PolicyIo> {
	io: &'scope I,
	previous: Option<ThreadPolicy>,
	_thread_bound: PhantomData<*const ()>,
}

impl<I: PolicyIo> RestorePolicy<'_, I> {
	fn restore(&mut self) -> Result<(), PolicyError> {
		if let Some(previous) = self.previous {
			if !matches!(self.io.current(), Ok(observed) if observed == previous) {
				self.io.set(previous)?;
				verify(self.io, previous)?;
			}
			self.previous = None;
		}
		Ok(())
	}
}

impl<I: PolicyIo> Drop for RestorePolicy<'_, I> {
	fn drop(&mut self) {
		let _ = self.restore();
	}
}

fn verify(io: &impl PolicyIo, expected: ThreadPolicy) -> Result<(), PolicyError> {
	let observed = io.current()?;
	if observed == expected {
		Ok(())
	} else {
		Err(PolicyError::UnexpectedPolicy { expected, observed })
	}
}
