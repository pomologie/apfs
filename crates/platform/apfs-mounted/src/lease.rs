//! Nonblocking Darwin advisory leases on independently opened directories.

use std::{error, fmt, io, os::fd::OwnedFd, process};

use rustix::{
	fs::{self, FlockOperation, Mode, OFlags},
	io::Errno,
};

use crate::{
	Directory, EntryName,
	identity::{IdentityError, ObjectIdentity},
};

#[cfg(test)]
mod tests;

const DIRECTORY_OPEN: OFlags = OFlags::RDONLY
	.union(OFlags::DIRECTORY)
	.union(OFlags::NOFOLLOW)
	.union(OFlags::CLOEXEC);
const HELD_DIRECTORY_ENTRY: &std::ffi::CStr = c".";

/// The advisory lock selected for an acquisition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseMode {
	Shared,
	Exclusive,
}

/// The outcome of a nonblocking advisory lock request.
#[derive(Debug)]
#[must_use = "an acquired lease is held only while its owner remains alive"]
pub enum LeaseAttempt {
	Acquired(Lease),
	Busy,
}

/// A failure opening, checking, locking, or unlocking a directory.
#[derive(Debug)]
#[non_exhaustive]
pub enum LeaseError {
	Identity(IdentityError),
	WrongProcess,
	Io(io::Error),
}

impl fmt::Display for LeaseError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Identity(error) => {
				write!(formatter, "could not verify the leased directory: {error}")
			}
			Self::WrongProcess => {
				formatter.write_str("the advisory lease belongs to another process")
			}
			Self::Io(error) => error.fmt(formatter),
		}
	}
}

impl error::Error for LeaseError {
	fn source(&self) -> Option<&(dyn error::Error + 'static)> {
		match self {
			Self::Identity(error) => Some(error),
			Self::Io(error) => Some(error),
			Self::WrongProcess => None,
		}
	}
}

impl From<IdentityError> for LeaseError {
	fn from(error: IdentityError) -> Self {
		Self::Identity(error)
	}
}

impl From<Errno> for LeaseError {
	fn from(error: Errno) -> Self {
		Self::Io(error.into())
	}
}

impl From<io::Error> for LeaseError {
	fn from(error: io::Error) -> Self {
		Self::Io(error)
	}
}

/// A live, process-owned advisory lease.
///
/// The lock coordinates cooperating writers. The directory remains a live
/// namespace. Use an already authorized directory on a filesystem with the
/// required advisory-lock semantics.
///
/// Each acquisition has its own close-on-exec open file description. The
/// descriptor stays private, and there is no in-place lock conversion. After
/// a fork, only the acquiring process may explicitly unlock it.
pub struct Lease {
	file: OwnedFd,
	binding: Binding,
	identity: ObjectIdentity,
	mode: LeaseMode,
	process: u32,
	unlock_on_drop: bool,
}

enum Binding {
	Held,
	Named { parent: Directory, name: EntryName },
}

impl Lease {
	/// Acquire a lease on a directory that is already held and authorized.
	/// Renaming its original path does not change the held binding.
	///
	/// # Errors
	/// Returns identity or system errors when the lease cannot be acquired.
	/// Contention is reported as [`LeaseAttempt::Busy`].
	pub fn try_acquire(directory: &Directory, mode: LeaseMode) -> Result<LeaseAttempt, LeaseError> {
		let identity = ObjectIdentity::held(directory)?;
		let file = fs::openat(
			directory,
			HELD_DIRECTORY_ENTRY,
			DIRECTORY_OPEN,
			Mode::empty(),
		)?;
		identity.revalidate_held(&file)?;
		Self::acquire(file, identity, Binding::Held, mode)
	}

	/// Acquire a lease on one child directory without following a final symlink.
	/// The lease retains an independently opened parent for revalidation of
	/// the exact relative name, even after the caller drops its handle.
	///
	/// # Errors
	/// Returns identity or system errors, including when the child is absent,
	/// is a symlink, or is rebound during acquisition. Contention is reported
	/// as [`LeaseAttempt::Busy`].
	pub fn try_acquire_named(
		parent: &Directory,
		name: &EntryName,
		mode: LeaseMode,
	) -> Result<LeaseAttempt, LeaseError> {
		let parent = Directory::from_owned_fd(fs::openat(
			parent,
			HELD_DIRECTORY_ENTRY,
			DIRECTORY_OPEN,
			Mode::empty(),
		)?)?;
		let file = fs::openat(&parent, name.as_c_str(), DIRECTORY_OPEN, Mode::empty())?;
		let identity = ObjectIdentity::held(&file)?;
		let binding = Binding::Named {
			parent,
			name: name.clone(),
		};
		binding.revalidate(&identity)?;
		Self::acquire(file, identity, binding, mode)
	}

	/// The identity captured at acquisition. Use [`Self::revalidate`] to
	/// check the current binding before a dependent operation.
	#[must_use]
	pub const fn identity(&self) -> &ObjectIdentity {
		&self.identity
	}

	/// The mode selected at acquisition.
	#[must_use]
	pub const fn mode(&self) -> LeaseMode {
		self.mode
	}

	/// Revalidate the pinned descriptor and its original binding.
	///
	/// # Errors
	/// Fails if used from an inherited process or if the kernel cannot
	/// confirm the held object and its binding.
	pub fn revalidate(&self) -> Result<(), LeaseError> {
		self.check_process()?;
		self.identity.revalidate_held(&self.file)?;
		Ok(self.binding.revalidate(&self.identity)?)
	}

	/// Consume the lease and return the explicit unlock result.
	/// Dropping a lease instead attempts unlock without reporting the result.
	///
	/// # Errors
	/// Fails for an inherited process or a failed unlock. The descriptor is
	/// closed after the attempt. If the open file description is still
	/// inherited elsewhere, a failed unlock does not establish release.
	pub fn release(mut self) -> Result<(), LeaseError> {
		self.check_process()?;
		self.unlock_on_drop = false;
		Ok(fs::flock(&self.file, FlockOperation::Unlock)?)
	}

	fn acquire(
		file: OwnedFd,
		identity: ObjectIdentity,
		binding: Binding,
		mode: LeaseMode,
	) -> Result<LeaseAttempt, LeaseError> {
		let operation = match mode {
			LeaseMode::Shared => FlockOperation::NonBlockingLockShared,
			LeaseMode::Exclusive => FlockOperation::NonBlockingLockExclusive,
		};
		match fs::flock(&file, operation) {
			Ok(()) => {}
			Err(Errno::AGAIN) => {
				identity.revalidate_held(&file)?;
				binding.revalidate(&identity)?;
				return Ok(LeaseAttempt::Busy);
			}
			Err(error) => return Err(error.into()),
		}
		let lease = Self {
			file,
			binding,
			identity,
			mode,
			process: process::id(),
			unlock_on_drop: true,
		};
		lease.revalidate()?;
		Ok(LeaseAttempt::Acquired(lease))
	}

	fn check_process(&self) -> Result<(), LeaseError> {
		if process::id() != self.process {
			return Err(LeaseError::WrongProcess);
		}
		Ok(())
	}
}

impl Binding {
	fn revalidate(&self, identity: &ObjectIdentity) -> Result<(), IdentityError> {
		match self {
			Self::Held => Ok(()),
			Self::Named { parent, name } => identity.revalidate_named(parent, name),
		}
	}
}

impl fmt::Debug for Lease {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("Lease")
			.field("mode", &self.mode)
			.finish_non_exhaustive()
	}
}

impl Drop for Lease {
	fn drop(&mut self) {
		if self.unlock_on_drop && self.check_process().is_ok() {
			let _ = fs::flock(&self.file, FlockOperation::Unlock);
		}
	}
}
