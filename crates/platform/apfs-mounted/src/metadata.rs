//! Live metadata observations and targeted updates on held Darwin descriptors.

use std::{collections::TryReserveError, error::Error, fmt, io, os::fd::AsFd};

use rustix::fs::{FileType, Mode, Stat, Timespec, Timestamps, fstat, futimens};

mod attributes;
mod security;
mod xattr;

pub use security::{
	ExtendedSecurity, MAX_EXTENDED_SECURITY_BYTES, SecurityGuids, SecurityPayload,
	extended_security, security_guids, set_empty_acl_on_fresh_directory,
};
pub use xattr::{
	FINDER_INFO_BYTES, ResourceFork, XattrVisibility, finder_info, list_xattrs, read_resource_fork,
	read_xattr, resource_fork,
};

const NANOS_PER_SECOND: i64 = 1_000_000_000;

/// A native timestamp normalized to Unix seconds and a nonnegative fraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
	seconds: i64,
	nanoseconds: i64,
}

impl Timestamp {
	/// Constructs a timestamp whose fractional part is below one second.
	#[must_use]
	pub const fn new(seconds: i64, nanoseconds: i64) -> Option<Self> {
		if nanoseconds >= 0 && nanoseconds < NANOS_PER_SECOND {
			Some(Self {
				seconds,
				nanoseconds,
			})
		} else {
			None
		}
	}

	/// Signed seconds since the Unix epoch.
	#[must_use]
	pub const fn seconds(self) -> i64 {
		self.seconds
	}

	/// Fractional nanoseconds within this second.
	#[must_use]
	pub const fn nanoseconds(self) -> i64 {
		self.nanoseconds
	}

	fn capture(seconds: i64, nanoseconds: i64) -> Result<Self, ObservationError> {
		Self::new(seconds, nanoseconds).ok_or(ObservationError::Malformed("timestamp"))
	}

	const fn raw(self) -> Timespec {
		Timespec {
			tv_sec: self.seconds,
			tv_nsec: self.nanoseconds,
		}
	}
}

/// Access and modification times suitable for a descriptor-relative update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessModificationTimes {
	pub access: Timestamp,
	pub modification: Timestamp,
}

impl AccessModificationTimes {
	fn from_stat(stat: &Stat) -> Result<Self, ObservationError> {
		Ok(Self {
			access: Timestamp::capture(stat.st_atime, stat.st_atime_nsec)?,
			modification: Timestamp::capture(stat.st_mtime, stat.st_mtime_nsec)?,
		})
	}
}

/// Basic metadata of one open object at the time of `fstat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Metadata {
	pub file_type: FileType,
	/// Logical length in bytes.
	pub length: u64,
	pub uid: u32,
	pub gid: u32,
	pub mode: Mode,
	pub link_count: u16,
	pub bsd_flags: u32,
	pub times: AccessModificationTimes,
	pub change: Timestamp,
	pub birth: Timestamp,
}

/// Failure to obtain a bounded metadata observation.
#[derive(Debug)]
#[non_exhaustive]
pub enum ObservationError {
	/// The observed byte count exceeded the requested limit.
	Limit {
		limit: usize,
		observed: usize,
	},
	/// The kernel reported a change between a size query and its data read.
	Changed,
	/// The kernel returned an unrecognized or internally inconsistent representation.
	Malformed(&'static str),
	/// The descriptor's filesystem does not implement this query.
	Unsupported(io::Error),
	/// The kernel denied access to the requested observation.
	PermissionDenied(io::Error),
	Io(io::Error),
	Allocation(TryReserveError),
}

impl From<io::Error> for ObservationError {
	fn from(error: io::Error) -> Self {
		match error.raw_os_error() {
			Some(libc::ENOTSUP | libc::EOPNOTSUPP) => Self::Unsupported(error),
			_ if error.kind() == io::ErrorKind::PermissionDenied => Self::PermissionDenied(error),
			_ => Self::Io(error),
		}
	}
}

impl fmt::Display for ObservationError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Limit { limit, observed } => {
				write!(
					formatter,
					"metadata requires {observed} bytes with limit {limit}"
				)
			}
			Self::Changed => formatter.write_str("metadata changed while reading"),
			Self::Malformed(item) => write!(formatter, "invalid Darwin {item} metadata"),
			Self::Unsupported(error) | Self::PermissionDenied(error) | Self::Io(error) => {
				write!(formatter, "metadata observation failed ({error})")
			}
			Self::Allocation(error) => {
				write!(formatter, "metadata buffer allocation failed ({error})")
			}
		}
	}
}

impl Error for ObservationError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Unsupported(error) | Self::PermissionDenied(error) | Self::Io(error) => {
				Some(error)
			}
			Self::Allocation(error) => Some(error),
			_ => None,
		}
	}
}

/// Failure to apply metadata or confirm the resulting state.
#[derive(Debug)]
#[non_exhaustive]
pub enum ApplyError {
	/// The update did not report success.
	Update(io::Error),
	/// The update returned success but the observed result was unavailable.
	ReadBack(ObservationError),
	/// The empty security payload was not confirmed after the update.
	UnexpectedSecurity(ExtendedSecurity),
}

impl fmt::Display for ApplyError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Update(error) => write!(formatter, "metadata update failed ({error})"),
			Self::ReadBack(error) => {
				write!(formatter, "metadata update read-back failed ({error})")
			}
			Self::UnexpectedSecurity(_) => formatter.write_str("empty ACL read-back did not match"),
		}
	}
}

impl Error for ApplyError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Update(error) => Some(error),
			Self::ReadBack(error) => Some(error),
			Self::UnexpectedSecurity(_) => None,
		}
	}
}

/// Observe a held object's basic metadata through `fstat`.
///
/// # Errors
/// Returns an error when the descriptor query fails or the kernel reports
/// a negative length or noncanonical timestamp.
pub fn stat(fd: impl AsFd) -> Result<Metadata, ObservationError> {
	let status = fstat(fd).map_err(io::Error::from)?;
	Ok(Metadata {
		file_type: FileType::from_raw_mode(status.st_mode),
		length: u64::try_from(status.st_size)
			.map_err(|_| ObservationError::Malformed("logical length"))?,
		uid: status.st_uid,
		gid: status.st_gid,
		mode: Mode::from_raw_mode(status.st_mode),
		link_count: status.st_nlink,
		bsd_flags: status.st_flags,
		times: AccessModificationTimes::from_stat(&status)?,
		change: Timestamp::capture(status.st_ctime, status.st_ctime_nsec)?,
		birth: Timestamp::capture(status.st_birthtime, status.st_birthtime_nsec)?,
	})
}

/// Apply access and modification times and return their observed values.
///
/// The caller owns authorization for changing this descriptor's metadata.
/// Compare the returned values to the request whenever exact fidelity matters.
///
/// # Errors
/// Returns the update or read-back failure. A read-back failure occurs after
/// the kernel acknowledged the update.
pub fn set_times(
	fd: impl AsFd,
	times: AccessModificationTimes,
) -> Result<AccessModificationTimes, ApplyError> {
	let fd = fd.as_fd();
	futimens(
		fd,
		&Timestamps {
			last_access: times.access.raw(),
			last_modification: times.modification.raw(),
		},
	)
	.map_err(|error| ApplyError::Update(error.into()))?;
	let status = fstat(fd).map_err(|error| ApplyError::ReadBack(io::Error::from(error).into()))?;
	AccessModificationTimes::from_stat(&status).map_err(ApplyError::ReadBack)
}

#[cfg(test)]
mod tests;
