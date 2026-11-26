//! Exact positioned reads from a selected live file under a held directory.

use std::{
	error, fmt,
	fs::File,
	io,
	os::{fd::AsFd as _, unix::fs::FileExt as _},
};

use rustix::{
	fs::{self, AtFlags, Mode, Stat},
	io::Errno,
};

use crate::{
	Directory, EntryName,
	dataless::{ContentError, PolicyError, ScopeError, with_materialization_disabled},
	identity::{IdentityError, ObjectIdentity},
	lease::{Lease, LeaseError},
	metadata::{MetadataView, ObjectFlags, ObservationError},
	publication::EventEntry,
	stored_name,
};

mod admission;

#[cfg(test)]
mod tests;

/// Upper byte count of one exact positioned read request.
pub const MAX_READ_BYTES: usize = 1 << 20;
const MAX_INTERRUPTED_RETRIES: usize = 16;

/// A normalized timestamp observed during source admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceTimestamp {
	pub seconds: i64,
	pub nanoseconds: u32,
}

impl SourceTimestamp {
	fn from_parts(seconds: i64, nanoseconds: i64) -> Result<Self, SourceError> {
		const NANOS_PER_SECOND: u32 = 1_000_000_000;
		let nanoseconds = u32::try_from(nanoseconds)
			.ok()
			.filter(|nanos| *nanos < NANOS_PER_SECOND)
			.ok_or(SourceError::Unsupported)?;
		Ok(Self {
			seconds,
			nanoseconds,
		})
	}
}

/// Basic metadata observed when selecting a source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceMetadata {
	pub length: u64,
	/// Permission and special mode bits, excluding the file type.
	pub mode: u16,
	pub owner: u32,
	pub group: u32,
	pub link_count: u64,
	pub flags: u32,
	/// Access time before opening the file for data. Ordinary reads may change it.
	pub accessed: SourceTimestamp,
	pub modified: SourceTimestamp,
	pub changed: SourceTimestamp,
}

impl SourceMetadata {
	/// Native flags with typed Darwin queries for known bits.
	#[must_use]
	pub const fn object_flags(self) -> ObjectFlags {
		ObjectFlags::from_raw(self.flags)
	}

	fn from_stat(stat: &Stat) -> Result<Self, SourceError> {
		Ok(Self {
			length: u64::try_from(stat.st_size).map_err(|_| SourceError::Unsupported)?,
			mode: Mode::from_raw_mode(stat.st_mode).as_raw_mode(),
			owner: stat.st_uid,
			group: stat.st_gid,
			link_count: u64::from(stat.st_nlink),
			flags: stat.st_flags,
			accessed: SourceTimestamp::from_parts(stat.st_atime, stat.st_atime_nsec)?,
			modified: SourceTimestamp::from_parts(stat.st_mtime, stat.st_mtime_nsec)?,
			changed: SourceTimestamp::from_parts(stat.st_ctime, stat.st_ctime_nsec)?,
		})
	}
}

/// A rejected source admission, observation, or read.
#[derive(Debug)]
#[non_exhaustive]
pub enum SourceError {
	Missing,
	Unsupported,
	/// The caller's admission rule rejected the named source before data open.
	AdmissionRefused,
	/// The supplied lease covers another directory.
	LeaseMismatch,
	Changed,
	Range {
		offset: u64,
		count: usize,
		length: u64,
	},
	RequestTooLarge {
		count: usize,
	},
	UnexpectedEof,
	ContentUnavailable(io::Error),
	Identity(IdentityError),
	Lease(LeaseError),
	Metadata(ObservationError),
	Io(io::Error),
	PolicyConfigure {
		error: PolicyError,
		restoration: Option<PolicyError>,
	},
	/// A completed observation whose thread policy could not be restored.
	/// `operation` preserves a simultaneous operation error, if there was one.
	PolicyRestore {
		error: PolicyError,
		operation: Option<Box<SourceError>>,
	},
}

impl fmt::Display for SourceError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Missing => formatter.write_str("source name is absent"),
			Self::Unsupported => formatter.write_str("unsupported source file or mount"),
			Self::AdmissionRefused => formatter.write_str("source admission was refused"),
			Self::LeaseMismatch => formatter.write_str("the lease covers another directory"),
			Self::Changed => formatter.write_str("source identity or metadata changed"),
			Self::Range {
				offset,
				count,
				length,
			} => write!(
				formatter,
				"source range {offset} + {count} exceeds length {length}"
			),
			Self::RequestTooLarge { count } => write!(
				formatter,
				"source read of {count} bytes exceeds the {MAX_READ_BYTES}-byte request limit"
			),
			Self::UnexpectedEof => formatter.write_str("source ended before the requested range"),
			Self::ContentUnavailable(_) => {
				formatter.write_str("source content unavailable with materialization disabled")
			}
			Self::Identity(_) => formatter.write_str("source identity observation failed"),
			Self::Lease(_) => formatter.write_str("source lease observation failed"),
			Self::Metadata(_) => formatter.write_str("source metadata observation failed"),
			Self::Io(_) => formatter.write_str("source I/O failed"),
			Self::PolicyConfigure { .. } => {
				formatter.write_str("could not establish the source materialization policy")
			}
			Self::PolicyRestore { .. } => {
				formatter.write_str("could not restore the source materialization policy")
			}
		}
	}
}

impl error::Error for SourceError {
	fn source(&self) -> Option<&(dyn error::Error + 'static)> {
		match self {
			Self::Identity(error) => Some(error),
			Self::Lease(error) => Some(error),
			Self::Metadata(error) => Some(error),
			Self::Io(error) | Self::ContentUnavailable(error) => Some(error),
			Self::PolicyConfigure { error, .. } | Self::PolicyRestore { error, .. } => Some(error),
			_ => None,
		}
	}
}

impl From<Errno> for SourceError {
	fn from(error: Errno) -> Self {
		Self::Io(error.into())
	}
}

impl From<IdentityError> for SourceError {
	fn from(error: IdentityError) -> Self {
		match error {
			IdentityError::Changed => Self::Changed,
			error => Self::Identity(error),
		}
	}
}

/// A selected file bound to a held directory and relative component.
///
/// The caller supplies a controlled namespace throughout the metadata check
/// and readable open. Observations describe live data and depend on the
/// caller's authority and any required cooperation or leasing.
pub struct PinnedSource<'root> {
	root: &'root Directory,
	name: &'root EntryName,
	file: File,
	root_identity: ObjectIdentity,
	identity: ObjectIdentity,
	initial: Stat,
	metadata: SourceMetadata,
	lease: Option<&'root Lease>,
	exact_anchor: Option<&'root EventEntry<'root>>,
}

impl PinnedSource<'_> {
	/// Identity of the held file and the original selected name at admission.
	#[must_use]
	pub const fn identity(&self) -> &ObjectIdentity {
		&self.identity
	}

	/// Identity of the held parent at admission.
	#[must_use]
	pub const fn parent_identity(&self) -> &ObjectIdentity {
		&self.root_identity
	}

	/// Admission metadata revalidated against the held file, with the access
	/// time observed before opening it for data.
	#[must_use]
	pub const fn metadata(&self) -> SourceMetadata {
		self.metadata
	}

	#[must_use]
	pub const fn len(&self) -> u64 {
		self.metadata.length
	}

	#[must_use]
	pub const fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// Recheck the held descriptor, original name, and live metadata stamp.
	///
	/// # Errors
	/// Returns an error for changed evidence, I/O, or a thread policy failure.
	pub fn validate(&self) -> Result<(), SourceError> {
		under_policy(|| self.validate_state())
	}

	/// Run bounded metadata queries against this pinned descriptor.
	///
	/// The read-only view is confined to the callback. The descriptor, name
	/// and any supplied lease are checked before and after the observation
	/// with materialization disabled. Access time in the view is live.
	/// # Errors
	/// Returns an error for changed evidence, a failed metadata query, or a
	/// thread policy failure.
	pub fn with_metadata<T>(
		&self,
		observe: impl FnOnce(MetadataView<'_>) -> Result<T, ObservationError>,
	) -> Result<T, SourceError> {
		under_policy(|| {
			self.validate_state()?;
			let outcome = observe(MetadataView::new(self.file.as_fd()));
			self.validate_state()?;
			outcome.map_err(SourceError::Metadata)
		})
	}

	/// Read exactly the requested bytes from the captured extent.
	///
	/// # Errors
	/// Returns an error for a request outside the admitted bounds, unexpected
	/// EOF, stale evidence, unavailable content, or I/O or policy failure.
	/// Discard the buffer on any error.
	pub fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), SourceError> {
		if buffer.len() > MAX_READ_BYTES {
			return Err(SourceError::RequestTooLarge {
				count: buffer.len(),
			});
		}
		if offset
			.checked_add(buffer.len() as u64)
			.is_none_or(|end| end > self.len())
		{
			return Err(SourceError::Range {
				offset,
				count: buffer.len(),
				length: self.len(),
			});
		}
		under_policy(|| {
			self.validate_state()?;
			let outcome = read_positioned_exact(&self.file, offset, buffer).map_err(content_error);
			self.validate_state()?;
			outcome
		})
	}

	/// Revalidate the live identity and probe EOF at the captured length.
	///
	/// # Errors
	/// Returns an error for changed evidence, unavailable content, unexpected
	/// bytes beyond the captured extent, or I/O or policy failure.
	pub fn revalidate(&self) -> Result<(), SourceError> {
		under_policy(|| {
			self.validate_state()?;
			let outcome = read_positioned(&self.file, self.len(), &mut [0]).map_err(content_error);
			self.validate_state()?;
			if outcome? != 0 {
				return Err(SourceError::Changed);
			}
			Ok(())
		})
	}

	fn validate_state(&self) -> Result<(), SourceError> {
		admission::validate_lease(self.lease, self.root_identity)?;
		self.root_identity.revalidate_held(self.root)?;
		self.identity.revalidate_held(&self.file)?;
		self.identity.revalidate_named(self.root, self.name)?;
		validate_exact_anchor(self.exact_anchor, self.name, self.identity)?;
		let held = fs::fstat(&self.file)?;
		let named = stat_name(self.root, self.name)?.ok_or(SourceError::Changed)?;
		if !same_stamp(&held, &self.initial) || !same_stamp(&named, &self.initial) {
			return Err(SourceError::Changed);
		}
		Ok(())
	}
}

fn validate_exact_anchor(
	anchor: Option<&EventEntry<'_>>,
	name: &EntryName,
	identity: ObjectIdentity,
) -> Result<(), SourceError> {
	if let Some(anchor) = anchor {
		if *anchor.identity() != identity {
			return Err(SourceError::Changed);
		}
		identity.revalidate_held(anchor.handle())?;
		if stored_name(anchor.handle()).map_err(SourceError::Io)? != *name {
			return Err(SourceError::Changed);
		}
	}
	Ok(())
}

fn stat_name(root: &Directory, name: &EntryName) -> Result<Option<Stat>, SourceError> {
	match fs::statat(root, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
		Ok(stat) => Ok(Some(stat)),
		Err(Errno::NOENT) => Ok(None),
		Err(error) => Err(error.into()),
	}
}

fn same_stamp(current: &Stat, initial: &Stat) -> bool {
	current.st_dev == initial.st_dev
		&& current.st_ino == initial.st_ino
		&& current.st_gen == initial.st_gen
		&& current.st_birthtime == initial.st_birthtime
		&& current.st_birthtime_nsec == initial.st_birthtime_nsec
		&& current.st_mode == initial.st_mode
		&& current.st_uid == initial.st_uid
		&& current.st_gid == initial.st_gid
		&& current.st_nlink == initial.st_nlink
		&& current.st_flags == initial.st_flags
		&& current.st_size == initial.st_size
		&& current.st_ctime == initial.st_ctime
		&& current.st_ctime_nsec == initial.st_ctime_nsec
		&& current.st_mtime == initial.st_mtime
		&& current.st_mtime_nsec == initial.st_mtime_nsec
}

fn under_policy<T>(operation: impl FnOnce() -> Result<T, SourceError>) -> Result<T, SourceError> {
	match with_materialization_disabled(operation) {
		Ok(outcome) => outcome,
		Err(ScopeError::Configure { error, restoration }) => {
			Err(SourceError::PolicyConfigure { error, restoration })
		}
		Err(ScopeError::Restore { outcome, error }) => Err(SourceError::PolicyRestore {
			error,
			operation: outcome.err().map(Box::new),
		}),
	}
}

fn content_error(error: io::Error) -> SourceError {
	match ContentError::while_materialization_disabled(error) {
		ContentError::Unavailable(error) => SourceError::ContentUnavailable(error),
		ContentError::Io(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
			SourceError::UnexpectedEof
		}
		ContentError::Io(error) => SourceError::Io(error),
	}
}

pub(crate) fn read_positioned(file: &File, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
	if offset > i64::MAX as u64 || buffer.len() > MAX_READ_BYTES {
		return Err(io::ErrorKind::InvalidInput.into());
	}
	retry_interrupted(|| file.read_at(buffer, offset))
}

pub(crate) fn read_positioned_exact(file: &File, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
	if buffer.len() > MAX_READ_BYTES {
		return Err(io::ErrorKind::InvalidInput.into());
	}
	read_exact_loop(offset, buffer, |position, unread| {
		file.read_at(unread, position)
	})
}

fn read_exact_loop(
	mut offset: u64,
	mut buffer: &mut [u8],
	mut read: impl FnMut(u64, &mut [u8]) -> io::Result<usize>,
) -> io::Result<()> {
	if offset
		.checked_add(buffer.len() as u64)
		.is_none_or(|end| end > i64::MAX as u64)
	{
		return Err(io::ErrorKind::InvalidInput.into());
	}
	while !buffer.is_empty() {
		let count = retry_interrupted(|| read(offset, buffer))?;
		if count == 0 {
			return Err(io::ErrorKind::UnexpectedEof.into());
		}
		buffer = buffer.get_mut(count..).ok_or(io::ErrorKind::InvalidData)?;
		offset += count as u64;
	}
	Ok(())
}

fn retry_interrupted<T>(mut operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
	let mut retries = MAX_INTERRUPTED_RETRIES;
	loop {
		match operation() {
			Err(error) if error.kind() == io::ErrorKind::Interrupted && retries > 0 => retries -= 1,
			outcome => return outcome,
		}
	}
}
