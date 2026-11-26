//! Live mounted object identities from held descriptors and relative names.

use std::{
	fmt, io,
	num::{NonZeroU32, NonZeroU64},
	os::fd::AsFd,
};

use rustix::{
	fs::{self, AtFlags, Stat},
	io::Errno,
};

use crate::{Directory, EntryName};

mod native;
#[cfg(test)]
mod tests;

const NO_DEVICE: i32 = -1;
const NANOS_PER_SECOND: u32 = 1_000_000_000;

/// A normalized Darwin birth-time observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BirthTime {
	seconds: i64,
	nanoseconds: u32,
}

impl BirthTime {
	fn from_stat(stat: &Stat) -> Result<Self, IdentityError> {
		let nanoseconds = u32::try_from(stat.st_birthtime_nsec)
			.ok()
			.filter(|&value| value < NANOS_PER_SECOND)
			.ok_or(IdentityError::Unavailable)?;
		Ok(Self {
			seconds: stat.st_birthtime,
			nanoseconds,
		})
	}

	/// Whole seconds relative to the Unix epoch.
	#[must_use]
	pub const fn seconds(self) -> i64 {
		self.seconds
	}

	/// Fractional nanoseconds within the second.
	#[must_use]
	pub const fn nanoseconds(self) -> u32 {
		self.nanoseconds
	}
}

/// Native device and real filesystem ID observed on a live mount.
/// Acquire fresh observations after reopening a mount.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountIdentity {
	device: i32,
	physical_fsid: [u32; 2],
}

impl MountIdentity {
	/// Signed device value from Darwin `stat`.
	#[must_use]
	pub const fn device(self) -> i32 {
		self.device
	}

	/// The ordered words returned for the physical volume's filesystem ID.
	#[must_use]
	pub const fn physical_fsid(self) -> [u32; 2] {
		self.physical_fsid
	}
}

/// Live identity evidence for a mounted object.
///
/// Equality compares the observed device, real filesystem ID, inode,
/// available generation and birth time. Read or write operations need their
/// own metadata and content checks. Reopening requires fresh authority and
/// observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectIdentity {
	mount: MountIdentity,
	inode: NonZeroU64,
	generation: Option<NonZeroU32>,
	birth: BirthTime,
}

impl ObjectIdentity {
	/// Observes the object referenced by an already held descriptor.
	///
	/// # Errors
	/// Returns an error for unavailable evidence, changed observations or a
	/// failed descriptor query.
	pub fn held(fd: impl AsFd) -> Result<Self, IdentityError> {
		Self::held_with_stat(fd).map(|(identity, _)| identity)
	}

	pub(crate) fn held_with_stat(fd: impl AsFd) -> Result<(Self, Stat), IdentityError> {
		let fd = fd.as_fd();
		let before = fs::fstat(fd)?;
		let real = native::held(fd)?;
		let after = fs::fstat(fd)?;
		Self::checked(&before, real, &after).map(|identity| (identity, after))
	}

	/// Observes a single relative entry without following a final symbolic link
	/// or opening the entry's payload. `None` indicates absence at first lookup.
	///
	/// # Errors
	/// Returns an error for unavailable evidence, a change during the lookup
	/// or a failed native metadata query.
	pub fn named(parent: &Directory, name: &EntryName) -> Result<Option<Self>, IdentityError> {
		Self::named_with_stat(parent, name).map(|entry| entry.map(|(identity, _)| identity))
	}

	pub(crate) fn named_with_stat(
		parent: &Directory,
		name: &EntryName,
	) -> Result<Option<(Self, Stat)>, IdentityError> {
		let parent = parent.as_fd();
		let name = name.as_c_str();
		let before = match fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
			Ok(stat) => stat,
			Err(Errno::NOENT) => return Ok(None),
			Err(error) => return Err(error.into()),
		};
		let real = match native::named(parent, name) {
			Err(IdentityError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
				return Err(IdentityError::Changed);
			}
			result => result?,
		};
		let after = match fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
			Ok(stat) => stat,
			Err(Errno::NOENT) => return Err(IdentityError::Changed),
			Err(error) => return Err(error.into()),
		};
		Self::checked(&before, real, &after).map(|identity| Some((identity, after)))
	}

	/// Compares a fresh held-object observation to this identity.
	///
	/// # Errors
	/// Returns [`IdentityError::Changed`] for a different identity and retains
	/// any observation error.
	pub fn revalidate_held(self, fd: impl AsFd) -> Result<(), IdentityError> {
		self.require(Some(Self::held(fd)?))
	}

	/// Rechecks an authorized relative name against this identity.
	///
	/// # Errors
	/// Returns [`IdentityError::Changed`] if the name is absent or resolves to
	/// a different identity and retains any observation error.
	pub fn revalidate_named(
		self,
		parent: &Directory,
		name: &EntryName,
	) -> Result<(), IdentityError> {
		self.require(Self::named(parent, name)?)
	}

	fn require(self, current: Option<Self>) -> Result<(), IdentityError> {
		if current == Some(self) {
			Ok(())
		} else {
			Err(IdentityError::Changed)
		}
	}

	fn checked(
		before: &Stat,
		real: native::RealIdentity,
		after: &Stat,
	) -> Result<Self, IdentityError> {
		let observed = Self::from_stat(before, real)?;
		observed.require(Some(Self::from_stat(after, real)?))?;
		Ok(observed)
	}

	fn from_stat(stat: &Stat, real: native::RealIdentity) -> Result<Self, IdentityError> {
		let device = stat.st_dev;
		if device == 0 || device == NO_DEVICE {
			return Err(IdentityError::Unavailable);
		}
		let inode = NonZeroU64::new(stat.st_ino).ok_or(IdentityError::Unavailable)?;
		if inode != real.inode {
			return Err(IdentityError::Changed);
		}
		Ok(Self {
			mount: MountIdentity {
				device,
				physical_fsid: real.physical_fsid,
			},
			inode,
			generation: NonZeroU32::new(stat.st_gen),
			birth: BirthTime::from_stat(stat)?,
		})
	}

	/// Device and real filesystem ID for the observed mount.
	#[must_use]
	pub const fn mount(self) -> MountIdentity {
		self.mount
	}

	/// Signed device value for the held or named object.
	#[must_use]
	pub const fn device(self) -> i32 {
		self.mount.device()
	}

	/// The ordered native words of the real filesystem ID.
	#[must_use]
	pub const fn physical_fsid(self) -> [u32; 2] {
		self.mount.physical_fsid()
	}

	/// Native inode observed within the mount.
	#[must_use]
	pub const fn inode(self) -> NonZeroU64 {
		self.inode
	}

	/// Native generation, when Darwin returned a nonzero value.
	#[must_use]
	pub const fn generation(self) -> Option<NonZeroU32> {
		self.generation
	}

	/// Normalized birth time associated with the observed inode.
	#[must_use]
	pub const fn birth(self) -> BirthTime {
		self.birth
	}
}

/// A mounted identity could not be obtained or revalidated.
#[derive(Debug)]
#[non_exhaustive]
pub enum IdentityError {
	/// Darwin did not supply the complete required evidence.
	Unavailable,
	/// A held object or named entry no longer matched the observation.
	Changed,
	/// A native metadata query failed.
	Io(io::Error),
}

impl fmt::Display for IdentityError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Unavailable => f.write_str("mounted object identity is unavailable"),
			Self::Changed => f.write_str("mounted object identity changed"),
			Self::Io(error) => write!(f, "mounted object identity query failed ({error})"),
		}
	}
}

impl std::error::Error for IdentityError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Io(error) => Some(error),
			_ => None,
		}
	}
}

impl From<Errno> for IdentityError {
	fn from(error: Errno) -> Self {
		Self::Io(error.into())
	}
}
