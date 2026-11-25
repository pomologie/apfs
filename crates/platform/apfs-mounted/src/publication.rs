//! Namespace observations, exclusive rename, and directory barriers.

use std::{error, fmt, io, os::fd::AsFd};

use rustix::{
	fs::{self, AtFlags, RenameFlags},
	io::Errno,
};

use crate::{
	Directory, EntryName, EventHandle,
	identity::{IdentityError, ObjectIdentity},
	writer::{BarrierError, sync_directory},
};

// Darwin <sys/stdio.h>. rustix 1.1.6 forwards retained bits to renameatx_np.
const RENAME_NOFOLLOW_ANY: RenameFlags = RenameFlags::from_bits_retain(0x0000_0010);

/// Live metadata observed for a name beneath a held directory.
#[derive(Debug)]
#[non_exhaustive]
pub enum EntryObservation {
	Absent,
	Present(ObjectIdentity),
	Inconclusive(IdentityError),
}

/// Inspect one selected name without following symlinks or opening its payload.
///
/// An initially missing name is absent. A change during the observation or
/// unavailable identity evidence is inconclusive. Repeat after reopening a
/// directory to obtain a fresh observation.
pub fn inventory(directory: &Directory, name: &EntryName) -> EntryObservation {
	match ObjectIdentity::named(directory, name) {
		Ok(Some(identity)) => EntryObservation::Present(identity),
		Ok(None) => EntryObservation::Absent,
		Err(error) => EntryObservation::Inconclusive(error),
	}
}

/// A held event-only anchor tied to a particular live name.
#[derive(Debug)]
pub struct EventEntry<'location> {
	directory: &'location Directory,
	name: &'location EntryName,
	file: EventHandle,
	identity: ObjectIdentity,
}

impl EventEntry<'_> {
	/// Returns the identity originally captured for this anchor.
	#[must_use]
	pub const fn identity(&self) -> &ObjectIdentity {
		&self.identity
	}

	/// Check the event descriptor and the relative name against its identity.
	/// # Errors
	/// Fails on a changed binding, unavailable evidence, or inspection failure.
	pub fn revalidate(&self) -> Result<(), IdentityError> {
		self.identity.revalidate_held(&self.file)?;
		self.identity.revalidate_named(self.directory, self.name)
	}
}

/// Failure when establishing an event-only identity anchor.
#[derive(Debug)]
#[non_exhaustive]
pub enum AnchorError {
	Identity(IdentityError),
	Open(io::Error),
}

impl fmt::Display for AnchorError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::Identity(_) => "could not establish the event entry identity",
			Self::Open(_) => "could not open the event entry",
		})
	}
}

impl error::Error for AnchorError {
	fn source(&self) -> Option<&(dyn error::Error + 'static)> {
		Some(match self {
			Self::Identity(error) => error,
			Self::Open(error) => error,
		})
	}
}

/// Open an event-only anchor relative to the held directory.
///
/// Returns `None` for initial absence. The anchor has no payload operations.
/// # Errors
/// A symlink, failed open, or mismatched identity returns an error. A name
/// disappearing between lookup and open also returns an error.
pub fn pin_entry<'location>(
	directory: &'location Directory,
	name: &'location EntryName,
) -> Result<Option<EventEntry<'location>>, AnchorError> {
	let Some(identity) = ObjectIdentity::named(directory, name).map_err(AnchorError::Identity)?
	else {
		return Ok(None);
	};
	let file = directory.open_event(name).map_err(AnchorError::Open)?;
	let entry = EventEntry {
		directory,
		name,
		file,
		identity,
	};
	entry.revalidate().map_err(AnchorError::Identity)?;
	Ok(Some(entry))
}

/// A preflight failure that prevented calling the rename primitive.
#[derive(Debug)]
#[non_exhaustive]
pub enum RenameRejection {
	HeldObject(IdentityError),
	SourceName(IdentityError),
	DestinationName(io::Error),
}

impl fmt::Display for RenameRejection {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::HeldObject(_) => "held stage identity revalidation failed",
			Self::SourceName(_) => "private source name revalidation failed",
			Self::DestinationName(_) => "public destination lookup failed",
		})
	}
}

impl error::Error for RenameRejection {
	fn source(&self) -> Option<&(dyn error::Error + 'static)> {
		Some(match self {
			Self::HeldObject(error) | Self::SourceName(error) => error,
			Self::DestinationName(error) => error,
		})
	}
}

/// The result of an exclusive name transition.
#[derive(Debug)]
#[non_exhaustive]
pub enum RenameOutcome {
	/// Preconditions could not be established before the rename call.
	NotAttempted(RenameRejection),
	/// The destination was occupied. The caller retains the source stage.
	Conflict,
	/// The rename call returned a failure whose effect requires reconciliation.
	Uncertain(io::Error),
	/// The rename call returned success. Inspect its separate evidence.
	Renamed(RenameEvidence),
}

/// Independent evidence after the kernel reports a successful rename.
#[derive(Debug)]
#[non_exhaustive]
pub enum RenameEvidence {
	/// The held object and public name matched and the former name was absent.
	Confirmed { target: ObjectIdentity },
	/// At least one post-rename condition remains unconfirmed.
	Incomplete {
		held: Result<(), IdentityError>,
		former_source: EntryObservation,
		destination: EntryObservation,
	},
}

/// Publish the held stage with one Darwin exclusive no-follow rename.
///
/// Supply the expected live identity of the already-held stage and a source
/// binding protected by the caller's cooperating-writer leases. The caller
/// owns filesystem capability admission, publication authorization, and
/// thread materialization policy. An occupied name, including a case alias,
/// produces a conflict. A racing arrival is handled by the kernel's exclusive
/// flag. Successful rename, post-rename identity evidence, and directory
/// synchronization are separate results.
///
/// Preserve the recorded observations after an uncertain or incomplete result.
/// Reconciliation and further mutations are caller decisions.
pub fn exclusive_rename(
	source: &Directory,
	source_name: &EntryName,
	destination: &Directory,
	destination_name: &EntryName,
	held: impl AsFd,
	expected: &ObjectIdentity,
) -> RenameOutcome {
	if let Err(error) = expected.revalidate_held(held.as_fd()) {
		return RenameOutcome::NotAttempted(RenameRejection::HeldObject(error));
	}
	if let Err(error) = expected.revalidate_named(source, source_name) {
		return RenameOutcome::NotAttempted(RenameRejection::SourceName(error));
	}
	match fs::statat(
		destination,
		destination_name.as_c_str(),
		AtFlags::SYMLINK_NOFOLLOW,
	) {
		Ok(_) => return RenameOutcome::Conflict,
		Err(Errno::NOENT) => {}
		Err(error) => {
			return RenameOutcome::NotAttempted(RenameRejection::DestinationName(error.into()));
		}
	}

	let result = rename_native(source, source_name, destination, destination_name);
	classify_rename(result, || {
		check_evidence(
			expected,
			expected.revalidate_held(held.as_fd()),
			inventory(source, source_name),
			inventory(destination, destination_name),
		)
	})
}

fn rename_native(
	source: &Directory,
	source_name: &EntryName,
	destination: &Directory,
	destination_name: &EntryName,
) -> rustix::io::Result<()> {
	fs::renameat_with(
		source,
		source_name.as_c_str(),
		destination,
		destination_name.as_c_str(),
		RenameFlags::NOREPLACE | RENAME_NOFOLLOW_ANY,
	)
}

fn classify_rename(
	result: rustix::io::Result<()>,
	observe: impl FnOnce() -> RenameEvidence,
) -> RenameOutcome {
	match result {
		Ok(()) => RenameOutcome::Renamed(observe()),
		Err(Errno::EXIST) => RenameOutcome::Conflict,
		Err(error) => RenameOutcome::Uncertain(error.into()),
	}
}

fn check_evidence(
	expected: &ObjectIdentity,
	held: Result<(), IdentityError>,
	former_source: EntryObservation,
	destination: EntryObservation,
) -> RenameEvidence {
	match (held, former_source, destination) {
		(Ok(()), EntryObservation::Absent, EntryObservation::Present(target))
			if expected == &target =>
		{
			RenameEvidence::Confirmed { target }
		}
		(held, former_source, destination) => RenameEvidence::Incomplete {
			held,
			former_source,
			destination,
		},
	}
}

/// Results of both affected directory synchronization calls.
#[derive(Debug)]
pub struct DirectoryBarriers {
	pub source: Result<(), BarrierError>,
	pub destination: Result<(), BarrierError>,
}

/// Synchronize both held directory handles and retain each result.
///
/// Each call runs even if the other fails. The caller chooses when to request
/// these barriers. Hardware power-loss behavior requires separate evidence.
pub fn sync_directories(source: &Directory, destination: &Directory) -> DirectoryBarriers {
	sync_both(|| sync_directory(source), || sync_directory(destination))
}

fn sync_both(
	source: impl FnOnce() -> Result<(), BarrierError>,
	destination: impl FnOnce() -> Result<(), BarrierError>,
) -> DirectoryBarriers {
	DirectoryBarriers {
		source: source(),
		destination: destination(),
	}
}

#[cfg(test)]
mod tests;
