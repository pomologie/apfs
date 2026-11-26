//! Namespace observations, exclusive rename, and directory barriers.

use std::{
	error, fmt, io,
	os::fd::{AsFd, BorrowedFd},
};

use rustix::{
	fs::{self, AtFlags, RenameFlags},
	io::Errno,
};

use crate::{
	Directory, EntryName, EventHandle,
	identity::{IdentityError, ObjectIdentity},
	writer::{BarrierError, sync_directory},
};

pub(crate) mod observation;

pub use observation::{EntrySnapshot, EntrySnapshotError, EntrySpelling};

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

impl<'location> EventEntry<'location> {
	pub(crate) const fn location(&self) -> (&'location Directory, &'location EntryName) {
		(self.directory, self.name)
	}

	pub(crate) const fn handle(&self) -> &EventHandle {
		&self.file
	}

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

/// The result of attempting one kernel no-clobber rename.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub enum RenameAttempt<'binding> {
	/// Source or held identity checks refused the operation before the call.
	NotAttempted(RenameRejection),
	/// The kernel reported that the destination already exists.
	Conflict,
	/// The rename returned an error and its effect requires reconciliation.
	Uncertain(io::Error),
	/// The kernel reported success. Barriers and observations are still separate.
	Renamed(RenamedEntry<'binding>),
}

/// A successful rename call with the original descriptor and name bindings.
#[derive(Debug)]
#[must_use]
pub struct RenamedEntry<'binding> {
	source: &'binding Directory,
	source_name: &'binding EntryName,
	destination: &'binding Directory,
	destination_name: &'binding EntryName,
	held: BorrowedFd<'binding>,
	expected: &'binding ObjectIdentity,
}

impl RenamedEntry<'_> {
	/// Sample the held identity, former-name absence, and destination identity.
	///
	/// To collect post-barrier evidence, call this after attempting the required
	/// directory barriers. Callers may also sample their own metadata and lease
	/// evidence after those barriers.
	pub fn observe(&self) -> RenameEvidence {
		check_evidence(
			self.expected,
			self.expected.revalidate_held(self.held),
			inventory(self.source, self.source_name),
			inventory(self.destination, self.destination_name),
		)
	}
}

/// Revalidate the source binding and attempt one Darwin exclusive no-follow rename.
///
/// The kernel makes the destination occupancy decision. This operation returns
/// directly after the call and leaves directory synchronization and later
/// observations to the caller. For a cross-directory transition, use
/// [`sync_directories`] to retain both barrier results, then call
/// [`RenamedEntry::observe`]. For a same-directory promotion, synchronize that
/// directory once with [`sync_directory`].
///
/// The caller owns durable intent, capability and materialization checks, and
/// authorization. Protect the source binding throughout with cooperating-writer
/// leases. Preserve uncertain results for reconciliation before further mutation.
pub fn attempt_exclusive_rename<'binding>(
	source: &'binding Directory,
	source_name: &'binding EntryName,
	destination: &'binding Directory,
	destination_name: &'binding EntryName,
	held: &'binding impl AsFd,
	expected: &'binding ObjectIdentity,
) -> RenameAttempt<'binding> {
	let held = held.as_fd();
	if let Err(rejection) = validate_rename_source(source, source_name, held, expected) {
		return RenameAttempt::NotAttempted(rejection);
	}
	rename_once(
		source,
		source_name,
		destination,
		destination_name,
		held,
		expected,
	)
}

/// Revalidate the source, acquire a caller guard, then attempt the exclusive rename.
///
/// `authorize` runs only after the native held and named identity probes pass.
/// Its guard stays live through the one no-clobber, no-follow syscall and is
/// released before this function returns. There are no intervening filesystem
/// probes or destination prelookup after `authorize` succeeds. The caller owns
/// the grant, any deadline check at submission, durable intent, and barriers.
/// A revocation guard does not extend a deadline or bound syscall duration.
/// Protect the source binding throughout with cooperating-writer leases.
///
/// # Errors
/// Returns the caller's authorization error without attempting the syscall.
/// Native preflight failures and syscall results remain distinct [`RenameAttempt`] values.
pub fn attempt_exclusive_rename_checked<'binding, G, E>(
	source: &'binding Directory,
	source_name: &'binding EntryName,
	destination: &'binding Directory,
	destination_name: &'binding EntryName,
	held: &'binding impl AsFd,
	expected: &'binding ObjectIdentity,
	authorize: impl FnOnce() -> Result<G, E>,
) -> Result<RenameAttempt<'binding>, E> {
	let held = held.as_fd();
	if let Err(rejection) = validate_rename_source(source, source_name, held, expected) {
		return Ok(RenameAttempt::NotAttempted(rejection));
	}
	let _guard = authorize()?;
	Ok(rename_once(
		source,
		source_name,
		destination,
		destination_name,
		held,
		expected,
	))
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
	let held = held.as_fd();
	if let Err(rejection) = validate_rename_source(source, source_name, held, expected) {
		return RenameOutcome::NotAttempted(rejection);
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

	match rename_once(
		source,
		source_name,
		destination,
		destination_name,
		held,
		expected,
	) {
		RenameAttempt::NotAttempted(rejection) => RenameOutcome::NotAttempted(rejection),
		RenameAttempt::Conflict => RenameOutcome::Conflict,
		RenameAttempt::Uncertain(error) => RenameOutcome::Uncertain(error),
		RenameAttempt::Renamed(entry) => RenameOutcome::Renamed(entry.observe()),
	}
}

fn validate_rename_source(
	source: &Directory,
	source_name: &EntryName,
	held: BorrowedFd<'_>,
	expected: &ObjectIdentity,
) -> Result<(), RenameRejection> {
	expected
		.revalidate_held(held)
		.map_err(RenameRejection::HeldObject)?;
	expected
		.revalidate_named(source, source_name)
		.map_err(RenameRejection::SourceName)
}

fn rename_once<'binding>(
	source: &'binding Directory,
	source_name: &'binding EntryName,
	destination: &'binding Directory,
	destination_name: &'binding EntryName,
	held: BorrowedFd<'binding>,
	expected: &'binding ObjectIdentity,
) -> RenameAttempt<'binding> {
	let result = rename_native(source, source_name, destination, destination_name);
	classify_rename(result, || RenamedEntry {
		source,
		source_name,
		destination,
		destination_name,
		held,
		expected,
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

fn classify_rename<'binding>(
	result: rustix::io::Result<()>,
	renamed_entry: impl FnOnce() -> RenamedEntry<'binding>,
) -> RenameAttempt<'binding> {
	match result {
		Ok(()) => RenameAttempt::Renamed(renamed_entry()),
		Err(Errno::EXIST) => RenameAttempt::Conflict,
		Err(error) => RenameAttempt::Uncertain(error.into()),
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
