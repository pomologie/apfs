use std::{error::Error, fmt, io, os::fd::AsFd as _};

use crate::{
	Directory, EntryName, EventHandle,
	identity::{IdentityError, ObjectIdentity},
	metadata::{MetadataView, ObservationError},
};

use super::observation::{
	EntrySnapshot, EntrySnapshotError, EntrySpelling, sample_entry, with_snapshot,
};

/// A held event-only anchor tied to a particular live name.
#[derive(Debug)]
pub struct EventEntry<'location> {
	directory: &'location Directory,
	name: &'location EntryName,
	anchor: EventAnchor,
}

impl<'location> EventEntry<'location> {
	pub(crate) const fn location(&self) -> (&'location Directory, &'location EntryName) {
		(self.directory, self.name)
	}

	pub(crate) const fn handle(&self) -> &EventHandle {
		&self.anchor.file
	}

	/// Returns the identity originally captured for this anchor.
	#[must_use]
	pub const fn identity(&self) -> &ObjectIdentity {
		&self.anchor.identity
	}

	/// Check the event descriptor and the relative name against its identity.
	/// # Errors
	/// Fails on a changed binding, unavailable evidence, or inspection failure.
	pub fn revalidate(&self) -> Result<(), IdentityError> {
		self.anchor.revalidate(self.directory, self.name)
	}

	/// Sample native identity, extent, change time, and bounded metadata.
	/// The entry binding and snapshot are checked around the queries. The
	/// caller supplies any required lease and namespace cooperation.
	/// # Errors
	/// Returns a changed binding, unavailable evidence, or metadata query error.
	pub fn with_observation<T>(
		&self,
		spelling: EntrySpelling,
		observe: impl FnOnce(&EntrySnapshot, MetadataView<'_>) -> Result<T, ObservationError>,
	) -> Result<(EntrySnapshot, T), EntrySnapshotError> {
		self.anchor
			.with_observation(self.directory, self.name, spelling, observe)
	}
}

/// A recovery inventory anchor owning its name and both directory and event descriptors.
/// Queries sample live state. The anchor provides no payload operations or lease authority.
#[derive(Debug)]
pub struct OwnedEventEntry {
	directory: Directory,
	name: EntryName,
	anchor: EventAnchor,
}

impl OwnedEventEntry {
	/// Open an event-only anchor with an owned name under a held directory.
	/// Returns `None` when the first lookup finds the name absent. A successful
	/// anchor retains a duplicate of the supplied directory without reopening a path.
	/// # Errors
	/// A symlink, failed open, or mismatched identity returns an error. A name
	/// disappearing between lookup and open or a failed directory duplication
	/// also returns an error.
	pub fn open_named(directory: &Directory, name: EntryName) -> Result<Option<Self>, AnchorError> {
		let Some(anchor) = EventAnchor::open(directory, &name)? else {
			return Ok(None);
		};
		let fd = rustix::io::fcntl_dupfd_cloexec(directory, 0)
			.map_err(|error| AnchorError::Directory(error.into()))?;
		let directory = Directory::from_owned_fd(fd).map_err(AnchorError::Directory)?;
		Ok(Some(Self {
			directory,
			name,
			anchor,
		}))
	}

	/// The supplied lookup component. A lookup alias can differ from the stored spelling.
	#[must_use]
	pub const fn name(&self) -> &EntryName {
		&self.name
	}

	/// Returns the identity originally captured for this anchor.
	#[must_use]
	pub const fn identity(&self) -> &ObjectIdentity {
		&self.anchor.identity
	}

	/// Check the event descriptor and the relative name against its identity.
	/// # Errors
	/// Fails on a changed binding, unavailable evidence, or inspection failure.
	pub fn revalidate(&self) -> Result<(), IdentityError> {
		self.anchor.revalidate(&self.directory, &self.name)
	}

	/// Sample native identity, extent, change time, and bounded metadata.
	/// The entry binding and snapshot are checked around the queries. The
	/// caller supplies any required lease and namespace cooperation.
	/// # Errors
	/// Returns a changed binding, unavailable evidence, or metadata query error.
	pub fn with_observation<T>(
		&self,
		spelling: EntrySpelling,
		observe: impl FnOnce(&EntrySnapshot, MetadataView<'_>) -> Result<T, ObservationError>,
	) -> Result<(EntrySnapshot, T), EntrySnapshotError> {
		self.anchor
			.with_observation(&self.directory, &self.name, spelling, observe)
	}
}

/// Failure when establishing an event-only identity anchor.
#[derive(Debug)]
#[non_exhaustive]
pub enum AnchorError {
	Identity(IdentityError),
	Open(io::Error),
	/// The parent descriptor could not be retained for an owned anchor.
	Directory(io::Error),
}

impl fmt::Display for AnchorError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::Identity(_) => "could not establish the event entry identity",
			Self::Open(_) => "could not open the event entry",
			Self::Directory(_) => "could not retain the event entry directory",
		})
	}
}

impl Error for AnchorError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		Some(match self {
			Self::Identity(error) => error,
			Self::Open(error) | Self::Directory(error) => error,
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
	let anchor = EventAnchor::open(directory, name)?;
	Ok(anchor.map(|anchor| EventEntry {
		directory,
		name,
		anchor,
	}))
}

#[derive(Debug)]
struct EventAnchor {
	file: EventHandle,
	identity: ObjectIdentity,
}

impl EventAnchor {
	fn open(directory: &Directory, name: &EntryName) -> Result<Option<Self>, AnchorError> {
		let Some(identity) =
			ObjectIdentity::named(directory, name).map_err(AnchorError::Identity)?
		else {
			return Ok(None);
		};
		let file = directory.open_event(name).map_err(AnchorError::Open)?;
		let anchor = Self { file, identity };
		anchor
			.revalidate(directory, name)
			.map_err(AnchorError::Identity)?;
		Ok(Some(anchor))
	}

	fn revalidate(&self, directory: &Directory, name: &EntryName) -> Result<(), IdentityError> {
		self.identity.revalidate_held(&self.file)?;
		self.identity.revalidate_named(directory, name)
	}

	fn with_observation<T>(
		&self,
		directory: &Directory,
		name: &EntryName,
		spelling: EntrySpelling,
		observe: impl FnOnce(&EntrySnapshot, MetadataView<'_>) -> Result<T, ObservationError>,
	) -> Result<(EntrySnapshot, T), EntrySnapshotError> {
		let held = self.file.as_fd();
		with_snapshot(
			held,
			|| sample_entry(directory, name, held, self.identity, spelling),
			observe,
		)
	}
}
