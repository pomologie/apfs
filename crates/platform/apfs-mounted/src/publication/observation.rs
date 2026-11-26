use std::{
	error::Error,
	fmt,
	os::fd::{AsFd as _, BorrowedFd},
};

use crate::{
	Directory, EntryName,
	identity::{IdentityError, ObjectIdentity},
	metadata::{Metadata, MetadataView, ObservationError, Timestamp},
	stored_name,
};

use super::{EventEntry, RenamedEntry};

/// Whether an observation accepts the filesystem's lookup spelling or requires the stored bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntrySpelling {
	/// Accept a name that resolves under the mounted filesystem's lookup rules.
	Lookup,
	/// Require the bytes reported by the held descriptor to match the component.
	Exact,
}

/// Identity and basic metadata sampled together for a held object and its name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct EntrySnapshot {
	pub identity: ObjectIdentity,
	pub metadata: Metadata,
}

impl EntrySnapshot {
	/// Logical byte length of the observed entry.
	#[must_use]
	pub const fn extent(self) -> u64 {
		self.metadata.length
	}

	/// Change time observed with the extent and other basic metadata.
	#[must_use]
	pub const fn change_stamp(self) -> Timestamp {
		self.metadata.change
	}
}

/// A coherent entry observation could not be established.
#[derive(Debug)]
#[non_exhaustive]
pub enum EntrySnapshotError {
	/// The held object, current name, or basic metadata differed on recheck.
	Changed,
	/// The former source name was present during post-rename observation.
	FormerSourcePresent,
	/// The requested component and the stored spelling differ.
	SpellingMismatch,
	Identity(IdentityError),
	Metadata(ObservationError),
}

impl fmt::Display for EntrySnapshotError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(match self {
			Self::Changed => "entry binding or basic metadata changed during observation",
			Self::FormerSourcePresent => "the former source name is present after rename",
			Self::SpellingMismatch => "the requested name differs from the stored spelling",
			Self::Identity(_) => "entry identity query failed during observation",
			Self::Metadata(_) => "entry metadata query failed during observation",
		})
	}
}

impl Error for EntrySnapshotError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::Identity(error) => Some(error),
			Self::Metadata(error) => Some(error),
			Self::Changed | Self::FormerSourcePresent | Self::SpellingMismatch => None,
		}
	}
}

impl From<IdentityError> for EntrySnapshotError {
	fn from(error: IdentityError) -> Self {
		match error {
			IdentityError::Changed => Self::Changed,
			error => Self::Identity(error),
		}
	}
}

impl From<ObservationError> for EntrySnapshotError {
	fn from(error: ObservationError) -> Self {
		Self::Metadata(error)
	}
}

impl EventEntry<'_> {
	/// Sample the named entry and run bounded queries on its event-only handle.
	/// The returned snapshot groups identity, extent, change time and basic
	/// metadata. The entry binding and snapshot are checked around the queries.
	/// The caller supplies any required lease and namespace cooperation.
	/// # Errors
	/// Returns a changed binding, unavailable evidence, or metadata query error.
	pub fn with_observation<T>(
		&self,
		spelling: EntrySpelling,
		observe: impl FnOnce(&EntrySnapshot, MetadataView<'_>) -> Result<T, ObservationError>,
	) -> Result<(EntrySnapshot, T), EntrySnapshotError> {
		let (directory, name) = self.location();
		let held = self.handle().as_fd();
		with_snapshot(
			held,
			|| sample_entry(directory, name, held, *self.identity(), spelling),
			observe,
		)
	}
}

impl RenamedEntry<'_> {
	/// Sample the held inode and destination, with the former name absent.
	/// The caller may request this after the directory barriers. The fresh
	/// snapshot includes the change time after rename. Bounded metadata queries
	/// use the held inode, with the namespace and snapshot rechecked afterward.
	/// # Errors
	/// Returns unavailable evidence, changed bindings or metadata, a present
	/// former name, or a metadata query error.
	pub fn with_observation<T>(
		&self,
		spelling: EntrySpelling,
		observe: impl FnOnce(&EntrySnapshot, MetadataView<'_>) -> Result<T, ObservationError>,
	) -> Result<(EntrySnapshot, T), EntrySnapshotError> {
		with_snapshot(
			self.held,
			|| {
				if ObjectIdentity::named(self.source, self.source_name)?.is_some() {
					return Err(EntrySnapshotError::FormerSourcePresent);
				}
				sample_entry(
					self.destination,
					self.destination_name,
					self.held,
					*self.expected,
					spelling,
				)
			},
			observe,
		)
	}
}

pub(crate) fn sample_entry(
	directory: &Directory,
	name: &EntryName,
	fd: BorrowedFd<'_>,
	expected: ObjectIdentity,
	spelling: EntrySpelling,
) -> Result<EntrySnapshot, EntrySnapshotError> {
	let (identity, held) = ObjectIdentity::held_with_stat(fd)?;
	let Some((named_identity, named)) = ObjectIdentity::named_with_stat(directory, name)? else {
		return Err(EntrySnapshotError::Changed);
	};
	if identity != expected || named_identity != expected {
		return Err(EntrySnapshotError::Changed);
	}
	if spelling == EntrySpelling::Exact && stored_name(fd).map_err(IdentityError::Io)? != *name {
		return Err(EntrySnapshotError::SpellingMismatch);
	}
	let metadata = Metadata::from_stat(&held)?;
	if Metadata::from_stat(&named)? != metadata {
		return Err(EntrySnapshotError::Changed);
	}
	Ok(EntrySnapshot { identity, metadata })
}

pub(crate) fn with_snapshot<T>(
	fd: BorrowedFd<'_>,
	mut sample: impl FnMut() -> Result<EntrySnapshot, EntrySnapshotError>,
	observe: impl FnOnce(&EntrySnapshot, MetadataView<'_>) -> Result<T, ObservationError>,
) -> Result<(EntrySnapshot, T), EntrySnapshotError> {
	let before = sample()?;
	let result = observe(&before, MetadataView::new(fd));
	let after = sample()?;
	if after != before {
		return Err(EntrySnapshotError::Changed);
	}
	Ok((after, result?))
}
