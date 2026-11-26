use std::{
	ffi::{CStr, CString},
	os::fd::BorrowedFd,
};

use super::{
	ExtendedSecurity, FINDER_INFO_BYTES, Metadata, ObservationError, ResourceFork, SecurityGuids,
	XattrVisibility, extended_security, finder_info, list_xattrs, read_resource_fork, read_xattr,
	resource_fork, security_guids, stat,
};

/// Bounded metadata queries on the same descriptor supplied by an observation scope.
///
/// The view grants only the listed queries. Its observations are live kernel
/// facts with the same limits as the individual metadata queries.
pub struct MetadataView<'fd>(BorrowedFd<'fd>);

impl<'fd> MetadataView<'fd> {
	pub(crate) const fn new(fd: BorrowedFd<'fd>) -> Self {
		Self(fd)
	}

	/// Read basic metadata, including times, owner, mode, links and flags.
	/// # Errors
	/// Returns the observation errors of [`stat`].
	pub fn stat(&self) -> Result<Metadata, ObservationError> {
		stat(self.0)
	}

	/// Read extended-security and ACL evidence with an explicit byte limit.
	/// # Errors
	/// Returns the observation errors of [`extended_security`].
	pub fn extended_security(
		&self,
		max_bytes: usize,
	) -> Result<ExtendedSecurity, ObservationError> {
		extended_security(self.0, max_bytes)
	}

	/// Read the reported owner and group security GUIDs.
	/// # Errors
	/// Returns the observation errors of [`security_guids`].
	pub fn security_guids(&self) -> Result<SecurityGuids, ObservationError> {
		security_guids(self.0)
	}

	/// List xattrs under an explicit bound and selected visibility.
	/// # Errors
	/// Returns the observation errors of [`list_xattrs`].
	pub fn list_xattrs(
		&self,
		visibility: XattrVisibility,
		max_bytes: usize,
	) -> Result<Vec<CString>, ObservationError> {
		list_xattrs(self.0, visibility, max_bytes)
	}

	/// Read one named xattr under an explicit bound and selected visibility.
	/// # Errors
	/// Returns the observation errors of [`read_xattr`].
	pub fn read_xattr(
		&self,
		name: &CStr,
		visibility: XattrVisibility,
		max_bytes: usize,
	) -> Result<Option<Vec<u8>>, ObservationError> {
		read_xattr(self.0, name, visibility, max_bytes)
	}

	/// Observe a FinderInfo field of the native fixed width.
	/// # Errors
	/// Returns the observation errors of [`finder_info`].
	pub fn finder_info(
		&self,
		visibility: XattrVisibility,
	) -> Result<Option<[u8; FINDER_INFO_BYTES]>, ObservationError> {
		finder_info(self.0, visibility)
	}

	/// Observe resource-fork length and attribute presence.
	/// # Errors
	/// Returns the observation errors of [`resource_fork`].
	pub fn resource_fork(&self) -> Result<ResourceFork, ObservationError> {
		resource_fork(self.0)
	}

	/// Read the named resource-fork value under an explicit bound.
	/// # Errors
	/// Returns the observation errors of [`read_resource_fork`].
	pub fn read_resource_fork(
		&self,
		max_bytes: usize,
	) -> Result<Option<Vec<u8>>, ObservationError> {
		read_resource_fork(self.0, max_bytes)
	}
}
