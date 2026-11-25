use std::{
	ffi::{CStr, CString},
	fmt,
	fs::File,
	io,
	os::fd::{AsFd, BorrowedFd, OwnedFd},
};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, fstat, mkdirat, openat, statat};

mod darwin;
#[cfg(test)]
mod tests;

pub use darwin::stored_name;

/// Byte limit of the supported directory entry profile.
pub const MAX_ENTRY_NAME_BYTES: usize = 255;
const NO_FOLLOW: OFlags = OFlags::NOFOLLOW
	.union(OFlags::CLOEXEC)
	.union(OFlags::NONBLOCK);
const PRIVATE_DIRECTORY: Mode = Mode::RUSR.union(Mode::WUSR).union(Mode::XUSR);

/// One owned component, preserving the supplied bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EntryName(CString);

impl EntryName {
	/// Validates one component without converting or normalizing its bytes.
	/// # Errors
	/// Rejects empty, oversized, reserved, separated, or NUL-containing names.
	pub fn new(bytes: &[u8]) -> Result<Self, InvalidEntryName> {
		if bytes.is_empty()
			|| bytes.len() > MAX_ENTRY_NAME_BYTES
			|| matches!(bytes, b"." | b"..")
			|| bytes.contains(&b'/')
		{
			return Err(InvalidEntryName);
		}
		CString::new(bytes).map(Self).map_err(|_| InvalidEntryName)
	}

	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		self.0.as_bytes()
	}

	#[must_use]
	pub fn as_c_str(&self) -> &CStr {
		&self.0
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidEntryName;

impl fmt::Display for InvalidEntryName {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("expected one nonreserved Darwin entry name")
	}
}

impl std::error::Error for InvalidEntryName {}

/// An owned, caller-authorized directory descriptor.
/// Authorization, local mount admission, and protected ancestors are caller
/// responsibilities. The descriptor stays bound when an ancestor is renamed.
#[derive(Debug)]
pub struct Directory(OwnedFd);

impl Directory {
	/// Adopts a held directory from the caller.
	///
	/// # Errors
	/// Fails if the descriptor cannot be inspected or refers to another object kind.
	pub fn from_file(file: File) -> io::Result<Self> {
		Self::from_owned_fd(file.into())
	}

	/// Adopts a held directory descriptor without reopening its original path.
	/// # Errors
	/// Fails if the descriptor cannot be inspected or refers to another object kind.
	pub fn from_owned_fd(fd: OwnedFd) -> io::Result<Self> {
		if FileType::from_raw_mode(fstat(&fd)?.st_mode) != FileType::Directory {
			return Err(io::Error::new(
				io::ErrorKind::NotADirectory,
				"expected a directory handle",
			));
		}
		Ok(Self(fd))
	}

	/// Opens a child directory relative to the held parent.
	/// # Errors
	/// Fails on lookup, permission, type, or symlink errors.
	pub fn open_directory(&self, name: &EntryName) -> io::Result<Self> {
		let flags = OFlags::RDONLY | OFlags::DIRECTORY | NO_FOLLOW;
		Ok(Self(openat(self, name.as_c_str(), flags, Mode::empty())?))
	}

	/// Opens a regular file for reading without following the selected name.
	/// Use the pinned source reader when the chosen name and extent must stay bound.
	/// # Errors
	/// Fails on lookup, permission, type, or symlink errors.
	pub fn open_file(&self, name: &EntryName) -> io::Result<File> {
		let inspect = || statat(self, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW);
		let expected = inspect()?;
		if FileType::from_raw_mode(expected.st_mode) != FileType::RegularFile {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"expected a regular file",
			));
		}
		let file = openat(
			self,
			name.as_c_str(),
			OFlags::RDONLY | NO_FOLLOW,
			Mode::empty(),
		)?;
		for observed in [fstat(&file)?, inspect()?] {
			if FileType::from_raw_mode(observed.st_mode) != FileType::RegularFile
				|| (observed.st_dev, observed.st_ino, observed.st_gen)
					!= (expected.st_dev, expected.st_ino, expected.st_gen)
			{
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					"regular file binding changed while opening",
				));
			}
		}
		Ok(File::from(file))
	}

	/// Holds a named object using Darwin's event-only open flag.
	/// This library uses the handle for metadata. The flag does not establish
	/// a kernel permission boundary against explicit descriptor I/O.
	/// # Errors
	/// Fails on lookup, permission, or symlink errors.
	pub fn open_event(&self, name: &EntryName) -> io::Result<EventHandle> {
		darwin::open_event(self, name).map(EventHandle)
	}

	/// Creates an exclusive private directory and reopens it relative to this handle.
	/// Use a protected parent with cooperating writers. Provision and observe the
	/// requested extended security before treating the new directory as a grant.
	/// # Errors
	/// Distinguishes an existing entry, create error, and successful creation with
	/// an unconfirmed reopened directory. An unconfirmed entry stays in place.
	pub fn create_private_directory(&self, name: &EntryName) -> Result<Self, DirectoryCreateError> {
		mkdirat(self, name.as_c_str(), PRIVATE_DIRECTORY).map_err(|error| {
			if error == rustix::io::Errno::EXIST {
				DirectoryCreateError::Existing
			} else {
				DirectoryCreateError::Create(error.into())
			}
		})?;
		let child = self
			.open_directory(name)
			.map_err(DirectoryCreateError::CreatedUnconfirmed)?;
		let mode = Mode::from_raw_mode(
			fstat(&child)
				.map_err(|error| DirectoryCreateError::CreatedUnconfirmed(error.into()))?
				.st_mode,
		);
		if mode != PRIVATE_DIRECTORY {
			return Err(DirectoryCreateError::CreatedUnconfirmed(io::Error::new(
				io::ErrorKind::PermissionDenied,
				"new directory mode does not match 0700",
			)));
		}
		Ok(child)
	}
}

impl AsFd for Directory {
	fn as_fd(&self) -> BorrowedFd<'_> {
		self.0.as_fd()
	}
}

/// An owned event-only open used for native identity and metadata queries.
#[derive(Debug)]
pub struct EventHandle(OwnedFd);

impl AsFd for EventHandle {
	fn as_fd(&self) -> BorrowedFd<'_> {
		self.0.as_fd()
	}
}

#[derive(Debug)]
pub enum DirectoryCreateError {
	Existing,
	Create(io::Error),
	CreatedUnconfirmed(io::Error),
}

impl fmt::Display for DirectoryCreateError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Existing => formatter.write_str("directory entry is occupied"),
			Self::Create(error) => write!(formatter, "directory creation failed ({error})"),
			Self::CreatedUnconfirmed(error) => write!(
				formatter,
				"created directory could not be confirmed ({error})"
			),
		}
	}
}

impl std::error::Error for DirectoryCreateError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Self::Existing => None,
			Self::Create(error) | Self::CreatedUnconfirmed(error) => Some(error),
		}
	}
}
