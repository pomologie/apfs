use std::{error::Error, fmt, io, os::fd::AsFd};

use rustix::fs;

use crate::Directory;

/// Darwin synchronization operation that failed.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BarrierKind {
	FullFile,
	Directory,
}

/// Native error from a specific barrier.
#[derive(Debug)]
pub struct BarrierError {
	pub kind: BarrierKind,
	pub error: io::Error,
}

impl fmt::Display for BarrierError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let operation = match self.kind {
			BarrierKind::FullFile => "F_FULLFSYNC",
			BarrierKind::Directory => "directory fsync",
		};
		write!(f, "{operation} failed ({})", self.error)
	}
}

impl Error for BarrierError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		Some(&self.error)
	}
}

/// Request Darwin `F_FULLFSYNC` for the supplied held file descriptor.
/// Success establishes the result of the syscall, with hardware durability
/// determined independently by the caller's qualification.
/// # Errors
/// Returns the native full-file barrier error.
pub fn full_file_sync(file: impl AsFd) -> Result<(), BarrierError> {
	fs::fcntl_fullfsync(file).map_err(|error| BarrierError {
		kind: BarrierKind::FullFile,
		error: error.into(),
	})
}

/// Request `fsync` on one held directory.
/// # Errors
/// Returns the native directory barrier error.
pub fn sync_directory(directory: &Directory) -> Result<(), BarrierError> {
	fs::fsync(directory).map_err(|error| BarrierError {
		kind: BarrierKind::Directory,
		error: error.into(),
	})
}
