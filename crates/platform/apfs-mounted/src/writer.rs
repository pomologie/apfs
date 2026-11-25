//! Private file lifecycle operations for a caller-authorized mounted APFS directory.

use std::{fs::File, io, os::fd::IntoRawFd, os::unix::fs::FileExt};

use rustix::fs::{self, OFlags};

use crate::{
	Directory, EntryName, EventHandle,
	identity::ObjectIdentity,
	metadata::{AccessModificationTimes, set_times},
};

mod barrier;
mod error;
mod observation;
mod read_back;

#[cfg(test)]
mod tests;

pub use barrier::{BarrierError, BarrierKind, full_file_sync, sync_directory};
pub use error::{LifecycleEffect, WriterError};
pub use read_back::ReadBack;

use error::without_materialization;
use observation::{Location, Snapshot};

/// Maximum bytes admitted by a single positioned write or independent read-back.
pub const MAX_PRIVATE_IO_BYTES: usize = 1024 * 1024;

const MAX_WRITE_INTERRUPTS: usize = 16;
const MAX_FILE_EXTENT: u64 = i64::MAX as u64;

/// Sole writable handle for one newly created private file and declared extent.
///
/// Supply an authorized owner-private directory with an empty ACL and protected
/// ancestors. The caller must exclude noncooperating writers and avoid inheriting
/// the writer across a fork. Failures leave any created entry for reconciliation.
#[derive(Debug)]
pub struct PrivateWriter<'dir> {
	location: Location<'dir>,
	file: Option<File>,
	position: u64,
	observed: Snapshot,
}

impl<'dir> PrivateWriter<'dir> {
	/// Exclusively create one private file at a relative name.
	/// # Errors
	/// Returns an occupied-name, invalid extent, opening, policy, or observation
	/// error. Once creation succeeds the name is retained even if admission fails.
	pub fn create(
		directory: &'dir Directory,
		name: &'dir EntryName,
		extent: u64,
	) -> Result<Self, WriterError> {
		if extent > MAX_FILE_EXTENT {
			return Err(WriterError::InvalidRange);
		}
		without_materialization(LifecycleEffect::Created, || {
			let parent = ObjectIdentity::held(directory)?;
			let file = match fs::openat(
				directory,
				name.as_c_str(),
				observation::PRIVATE_OPEN | OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
				observation::PRIVATE_MODE,
			) {
				Ok(fd) => File::from(fd),
				Err(rustix::io::Errno::EXIST) => return Err(WriterError::Occupied),
				Err(error) => return Err(WriterError::CreateUncertain(error.into())),
			};

			let admit = || {
				let location = Location::capture(directory, name, extent, parent, &file)?;
				let observed = location.observe(&file, 0)?;
				Ok(Self {
					location,
					file: Some(file),
					position: 0,
					observed,
				})
			};
			admit().map_err(|error| WriterError::CreatedButUnverified(Box::new(error)))
		})
	}

	/// Admitted identity of the newly created file.
	pub fn identity(&self) -> &ObjectIdentity {
		self.location.identity()
	}

	/// Position of the end of the last verified write.
	pub const fn position(&self) -> u64 {
		self.position
	}

	/// Write the next nonempty contiguous chunk at its declared offset.
	/// # Errors
	/// Invalid ranges leave the writer untouched. Other write or observation
	/// failures after admission retire it and may leave a partial transfer.
	pub fn write_next(&mut self, bytes: &[u8]) -> Result<(), WriterError> {
		self.write_next_with(bytes, FileExt::write_at)
	}

	fn write_next_with(
		&mut self,
		bytes: &[u8],
		write: impl FnMut(&File, &[u8], u64) -> io::Result<usize>,
	) -> Result<(), WriterError> {
		self.location.check_process()?;
		let end = bounded_end(self.position, bytes.len(), self.location.extent())?;
		if bytes.is_empty() {
			return Err(WriterError::InvalidRange);
		}
		let file = self.file.take().ok_or(WriterError::Retired)?;
		let observed = without_materialization(LifecycleEffect::Written { end }, || {
			self.location.revalidate(&file, &self.observed)?;
			write_positioned(&file, self.position, bytes, write)?;
			let current = self.location.observe(&file, end)?;
			if !current.same_layout(&self.observed) {
				return Err(WriterError::Changed);
			}
			Ok(current)
		})?;
		self.file = Some(file);
		self.position = end;
		self.observed = observed;
		Ok(())
	}

	/// Complete the full-file barrier and consume the writer via checked close.
	/// # Errors
	/// Refuses incomplete data, unavailable observations, and barrier or close
	/// failure. The writer is consumed in every case. Any file entry is retained.
	pub fn flush_and_close(self) -> Result<ClosedFile<'dir>, WriterError> {
		self.finish_with(|file| full_file_sync(file), checked_close)
	}

	fn finish_with(
		self,
		barrier: impl FnOnce(&File) -> Result<(), BarrierError>,
		close: impl FnOnce(File) -> Result<(), WriterError>,
	) -> Result<ClosedFile<'dir>, WriterError> {
		self.location.check_process()?;
		let file = self.file.ok_or(WriterError::Retired)?;
		if self.position != self.location.extent() {
			return Err(WriterError::Incomplete);
		}
		without_materialization(LifecycleEffect::Closed, || {
			self.location.revalidate(&file, &self.observed)?;
			barrier(&file).map_err(WriterError::Barrier)?;
			self.location.revalidate(&file, &self.observed)?;
			close(file)?;
			self.location
				.revalidate_anchor(&self.observed)
				.map_err(|error| WriterError::ClosedButUnverified(Box::new(error)))?;
			Ok(ClosedFile {
				location: self.location,
				observed: self.observed,
			})
		})
	}
}

/// A complete file whose sole writer reported a successful checked close.
#[derive(Debug)]
pub struct ClosedFile<'dir> {
	location: Location<'dir>,
	observed: Snapshot,
}

impl<'dir> ClosedFile<'dir> {
	/// Admitted identity retained by the event-only anchor.
	pub fn identity(&self) -> &ObjectIdentity {
		self.location.identity()
	}

	/// Declared logical length in bytes.
	pub const fn len(&self) -> u64 {
		self.location.extent()
	}

	/// Whether the declared logical length is zero.
	pub const fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// Install and flush final access and modification times after independent read-back.
	/// Darwin may move the file's birth time to an earlier modification time.
	/// The returned capability reports the identity revalidated after that update.
	/// # Errors
	/// Refuses changed observations or unequal read-back and reports a failed
	/// timestamp update, barrier, or policy operation. The entry is retained.
	pub fn apply_times(
		mut self,
		times: AccessModificationTimes,
	) -> Result<MetadataReadyFile<'dir>, WriterError> {
		self.location.check_process()?;
		without_materialization(LifecycleEffect::TimesApplied, || {
			self.location.revalidate_anchor(&self.observed)?;
			let descriptor = self.location.open_read_only(&self.observed)?;
			let reported = set_times(&descriptor, times).map_err(WriterError::Times)?;
			let mut verify_and_flush = || {
				if reported != times {
					return Err(WriterError::TimesMismatch);
				}
				let observed =
					self.location
						.confirm_time_update(&descriptor, &self.observed, times)?;
				full_file_sync(&descriptor).map_err(WriterError::Barrier)?;
				self.location.revalidate(&descriptor, &observed)?;
				self.location.revalidate_times(&observed, times)?;
				Ok(observed)
			};
			let observed = verify_and_flush()
				.map_err(|error| WriterError::TimesAppliedButUnverified(Box::new(error)))?;
			Ok(MetadataReadyFile {
				location: self.location,
				observed,
				times,
			})
		})
	}
}

/// Closed, synchronized private file with its final timestamps installed.
/// This capability retains an event-only anchor for metadata observations.
#[derive(Debug)]
pub struct MetadataReadyFile<'dir> {
	location: Location<'dir>,
	observed: Snapshot,
	times: AccessModificationTimes,
}

impl MetadataReadyFile<'_> {
	/// Admitted identity retained by the event-only anchor.
	pub fn identity(&self) -> &ObjectIdentity {
		self.location.identity()
	}

	/// Retain the original held inode when passing it to a publication operation.
	pub const fn event_handle(&self) -> &EventHandle {
		self.location.event_handle()
	}

	/// Confirmed final access and modification times.
	pub const fn times(&self) -> AccessModificationTimes {
		self.times
	}

	/// Verify that the live inode, name, extent and timestamps still match.
	/// # Errors
	/// Returns identity, metadata, process or policy failures.
	pub fn revalidate(&self) -> Result<(), WriterError> {
		self.location.check_process()?;
		without_materialization(LifecycleEffect::Observed, || {
			self.location.revalidate_times(&self.observed, self.times)
		})
	}
}

fn bounded_end(offset: u64, length: usize, extent: u64) -> Result<u64, WriterError> {
	if length > MAX_PRIVATE_IO_BYTES {
		return Err(WriterError::InvalidRange);
	}
	offset
		.checked_add(length as u64)
		.filter(|end| *end <= extent)
		.ok_or(WriterError::InvalidRange)
}

fn write_positioned(
	file: &File,
	mut offset: u64,
	mut bytes: &[u8],
	mut write: impl FnMut(&File, &[u8], u64) -> io::Result<usize>,
) -> Result<(), WriterError> {
	let mut interrupts = MAX_WRITE_INTERRUPTS;
	while !bytes.is_empty() {
		match write(file, bytes, offset) {
			Ok(0) => return Err(WriterError::Write(io::ErrorKind::WriteZero.into())),
			Ok(written) if written <= bytes.len() => {
				offset += written as u64;
				bytes = &bytes[written..];
			}
			Ok(_) => return Err(WriterError::Write(io::ErrorKind::InvalidData.into())),
			Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupts > 0 => {
				interrupts -= 1
			}
			Err(error) => return Err(WriterError::Write(error)),
		}
	}
	Ok(())
}

#[allow(
	unsafe_code,
	reason = "checked consuming close must preserve Darwin failures"
)]
fn checked_close(file: File) -> Result<(), WriterError> {
	let fd = file.into_raw_fd();
	// SAFETY: Ownership of this live, unique writable descriptor was transferred
	// from File. Nothing can access it through this API after consuming the File.
	// try_close invalidates the number even on error, so it is never retried.
	unsafe { rustix::io::try_close(fd) }.map_err(|error| WriterError::Close(error.into()))
}
