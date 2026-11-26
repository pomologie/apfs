//! Private file lifecycle operations for a caller-authorized mounted APFS directory.

use std::{
	fs::File,
	io,
	os::fd::{AsFd, IntoRawFd},
	os::unix::fs::FileExt,
};

use rustix::fs::{self, OFlags};

use crate::{
	Directory, EntryName, EventHandle,
	identity::ObjectIdentity,
	metadata::{
		AccessModificationTimes, ApplyError, MetadataView, ObjectFlags, ObservationError, set_times,
	},
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

/// Caller-selected admission rule for the initial stage's BSD flags.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum InitialFlags {
	/// Admit any initial flags. The existing live checks still require them to stay unchanged.
	AllowStable,
	/// Refuse an initial observation with any flag set.
	RequireZero,
}

impl InitialFlags {
	fn check(self, actual: ObjectFlags) -> Result<(), WriterError> {
		if self == Self::RequireZero && actual.raw() != 0 {
			return Err(WriterError::UnexpectedInitialFlags { actual });
		}
		Ok(())
	}
}

/// Caller-selected acceptance rule for the birth time after timestamp installation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BirthTimePolicy {
	/// Accept only the original birth time.
	Preserve,
	/// Also accept Darwin lowering the birth time to the requested modification time.
	AllowDarwinAdjustment,
}

/// Point at which the caller checks metadata during timestamp installation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MetadataCheckPhase {
	/// Before changing any timestamps.
	BeforeUpdate,
	/// After the timestamp update and before the full-file barrier.
	AfterUpdate,
	/// After the full-file barrier.
	AfterBarrier,
}

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
		Self::create_with_initial_flags(directory, name, extent, InitialFlags::AllowStable)
	}

	/// Exclusively create a private file and apply the selected initial flag rule.
	/// # Errors
	/// In addition to the errors from [Self::create], refusal of the initial flags
	/// returns [WriterError::CreatedButUnverified] and retains the entry.
	pub fn create_with_initial_flags(
		directory: &'dir Directory,
		name: &'dir EntryName,
		extent: u64,
		flags: InitialFlags,
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
				flags.check(observed.flags())?;
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

	/// Query metadata on the held writer with live name and identity checks on both sides.
	/// # Errors
	/// Returns an error for a retired writer, failed observations, or a materialization
	/// policy failure. Discard the result when revalidation fails.
	pub fn with_metadata<T>(
		&self,
		observe: impl FnOnce(MetadataView<'_>) -> Result<T, ObservationError>,
	) -> Result<T, WriterError> {
		self.location.check_process()?;
		let file = self.file.as_ref().ok_or(WriterError::Retired)?;
		without_materialization(LifecycleEffect::Observed, || {
			self.location.with_metadata(file, &self.observed, observe)
		})
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
			self.location
				.revalidate(&file, &self.observed)
				.map_err(|error| WriterError::BarrierPassedButUnverified(Box::new(error)))?;
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

	/// Query metadata through an independent read-only handle to the same private entry.
	/// # Errors
	/// Returns read-only admission, metadata, identity, or policy failures.
	pub fn with_metadata<T>(
		&self,
		observe: impl FnOnce(MetadataView<'_>) -> Result<T, ObservationError>,
	) -> Result<T, WriterError> {
		self.open_read_back()?.with_metadata(observe)
	}

	/// Install and flush final access and modification times after independent read-back.
	/// Darwin may move the file's birth time to an earlier modification time.
	/// The returned capability reports the identity revalidated after that update.
	/// # Errors
	/// Refuses changed observations or unequal read-back and reports a failed
	/// timestamp update, barrier, or policy operation. The entry is retained.
	pub fn apply_times(
		self,
		times: AccessModificationTimes,
	) -> Result<MetadataReadyFile<'dir>, WriterError> {
		self.apply_times_with_birth_policy(times, BirthTimePolicy::AllowDarwinAdjustment)
	}

	/// Install final timestamps under the selected birth-time rule and synchronize the inode.
	/// A birth-time refusal is reported after the update. The file remains at its private name.
	/// # Errors
	/// Returns pre-update observation failures, update errors, or
	/// [WriterError::TimesAppliedButUnverified] after a successful update whose validation or
	/// synchronization failed. Any materialization policy failure is reported separately.
	pub fn apply_times_with_birth_policy(
		self,
		times: AccessModificationTimes,
		birth_policy: BirthTimePolicy,
	) -> Result<MetadataReadyFile<'dir>, WriterError> {
		self.apply_times_checked(times, birth_policy, |_, _| Ok(()))
	}

	/// Install, verify and synchronize timestamps with caller-selected metadata checks.
	/// Each check receives a view of the same independently opened read-only descriptor.
	/// Callers may capture their live lease and return a policy refusal with
	/// [WriterError::MetadataRefused].
	/// # Errors
	/// A refusal before the update leaves timestamps untouched. A refusal after the
	/// update is reported as [WriterError::TimesAppliedButUnverified]. The private entry
	/// is retained. See [Self::apply_times_with_birth_policy] for other failures.
	pub fn apply_times_checked(
		self,
		times: AccessModificationTimes,
		birth_policy: BirthTimePolicy,
		check: impl FnMut(MetadataCheckPhase, MetadataView<'_>) -> Result<(), WriterError>,
	) -> Result<MetadataReadyFile<'dir>, WriterError> {
		self.apply_times_checked_with(times, birth_policy, check, |file| full_file_sync(file))
	}

	fn apply_times_checked_with(
		mut self,
		times: AccessModificationTimes,
		birth_policy: BirthTimePolicy,
		mut check: impl FnMut(MetadataCheckPhase, MetadataView<'_>) -> Result<(), WriterError>,
		barrier: impl FnOnce(&File) -> Result<(), BarrierError>,
	) -> Result<MetadataReadyFile<'dir>, WriterError> {
		self.location.check_process()?;
		without_materialization(LifecycleEffect::TimesApplied, || {
			self.location.revalidate_anchor(&self.observed)?;
			let descriptor = self.location.open_read_only(&self.observed)?;
			let mut check = |phase| check(phase, MetadataView::new(descriptor.as_fd()));
			check(MetadataCheckPhase::BeforeUpdate)?;
			self.location.revalidate(&descriptor, &self.observed)?;
			let reported = set_times(&descriptor, times).map_err(|error| {
				if matches!(error, ApplyError::ReadBack(_)) {
					WriterError::TimesAppliedButUnverified(Box::new(WriterError::Times(error)))
				} else {
					WriterError::Times(error)
				}
			})?;
			let verify_and_flush = || {
				if reported != times {
					return Err(WriterError::TimesMismatch);
				}
				let observed = self.location.confirm_time_update(
					&descriptor,
					&self.observed,
					times,
					birth_policy,
				)?;
				check(MetadataCheckPhase::AfterUpdate)?;
				self.location
					.revalidate_times(&descriptor, &observed, times)?;
				barrier(&descriptor).map_err(WriterError::Barrier)?;
				self.location
					.revalidate_times(&descriptor, &observed, times)?;
				check(MetadataCheckPhase::AfterBarrier)?;
				self.location
					.revalidate_times(&descriptor, &observed, times)?;
				Ok(observed)
			};
			let observed = verify_and_flush()
				.map_err(|error| WriterError::TimesAppliedButUnverified(Box::new(error)))?;
			Ok(MetadataReadyFile {
				location: self.location,
				descriptor,
				observed,
				times,
			})
		})
	}
}

/// Closed, synchronized private file with its final timestamps installed.
/// It retains a read-only descriptor and the original event-only anchor.
#[derive(Debug)]
pub struct MetadataReadyFile<'dir> {
	location: Location<'dir>,
	descriptor: File,
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

	/// Query the synchronized file's metadata while checking its held and named state.
	/// # Errors
	/// Returns identity, timestamp, metadata, process or policy failures.
	pub fn with_metadata<T>(
		&self,
		observe: impl FnOnce(MetadataView<'_>) -> Result<T, ObservationError>,
	) -> Result<T, WriterError> {
		self.location.check_process()?;
		without_materialization(LifecycleEffect::Observed, || {
			self.revalidate_final()?;
			let result = observe(MetadataView::new(self.descriptor.as_fd()));
			self.revalidate_final()?;
			Ok(result?)
		})
	}

	/// Query the sealed inode through its retained read-only descriptor after a rename.
	///
	/// A rename can advance change time. All other sealed fields must still match,
	/// and change time must remain stable across the query. Use
	/// [`crate::publication::RenamedEntry::observe`] for separate namespace evidence.
	/// # Errors
	/// Returns identity, timestamp, metadata, process or materialization policy failures.
	pub fn with_held_metadata<T>(
		&self,
		observe: impl FnOnce(MetadataView<'_>) -> Result<T, ObservationError>,
	) -> Result<T, WriterError> {
		self.location.check_process()?;
		without_materialization(LifecycleEffect::Observed, || {
			let before = self.observe_held()?;
			let result = observe(MetadataView::new(self.descriptor.as_fd()));
			if !self.observe_held()?.same_live(&before) {
				return Err(WriterError::Changed);
			}
			Ok(result?)
		})
	}

	/// Verify that the live inode, name, extent and timestamps still match.
	/// # Errors
	/// Returns identity, metadata, process or policy failures.
	pub fn revalidate(&self) -> Result<(), WriterError> {
		self.location.check_process()?;
		without_materialization(LifecycleEffect::Observed, || self.revalidate_final())
	}

	fn revalidate_final(&self) -> Result<(), WriterError> {
		self.location
			.revalidate_times(&self.descriptor, &self.observed, self.times)
	}

	fn observe_held(&self) -> Result<Snapshot, WriterError> {
		self.location
			.observe_sealed_held(&self.descriptor, &self.observed, self.times)
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
