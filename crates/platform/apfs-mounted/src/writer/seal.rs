use std::{fs::File, os::fd::AsFd};

use crate::metadata::MetadataView;

use super::{
	BarrierError, ClosedFile, LifecycleEffect, MetadataReadyFile, WriterError, full_file_sync,
	without_materialization,
};

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

/// Point at which the caller checks metadata during mutation-free sealing.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SealCheckPhase {
	/// Before the full-file barrier.
	BeforeBarrier,
	/// After the full-file barrier.
	AfterBarrier,
}

impl<'dir> ClosedFile<'dir> {
	/// Seal the current metadata through an independently opened read-only descriptor.
	/// The checks bracket a full-file barrier. Live identity, extent and timestamps
	/// are revalidated around both checks, and the operation preserves the timestamps
	/// observed when sealing began. Complete any caller-required read-back first.
	/// Each check can enforce caller policy and return [WriterError::MetadataRefused].
	/// # Errors
	/// Returns opening, metadata, policy or barrier failures. If the barrier succeeds
	/// and the final checks fail, returns [WriterError::BarrierPassedButUnverified].
	/// All failures retain the private file entry.
	pub fn seal_checked(
		self,
		check: impl FnMut(SealCheckPhase, MetadataView<'_>) -> Result<(), WriterError>,
	) -> Result<MetadataReadyFile<'dir>, WriterError> {
		self.seal_checked_with(check, |file| full_file_sync(file))
	}

	pub(super) fn seal_checked_with(
		self,
		mut check: impl FnMut(SealCheckPhase, MetadataView<'_>) -> Result<(), WriterError>,
		barrier: impl FnOnce(&File) -> Result<(), BarrierError>,
	) -> Result<MetadataReadyFile<'dir>, WriterError> {
		self.location.check_process()?;
		without_materialization(LifecycleEffect::MetadataSealed, || {
			let descriptor = self.location.open_read_only(&self.observed)?;
			let view = || MetadataView::new(descriptor.as_fd());
			let times = view().stat()?.times;
			let revalidate = || {
				self.location
					.revalidate_times(&descriptor, &self.observed, times)
			};
			let mut check_live = |phase| {
				revalidate()?;
				let result = check(phase, view());
				revalidate()?;
				result
			};
			check_live(SealCheckPhase::BeforeBarrier)?;
			barrier(&descriptor).map_err(WriterError::Barrier)?;
			check_live(SealCheckPhase::AfterBarrier)
				.map_err(|error| WriterError::BarrierPassedButUnverified(Box::new(error)))?;
			Ok(MetadataReadyFile {
				location: self.location,
				descriptor,
				observed: self.observed,
				times,
			})
		})
	}
}
