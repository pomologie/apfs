use std::{fs::File, io};

use crate::{
	dataless::ContentError,
	source::{read_positioned, read_positioned_exact},
};

use super::{ClosedFile, LifecycleEffect, WriterError, bounded_end, without_materialization};

impl ClosedFile<'_> {
	/// Independently reopen the closed stage read-only under its original name.
	/// # Errors
	/// Returns an error for an unavailable or changed live observation or a
	/// failure to open the read-only descriptor.
	pub fn open_read_back(&self) -> Result<ReadBack<'_>, WriterError> {
		self.location.check_process()?;
		without_materialization(LifecycleEffect::Observed, || {
			let file = self.location.open_read_only(&self.observed)?;
			Ok(ReadBack { stage: self, file })
		})
	}
}

/// Independently opened read-only access to a closed private file.
#[derive(Debug)]
pub struct ReadBack<'stage> {
	stage: &'stage ClosedFile<'stage>,
	file: File,
}

impl ReadBack<'_> {
	/// Exact logical length of the complete stage in bytes.
	pub const fn len(&self) -> u64 {
		self.stage.len()
	}

	/// Whether the logical length is zero.
	pub const fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// Read the exact requested range, with live checks before and after I/O.
	/// # Errors
	/// Returns range, observation, unavailable content, short data or I/O
	/// failures. Discard the buffer after any error.
	pub fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), WriterError> {
		self.stage.location.check_process()?;
		bounded_end(offset, buffer.len(), self.len())?;
		without_materialization(LifecycleEffect::Read, || {
			let location = &self.stage.location;
			location.revalidate(&self.file, &self.stage.observed)?;
			read_positioned_exact(&self.file, offset, buffer).map_err(read_error)?;
			location.revalidate(&self.file, &self.stage.observed)
		})
	}

	/// Check the held and named inode, metadata, extent and actual EOF.
	/// # Errors
	/// Returns an error for unavailable or changed observations, unexpected data
	/// past EOF, or an I/O or materialization policy failure.
	pub fn revalidate(&self) -> Result<(), WriterError> {
		self.stage.location.check_process()?;
		without_materialization(LifecycleEffect::Observed, || {
			let location = &self.stage.location;
			location.revalidate(&self.file, &self.stage.observed)?;
			if read_positioned(&self.file, self.len(), &mut [0]).map_err(read_error)? != 0 {
				return Err(WriterError::UnexpectedDataAfterEnd);
			}
			location.revalidate(&self.file, &self.stage.observed)
		})
	}
}

fn read_error(error: io::Error) -> WriterError {
	if error.kind() == io::ErrorKind::UnexpectedEof {
		WriterError::UnexpectedEnd
	} else {
		WriterError::Read(ContentError::while_materialization_disabled(error))
	}
}
