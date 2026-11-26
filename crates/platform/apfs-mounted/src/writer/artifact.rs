use std::{error::Error, fmt, os::fd::AsFd};

use crate::{Directory, EntryName, metadata::MetadataView};

use super::{
	ClosedFile, InitialFlags, LifecycleEffect, MAX_PRIVATE_IO_BYTES, PrivateWriter, ReadBack,
	WriterError, without_materialization,
};

#[cfg(test)]
mod tests;

const READ_BACK_CHUNK_BYTES: usize = 4096;

/// Point at which the caller can check the private artifact and its ancestry.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArtifactCheckPhase {
	/// The newly created empty file, before any data is written.
	AfterCreate,
	/// The complete file through its sole writer, before synchronization.
	BeforeBarrier,
	/// The closed file through its event-only anchor, before the read-only open.
	BeforeReopen,
	/// The complete file through its independent read-only descriptor.
	BeforeReadBack,
	/// The same read-only descriptor after exact byte and EOF verification.
	AfterReadBack,
}

/// Lifecycle operation in progress at a private-artifact failure.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum ArtifactPhase {
	Create,
	Write,
	FlushAndClose,
	Reopen,
	ReadBack,
}

/// A failure with its lifecycle operation and the underlying effect evidence.
#[derive(Debug)]
pub struct ArtifactError {
	pub phase: ArtifactPhase,
	pub error: WriterError,
}

impl fmt::Display for ArtifactError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		let operation = match self.phase {
			ArtifactPhase::Create => "create",
			ArtifactPhase::Write => "write",
			ArtifactPhase::FlushAndClose => "flush and close",
			ArtifactPhase::Reopen => "reopen",
			ArtifactPhase::ReadBack => "read back",
		};
		write!(
			formatter,
			"could not {operation} private artifact ({})",
			self.error
		)
	}
}

impl Error for ArtifactError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		Some(&self.error)
	}
}

/// Exclusively create, write, flush, close and independently read back a private artifact.
///
/// The caller selects the private directory, protects it with cooperating leases,
/// and admits the contents and their length. After the parent identity probe,
/// `authorize_create` can check ancestry and return a guard held through the native
/// exclusive open. The guard is dropped before the subsequent binding checks.
/// Return [`WriterError::CreationRefused`] to record a caller denial. Use
/// `check_metadata` to check the live lease and metadata policy at each phase.
/// The private writer verifies exact stored spelling, held and named identity, and
/// private attributes. The reopened file is compared byte for byte and probed at
/// EOF. A read can advance access time.
///
/// The returned file retains its event anchor. Name promotion and directory
/// synchronization are separate caller-directed operations.
/// # Errors
/// A creation authorization refusal skips the open. The creation result can also
/// report occupancy, uncertain effect, or a created but unverified entry. During
/// `FlushAndClose`, the underlying error distinguishes failed synchronization,
/// successful synchronization with failed revalidation, failed consuming close,
/// and successful close with failed revalidation. Every failure retains any
/// affected entry for reconciliation.
pub fn write_private_artifact_checked<'dir, G>(
	directory: &'dir Directory,
	name: &'dir EntryName,
	contents: &[u8],
	initial_flags: InitialFlags,
	authorize_create: impl FnOnce() -> Result<G, WriterError>,
	mut check_metadata: impl FnMut(ArtifactCheckPhase, MetadataView<'_>) -> Result<(), WriterError>,
) -> Result<ClosedFile<'dir>, ArtifactError> {
	let mut writer = PrivateWriter::create_guarded(
		directory,
		name,
		contents.len() as u64,
		initial_flags,
		authorize_create,
	)
	.map_err(|error| ArtifactError {
		phase: ArtifactPhase::Create,
		error,
	})?;
	writer
		.with_checked_metadata(|view| check_metadata(ArtifactCheckPhase::AfterCreate, view))
		.map_err(|error| ArtifactError {
			phase: ArtifactPhase::Create,
			error: WriterError::CreatedButUnverified(Box::new(error)),
		})?;
	for chunk in contents.chunks(MAX_PRIVATE_IO_BYTES) {
		writer.write_next(chunk).map_err(|error| ArtifactError {
			phase: ArtifactPhase::Write,
			error,
		})?;
	}
	let closed = writer
		.with_checked_metadata(|view| check_metadata(ArtifactCheckPhase::BeforeBarrier, view))
		.and_then(|()| writer.flush_and_close())
		.map_err(|error| ArtifactError {
			phase: ArtifactPhase::FlushAndClose,
			error,
		})?;
	let reopen_error = |error| ArtifactError {
		phase: ArtifactPhase::Reopen,
		error,
	};
	without_materialization(LifecycleEffect::Observed, || {
		closed.location.revalidate_anchor(&closed.observed)?;
		let result = check_metadata(
			ArtifactCheckPhase::BeforeReopen,
			MetadataView::new(closed.event_handle().as_fd()),
		);
		closed.location.revalidate_anchor(&closed.observed)?;
		result
	})
	.map_err(reopen_error)?;
	let reader = closed.open_read_back().map_err(reopen_error)?;
	let read_back_error = |error| ArtifactError {
		phase: ArtifactPhase::ReadBack,
		error,
	};
	reader
		.with_checked_metadata(|view| check_metadata(ArtifactCheckPhase::BeforeReadBack, view))
		.map_err(read_back_error)?;
	verify_bytes(&reader, contents).map_err(read_back_error)?;
	reader.revalidate().map_err(read_back_error)?;
	reader
		.with_checked_metadata(|view| check_metadata(ArtifactCheckPhase::AfterReadBack, view))
		.map_err(read_back_error)?;
	Ok(closed)
}

fn verify_bytes(reader: &ReadBack<'_>, contents: &[u8]) -> Result<(), WriterError> {
	let mut scratch = [0; READ_BACK_CHUNK_BYTES];
	let mut offset = 0;
	for expected in contents.chunks(scratch.len()) {
		let observed = &mut scratch[..expected.len()];
		reader.read_exact_at(offset, observed)?;
		if let Some(index) = observed
			.iter()
			.zip(expected)
			.position(|(seen, want)| seen != want)
		{
			return Err(WriterError::ReadBackMismatch {
				offset: offset + index as u64,
			});
		}
		offset += expected.len() as u64;
	}
	Ok(())
}
