use apfs_core::ReadAt;
use apfs_format::{
	checkpoint::Mapping,
	object::{ObjectId, TransactionId},
	superblock::{BlockAddress, Superblock},
};

use crate::{
	Diagnostic, Error, OpenOptions,
	alloc::vec::Vec,
	checkpoint::{Selected, select},
};

/// Immutable view at one complete APFS checkpoint. Volume and tree resolution
/// require their own structural and format admission checks.
#[derive(Debug)]
pub struct Container<S> {
	source: S,
	selected: Superblock,
	descriptor: BlockAddress,
	mappings: Vec<Mapping>,
	diagnostics: Vec<Diagnostic>,
}

impl<S: ReadAt> Container<S> {
	/// Scans the declared descriptor ring and selects the highest complete XID.
	/// The accepted profile is an ordinary APFS v2 single physical store with
	/// contiguous checkpoint rings and checksummed persisted ephemeral objects.
	///
	/// # Errors
	/// Rejects invalid bootstrap geometry, unsupported newest candidates, split
	/// identities, read failures, exhausted budgets and missing complete checkpoints.
	pub fn open(source: S, options: OpenOptions) -> Result<Self, Error<S::Error>> {
		Self::open_selection(source, options, None)
	}

	/// Opens the complete checkpoint with the specified transaction ID.
	///
	/// The descriptor must still be present in the ring and its referenced
	/// checkpoint data must still validate. The resulting view stays bound to
	/// this transaction.
	///
	/// # Errors
	/// Returns `Error::CheckpointNotFound` when no checksummed descriptor
	/// identifies this transaction. A verified matching descriptor can still
	/// fail validation, be unsupported, or have an ambiguous identity. The
	/// same bootstrap, read and resource limits apply as with `Self::open`.
	pub fn open_at(
		source: S,
		options: OpenOptions,
		transaction: TransactionId,
	) -> Result<Self, Error<S::Error>> {
		Self::open_selection(source, options, Some(transaction))
	}

	fn open_selection(
		source: S,
		options: OpenOptions,
		transaction: Option<TransactionId>,
	) -> Result<Self, Error<S::Error>> {
		let Selected {
			selected,
			descriptor,
			mappings,
			diagnostics,
		} = select(&source, options, transaction)?;
		Ok(Self {
			source,
			selected,
			descriptor,
			mappings,
			diagnostics,
		})
	}

	/// Verified NXSB of the selected checkpoint rather than the block-zero copy.
	#[must_use]
	pub fn superblock(&self) -> &Superblock {
		&self.selected
	}

	/// Physical location of the selected checkpoint NXSB.
	#[must_use]
	pub fn descriptor(&self) -> BlockAddress {
		self.descriptor
	}

	/// Warnings about rejected slots and rollback evidence.
	#[must_use]
	pub fn diagnostics(&self) -> &[Diagnostic] {
		&self.diagnostics
	}

	/// Verified checkpoint mappings, in ascending ephemeral object ID order.
	#[must_use]
	pub fn mappings(&self) -> &[Mapping] {
		&self.mappings
	}

	/// Locates an ephemeral object within the selected checkpoint.
	#[must_use]
	pub fn ephemeral_mapping(&self, id: ObjectId) -> Option<&Mapping> {
		self.mappings
			.binary_search_by_key(&id, |mapping| mapping.id)
			.ok()
			.map(|index| &self.mappings[index])
	}

	/// Borrows the original immutable source for checked container services.
	#[must_use]
	pub fn source(&self) -> &S {
		&self.source
	}
}
