use crate::alloc::vec::Vec;
use core::fmt;

use apfs_core::ByteOffset;
use apfs_format::{
	object::{ObjectId, TransactionId},
	superblock::BlockAddress,
};

use crate::Diagnostic;

/// A budget exhausted during checkpoint selection or object lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Limit {
	/// Number of descriptor slots.
	DescriptorBlocks,
	/// Mapping records per checkpoint.
	Mappings,
	/// Bytes in one physical object or read buffer.
	ObjectBytes,
	/// Bytes read during the entire discovery operation.
	ReadBytes,
	/// Number of nodes visited during one object-map lookup.
	ObjectMapNodes,
}

/// A verified descriptor declares a format outside the supported profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Unsupported {
	/// NXSB version or incompatible feature mask.
	IncompatibleFeatures(u64),
	/// A superblock has unsupported object or storage flags.
	SuperblockObjectType(u32),
	/// A container keybag is present.
	Keylocker,
	/// A descriptor or payload area is a fragmented tree.
	FragmentedCheckpointArea,
	/// A valid map introduced unknown flags.
	CheckpointMapFlags(u32),
	/// A map has unsupported storage or object flags.
	CheckpointMapType(u32),
	/// A mapping uses unsupported on-disk object flags or storage type.
	MappedObjectType(u32),
}

/// Why a descriptor did not produce a complete checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Corruption {
	/// An underlying format check failed.
	Format(apfs_format::Error),
	/// The descriptor disagrees with the bootstrap identity or hard geometry.
	Identity,
	/// An admitted ring does not cover the expected descriptor or data span.
	Ring,
	/// An object is missing, duplicated, from another XID or has the wrong type.
	Object,
}

/// Rejected on-disk checkpoint evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Damage {
	/// Physical location of the descriptor.
	pub descriptor: BlockAddress,
	/// Verified transaction, when the descriptor checksum and header succeeded.
	pub transaction: Option<TransactionId>,
	/// Specific group of validation checks that failed.
	pub reason: Corruption,
}

/// Why an object-map lookup could not establish a checked result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ObjectMapError {
	/// An object-map or mapped-object format check failed.
	Format(apfs_format::Error),
	/// The requested transaction is zero or newer than the selected checkpoint.
	Transaction(TransactionId),
	/// A child, map, or object points into a reserved physical range.
	Address,
	/// The physical or virtual object's OID or XID disagrees with its context.
	Identity,
	/// A child does not match its parent's promised level or key range.
	Routing,
	/// A child points to a node already visited by this lookup.
	Cycle,
}

/// Why a declared volume was not admitted in the selected checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VolumeError {
	/// Invalid or unsupported volume superblock.
	Format(apfs_format::volume::Error),
	/// Volume OID lies outside the allocated virtual namespace.
	InvalidId,
	/// The occupied slot is beyond the declared volume capacity.
	SlotBounds(u32),
	/// The volume table declares the same OID twice.
	DuplicateId,
	/// Two resolved volumes share one UUID.
	DuplicateUuid,
	/// No visible mapping exists for an occupied table slot.
	MissingObject,
	/// The APSB slot index disagrees with its NXSB table index.
	SlotMismatch { expected: u32, actual: u32 },
	/// A tree reference aliases another declared object.
	AliasedTree,
	/// The filesystem root OID lies outside the allocated virtual namespace.
	InvalidRootId,
}

/// A source or container prevented reliable checkpoint selection or lookup.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error<E> {
	/// The block-zero copy failed format admission.
	Bootstrap(apfs_format::Error),
	/// The block-zero checkpoint area declarations are inconsistent.
	BootstrapGeometry(Corruption),
	/// The candidate's format is recognized but unsupported. Selection cannot safely fall back.
	Unsupported {
		/// Physical descriptor (zero for bootstrap).
		descriptor: BlockAddress,
		/// Verified transaction identifier.
		transaction: TransactionId,
		/// Why the profile is outside the supported scope.
		reason: Unsupported,
	},
	/// Discovery exceeded an explicit budget. No fallback is safe.
	Limit(Limit),
	/// Bounded work memory could not be obtained.
	Allocation,
	/// An exact read was outside the source.
	ReadBounds { offset: ByteOffset, bytes: u64 },
	/// An exact positional source read failed. No fallback is safe.
	Read { offset: ByteOffset, source: E },
	/// More than one descriptor claims the same verified transaction.
	AmbiguousTransaction(TransactionId),
	/// A descriptor is corrupt or incomplete. Its slot may be skipped with a diagnostic.
	CandidateCorruption(Damage),
	/// The ring contained no complete candidate in the supported profile.
	NoCheckpoint { diagnostics: Vec<Diagnostic> },
	/// Object-map or mapped-object admission failed at the given block.
	ObjectMap {
		/// Physical block associated with the failed lookup.
		address: BlockAddress,
		/// Specific failed check.
		reason: ObjectMapError,
	},
	/// Volume discovery failed for a declared OID.
	Volume {
		/// Virtual OID in the selected checkpoint's volume table.
		id: ObjectId,
		/// Specific failed check.
		reason: VolumeError,
	},
}

impl<E: fmt::Display> fmt::Display for Error<E> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Bootstrap(error) => write!(f, "invalid APFS bootstrap: {error}"),
			Self::BootstrapGeometry(reason) => {
				write!(f, "invalid APFS bootstrap geometry: {reason:?}")
			}
			Self::Unsupported {
				descriptor,
				transaction,
				reason,
			} => write!(
				f,
				"unsupported APFS checkpoint at block {}, XID {}: {reason:?}",
				descriptor.0, transaction.0
			),
			Self::Limit(limit) => write!(f, "APFS operation exhausted {limit:?} budget"),
			Self::Allocation => f.write_str("cannot allocate APFS workspace"),
			Self::ReadBounds { offset, bytes } => write!(
				f,
				"APFS read of {bytes} bytes at {} exceeds source",
				offset.0
			),
			Self::Read { offset, source } => {
				write!(f, "APFS read at byte {} failed: {source}", offset.0)
			}
			Self::AmbiguousTransaction(xid) => write!(
				f,
				"multiple APFS checkpoint descriptors claim XID {}",
				xid.0
			),
			Self::CandidateCorruption(damage) => write!(
				f,
				"invalid APFS checkpoint at block {}: {:?}",
				damage.descriptor.0, damage.reason
			),
			Self::NoCheckpoint { .. } => f.write_str("no complete APFS checkpoint was found"),
			Self::ObjectMap { address, reason } => {
				write!(
					f,
					"APFS object-map lookup failed at block {}: {reason:?}",
					address.0
				)
			}
			Self::Volume { id, reason } => {
				write!(
					f,
					"APFS volume discovery failed for OID {}: {reason:?}",
					id.0
				)
			}
		}
	}
}

impl<E: core::error::Error + 'static> core::error::Error for Error<E> {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			Self::Bootstrap(error) => Some(error),
			Self::Read { source, .. } => Some(source),
			Self::ObjectMap {
				reason: ObjectMapError::Format(error),
				..
			} => Some(error),
			Self::Volume {
				reason: VolumeError::Format(error),
				..
			} => Some(error),
			_ => None,
		}
	}
}
