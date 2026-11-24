//! Bounded, immutable selection of APFS container checkpoints.
#![no_std]

extern crate alloc;

mod error;
mod validate;

use alloc::vec::Vec;
use core::cmp::Reverse;

use apfs_core::{ByteOffset, ReadAt};
use apfs_format::{
	checkpoint::Mapping,
	object::{Header, ObjectId, TransactionId},
	superblock::{BLOCK_SIZE_PREFIX_BYTES, BlockAddress, Geometry, Profile, Superblock},
};

pub use error::{Corruption, Damage, Error, Limit, Unsupported};

const BLOCK_ZERO: BlockAddress = BlockAddress(0);
const VERSION_TWO: u64 = 1 << 1;
const DEFAULT_MAX_DESCRIPTOR_BLOCKS: u32 = 4_096;
const DEFAULT_MAX_MAPPINGS: usize = 65_536;
const DEFAULT_MAX_OBJECT_BYTES: usize = 16 << 20;
const DEFAULT_MAX_READ_BYTES: u64 = 128 << 20;

/// Limits applied before allocation or disk traversal during checkpoint selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenOptions {
	/// Maximum number of slots admitted in the checkpoint descriptor ring.
	pub max_descriptor_blocks: u32,
	/// Maximum mapping records held for any candidate.
	pub max_mappings: usize,
	/// Maximum scratch bytes for a single checkpoint object, including NXSB.
	pub max_object_bytes: usize,
	/// Sum of all exact read sizes across discovery, including retries across candidates.
	pub max_read_bytes: u64,
}

impl Default for OpenOptions {
	fn default() -> Self {
		Self {
			max_descriptor_blocks: DEFAULT_MAX_DESCRIPTOR_BLOCKS,
			max_mappings: DEFAULT_MAX_MAPPINGS,
			max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
			max_read_bytes: DEFAULT_MAX_READ_BYTES,
		}
	}
}

/// A warning retained when discovery cannot establish a clean latest view.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Diagnostic {
	/// Descriptor evidence did not belong to a usable candidate.
	Rejected(Damage),
	/// The verified bootstrap header advertised a newer transaction than any selected one.
	NewerBootstrap {
		/// Transaction seen in block zero.
		advertised: TransactionId,
		/// Highest complete selected checkpoint.
		selected: TransactionId,
	},
}

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
		let mut probe = Probe {
			source: &source,
			options,
			bytes_left: options.max_read_bytes,
		};
		let bootstrap = probe.bootstrap()?;
		let ring = validate::Rings::from_bootstrap(&bootstrap).map_err(Error::BootstrapGeometry)?;
		if bootstrap.descriptors.blocks > options.max_descriptor_blocks {
			return Err(Error::Limit(Limit::DescriptorBlocks));
		}
		let mut scratch = Vec::new();
		let Scan {
			mut candidates,
			mut diagnostics,
		} = probe.scan(&bootstrap, &ring, &mut scratch)?;
		candidates.sort_unstable_by_key(|candidate| Reverse(candidate.xid));
		for (index, candidate) in candidates.iter().enumerate() {
			if candidates
				.get(index + 1)
				.is_some_and(|next| next.xid == candidate.xid)
			{
				return Err(Error::AmbiguousTransaction(candidate.xid));
			}
			let address = candidate.address;
			let result = probe.read_candidate(&bootstrap, &ring, *candidate, &mut scratch);
			let (selected, mappings) = match result {
				Ok(complete) => complete,
				Err(Error::CandidateCorruption(damage)) => {
					push(&mut diagnostics, Diagnostic::Rejected(damage))?;
					continue;
				}
				Err(error) => return Err(error),
			};
			if bootstrap.object.transaction > selected.object.transaction {
				push(
					&mut diagnostics,
					Diagnostic::NewerBootstrap {
						advertised: bootstrap.object.transaction,
						selected: selected.object.transaction,
					},
				)?;
			}
			return Ok(Self {
				source,
				selected,
				descriptor: address,
				mappings,
				diagnostics,
			});
		}
		Err(Error::NoCheckpoint { diagnostics })
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

#[derive(Clone, Copy)]
struct Candidate {
	address: BlockAddress,
	xid: TransactionId,
}

impl Candidate {
	fn reject<E>(self, reason: Corruption) -> Error<E> {
		Error::CandidateCorruption(Damage {
			descriptor: self.address,
			transaction: Some(self.xid),
			reason,
		})
	}

	fn unsupported<E>(self, reason: Unsupported) -> Error<E> {
		Error::Unsupported {
			descriptor: self.address,
			transaction: self.xid,
			reason,
		}
	}
}

struct Scan {
	candidates: Vec<Candidate>,
	diagnostics: Vec<Diagnostic>,
}

struct Probe<'source, S> {
	source: &'source S,
	options: OpenOptions,
	bytes_left: u64,
}

impl<S: ReadAt> Probe<'_, S> {
	fn read_exact(
		&mut self,
		offset: ByteOffset,
		destination: &mut [u8],
	) -> Result<(), Error<S::Error>> {
		let bytes = destination.len() as u64;
		if offset
			.0
			.checked_add(bytes)
			.is_none_or(|end| end > self.source.len())
		{
			return Err(Error::ReadBounds { offset, bytes });
		}
		self.bytes_left = self
			.bytes_left
			.checked_sub(bytes)
			.ok_or(Error::Limit(Limit::ReadBytes))?;
		self.source
			.read_exact_at(offset, destination)
			.map_err(|source| Error::Read { offset, source })
	}

	fn buffer(&self, bytes: usize, scratch: &mut Vec<u8>) -> Result<(), Error<S::Error>> {
		if bytes > self.options.max_object_bytes {
			return Err(Error::Limit(Limit::ObjectBytes));
		}
		if bytes > scratch.len() {
			scratch
				.try_reserve_exact(bytes - scratch.len())
				.map_err(|_| Error::Allocation)?;
		}
		scratch.resize(bytes, 0);
		Ok(())
	}

	fn read_blocks(
		&mut self,
		geometry: Geometry,
		address: BlockAddress,
		blocks: u64,
		scratch: &mut Vec<u8>,
	) -> Result<(), Error<S::Error>> {
		let range = geometry
			.byte_range(address, blocks)
			.map_err(Error::Bootstrap)?;
		let len = usize::try_from(range.end - range.start)
			.map_err(|_| Error::Limit(Limit::ObjectBytes))?;
		self.buffer(len, scratch)?;
		self.read_exact(ByteOffset(range.start), scratch)
	}

	fn bootstrap(&mut self) -> Result<Superblock, Error<S::Error>> {
		let mut prefix = [0; BLOCK_SIZE_PREFIX_BYTES];
		self.read_exact(ByteOffset(0), &mut prefix)?;
		let bytes = Superblock::block_size_hint(&prefix).map_err(Error::Bootstrap)? as usize;
		let mut scratch = Vec::new();
		self.buffer(bytes, &mut scratch)?;
		self.read_exact(ByteOffset(0), &mut scratch)?;
		let (header, profile) = Superblock::verified_profile(&scratch).map_err(Error::Bootstrap)?;
		let bootstrap = Candidate {
			address: BLOCK_ZERO,
			xid: header.transaction,
		};
		check_profile(profile).map_err(|reason| bootstrap.unsupported(reason))?;
		Superblock::decode(&scratch, self.source.len()).map_err(Error::Bootstrap)
	}

	fn scan(
		&mut self,
		bootstrap: &Superblock,
		rings: &validate::Rings,
		scratch: &mut Vec<u8>,
	) -> Result<Scan, Error<S::Error>> {
		let mut candidates = Vec::new();
		let mut diagnostics = Vec::new();
		for index in 0..bootstrap.descriptors.blocks {
			let address = BlockAddress(rings.descriptor.0 + u64::from(index));
			self.read_blocks(bootstrap.geometry, address, 1, scratch)?;
			if !Superblock::looks_like_superblock(scratch) {
				continue;
			}
			match Header::decode(scratch) {
				Ok(header) => push(
					&mut candidates,
					Candidate {
						address,
						xid: header.transaction,
					},
				)?,
				Err(error) => push(
					&mut diagnostics,
					Diagnostic::Rejected(Damage {
						descriptor: address,
						transaction: None,
						reason: Corruption::Format(error),
					}),
				)?,
			}
		}
		Ok(Scan {
			candidates,
			diagnostics,
		})
	}
}

fn check_profile(profile: Profile) -> Result<(), Unsupported> {
	if profile.incompatible != VERSION_TWO {
		return Err(Unsupported::IncompatibleFeatures(profile.incompatible));
	}
	if profile.has_keylocker {
		return Err(Unsupported::Keylocker);
	}
	if profile.fragmented_checkpoint_area {
		return Err(Unsupported::FragmentedCheckpointArea);
	}
	Ok(())
}

fn push<T, E>(list: &mut Vec<T>, item: T) -> Result<(), Error<E>> {
	list.try_reserve(1).map_err(|_| Error::Allocation)?;
	list.push(item);
	Ok(())
}
