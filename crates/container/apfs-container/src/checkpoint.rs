use core::cmp::Reverse;

use apfs_core::{ByteOffset, ReadAt};
use apfs_format::{
	checkpoint::Mapping,
	object::{Header, TransactionId},
	superblock::{BLOCK_SIZE_PREFIX_BYTES, BlockAddress, Profile, Superblock},
};

use crate::{
	Corruption, Damage, Error, Limit, Unsupported,
	alloc::vec::Vec,
	allocation::push,
	probe::{BLOCK_ZERO, DEFAULT_MAX_OBJECT_BYTES, DEFAULT_MAX_READ_BYTES, Probe},
};

mod validate;

const BOOTSTRAP_OFFSET: ByteOffset = ByteOffset(0);
const VERSION_TWO: u64 = 1 << 1;
const DEFAULT_MAX_DESCRIPTOR_BLOCKS: u32 = 4_096;
const DEFAULT_MAX_MAPPINGS: usize = 65_536;

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

pub(super) struct Selected {
	pub(super) selected: Superblock,
	pub(super) descriptor: BlockAddress,
	pub(super) mappings: Vec<Mapping>,
	pub(super) diagnostics: Vec<Diagnostic>,
}

pub(super) fn select<S: ReadAt>(
	source: &S,
	options: OpenOptions,
	transaction: Option<TransactionId>,
) -> Result<Selected, Error<S::Error>> {
	let mut discovery = Discovery {
		probe: Probe::new(source, options.max_object_bytes, options.max_read_bytes),
		max_mappings: options.max_mappings,
	};
	let bootstrap = discovery.bootstrap()?;
	let ring = validate::Rings::from_bootstrap(&bootstrap).map_err(Error::BootstrapGeometry)?;
	if bootstrap.descriptors.blocks > options.max_descriptor_blocks {
		return Err(Error::Limit(Limit::DescriptorBlocks));
	}
	let mut scratch = Vec::new();
	let Scan {
		mut candidates,
		mut diagnostics,
	} = discovery.scan(&bootstrap, &ring, transaction, &mut scratch)?;
	candidates.sort_unstable_by_key(|candidate| Reverse(candidate.xid));
	for (index, candidate) in candidates.iter().enumerate() {
		if candidates
			.get(index + 1)
			.is_some_and(|next| next.xid == candidate.xid)
		{
			return Err(Error::AmbiguousTransaction(candidate.xid));
		}
		let address = candidate.address;
		let result = discovery.read_candidate(&bootstrap, &ring, *candidate, &mut scratch);
		let (selected, mappings) = match result {
			Ok(complete) => complete,
			Err(Error::CandidateCorruption(damage)) if transaction.is_none() => {
				push(&mut diagnostics, Diagnostic::Rejected(damage))?;
				continue;
			}
			Err(error) => return Err(error),
		};
		if transaction.is_none() && bootstrap.object.transaction > selected.object.transaction {
			push(
				&mut diagnostics,
				Diagnostic::NewerBootstrap {
					advertised: bootstrap.object.transaction,
					selected: selected.object.transaction,
				},
			)?;
		}
		return Ok(Selected {
			selected,
			descriptor: address,
			mappings,
			diagnostics,
		});
	}
	Err(match transaction {
		Some(transaction) => Error::CheckpointNotFound {
			transaction,
			diagnostics,
		},
		None => Error::NoCheckpoint { diagnostics },
	})
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

struct Discovery<'source, S> {
	probe: Probe<'source, S>,
	max_mappings: usize,
}

impl<S: ReadAt> Discovery<'_, S> {
	fn bootstrap(&mut self) -> Result<Superblock, Error<S::Error>> {
		let mut prefix = [0; BLOCK_SIZE_PREFIX_BYTES];
		self.probe.read_exact(BOOTSTRAP_OFFSET, &mut prefix)?;
		let bytes = Superblock::block_size_hint(&prefix).map_err(Error::Bootstrap)? as usize;
		let mut scratch = Vec::new();
		self.probe.buffer(bytes, &mut scratch)?;
		self.probe.read_exact(BOOTSTRAP_OFFSET, &mut scratch)?;
		let (header, profile) = Superblock::verified_profile(&scratch).map_err(Error::Bootstrap)?;
		let bootstrap = Candidate {
			address: BLOCK_ZERO,
			xid: header.transaction,
		};
		check_profile(profile).map_err(|reason| bootstrap.unsupported(reason))?;
		Superblock::decode(&scratch, self.probe.source_len()).map_err(Error::Bootstrap)
	}

	fn scan(
		&mut self,
		bootstrap: &Superblock,
		rings: &validate::Rings,
		transaction: Option<TransactionId>,
		scratch: &mut Vec<u8>,
	) -> Result<Scan, Error<S::Error>> {
		let mut candidates = Vec::new();
		let mut diagnostics = Vec::new();
		for index in 0..bootstrap.descriptors.blocks {
			let address = BlockAddress(rings.descriptor.0 + u64::from(index));
			self.probe
				.read_blocks(bootstrap.geometry, address, 1, scratch)?;
			if !Superblock::looks_like_superblock(scratch) {
				continue;
			}
			match Header::decode(scratch) {
				Ok(header)
					if transaction.is_none_or(|requested| header.transaction == requested) =>
				{
					push(
						&mut candidates,
						Candidate {
							address,
							xid: header.transaction,
						},
					)?
				}
				Ok(_) => {}
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
