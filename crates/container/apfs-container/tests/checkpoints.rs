use std::cell::RefCell;

use apfs_container::{Container, Corruption, Diagnostic, Error, Limit, OpenOptions, Unsupported};
use apfs_core::{ByteOffset, ReadAt};
use apfs_format::{
	object::{Header, ObjectId},
	superblock::{BLOCK_SIZE_PREFIX_BYTES, BlockAddress},
};
use fixture::*;

#[path = "checkpoint_selection/exact.rs"]
mod exact;
#[path = "../verification/checkpoint_fixture.rs"]
mod fixture;
#[path = "checkpoint_selection/hosted_parity.rs"]
mod hosted_parity;
#[path = "../verification/checkpoint_layouts.rs"]
mod layouts;
#[path = "../verification/checkpoint_selection.rs"]
mod model;
#[path = "checkpoint_selection/multiple_maps.rs"]
mod multiple_maps;
#[path = "checkpoint_selection/namespaces.rs"]
mod namespaces;
#[path = "object_map/lookup.rs"]
mod object_map;
#[path = "volume_objects/resolution.rs"]
mod volume_objects;
#[path = "volumes/discovery.rs"]
mod volumes;

#[test]
fn selects_native_fsck_checkpoint_even_with_stale_bootstrap() {
	let mut fixture = Fixture::native();
	fixture.0.insert(BOOTSTRAP, fixture.0[&EARLY_NXSB]);
	let view = Container::open(fixture, OpenOptions::default()).unwrap();
	assert_eq!(view.superblock().object.transaction, LATEST_XID);
	assert_eq!(view.descriptor(), BlockAddress(LATEST_NXSB));
	assert_eq!(view.mappings().len(), LATEST_MAPPING_COUNT);
	assert_eq!(
		view.ephemeral_mapping(ObjectId(1024)).unwrap().physical,
		BlockAddress(LATEST_FIRST_DATA)
	);
	assert!(view.diagnostics().is_empty());
}

#[test]
fn checksum_failure_falls_back_with_verified_transaction() {
	let mut fixture = Fixture::native();
	fixture.0.get_mut(&LATEST_FIRST_DATA).unwrap()[BLOCK_BYTES - 1] ^= 1;
	let view = Container::open(fixture, OpenOptions::default()).unwrap();
	assert_eq!(view.superblock().object.transaction, EARLY_XID);
	assert!(
		matches!(view.diagnostics(), [Diagnostic::Rejected(damage), Diagnostic::NewerBootstrap { advertised: LATEST_XID, selected: EARLY_XID }]
		if damage.transaction == Some(LATEST_XID) && damage.reason == Corruption::Format(apfs_format::Error::InvalidChecksum))
	);
}

#[test]
fn unsupported_latest_is_not_treated_as_rollback() {
	const VERSION_TWO_WITH_FUSION: u64 = 0x102;
	const FIRST_DESCRIPTOR_BLOCK: u64 = 1;
	const DESCRIPTOR_SLOTS: u64 = LAST_DESCRIPTOR_BLOCK - FIRST_DESCRIPTOR_BLOCK + 1;

	let mut fixture = Fixture::native();
	fixture.set_u64(LATEST_NXSB, INCOMPATIBLE_OFFSET, VERSION_TWO_WITH_FUSION);
	let source = CheckpointReadTrace {
		fixture,
		reads: RefCell::default(),
	};
	// Descriptor enumeration legitimately reads every ring slot, including map
	// objects. After that scan, the selected unsupported NXSB is the final read.
	let expected: Vec<_> = [
		(ByteOffset(BOOTSTRAP), BLOCK_SIZE_PREFIX_BYTES),
		full_read(BOOTSTRAP),
	]
	.into_iter()
	.chain((FIRST_DESCRIPTOR_BLOCK..=LAST_DESCRIPTOR_BLOCK).map(full_read))
	.chain([full_read(LATEST_NXSB)])
	.collect();
	let mut opens = 0;
	for transaction in [None, Some(LATEST_XID)] {
		let options = OpenOptions::default();
		let result = match transaction {
			Some(xid) => Container::open_at(&source, options, xid),
			None => Container::open(&source, options),
		};
		assert!(matches!(
			result,
			Err(Error::Unsupported {
				descriptor: BlockAddress(LATEST_NXSB),
				transaction: LATEST_XID,
				reason: Unsupported::IncompatibleFeatures(VERSION_TWO_WITH_FUSION),
			})
		));
		assert_eq!(*source.reads.borrow(), expected);
		source.reads.borrow_mut().clear();
		opens += 1;
	}
	println!(
		"\nAPFS bootstrap property candidate-feature-cutoff {DESCRIPTOR_SLOTS} {opens} {}",
		expected.len()
	);

	let mut fixture = Fixture::native();
	let unknown_flags = 0x81;
	fixture.set_u32(LATEST_MAP, MAP_FLAGS_OFFSET, unknown_flags);
	assert!(
		matches!(Container::open(fixture, OpenOptions::default()), Err(Error::Unsupported { transaction: LATEST_XID, reason: Unsupported::CheckpointMapFlags(flags), .. }) if flags == unknown_flags)
	);
}

fn full_read(block: u64) -> (ByteOffset, usize) {
	(ByteOffset(block * BLOCK_BYTES as u64), BLOCK_BYTES)
}

struct CheckpointReadTrace {
	fixture: Fixture,
	reads: RefCell<Vec<(ByteOffset, usize)>>,
}

impl ReadAt for CheckpointReadTrace {
	type Error = <Fixture as ReadAt>::Error;

	fn len(&self) -> u64 {
		self.fixture.len()
	}

	fn read_exact_at(&self, offset: ByteOffset, out: &mut [u8]) -> Result<(), Self::Error> {
		self.reads.borrow_mut().push((offset, out.len()));
		self.fixture.read_exact_at(offset, out)
	}
}

#[test]
fn reads_descriptor_and_data_spans_across_ring_wrap() {
	let mut fixture = Fixture::wrapped_descriptors();
	let start = DATA_RING_BLOCKS - 2;
	fixture.set_u32(WRAPPED_NXSB, DATA_INDEX_OFFSET, start as u32);
	fixture.set_u32(WRAPPED_NXSB, DATA_NEXT_OFFSET, 2);
	for index in 0..LATEST_MAPPING_COUNT {
		let block = DATA_RING_START + (start + index as u64) % DATA_RING_BLOCKS;
		fixture
			.0
			.insert(block, fixture.0[&(LATEST_FIRST_DATA + index as u64)]);
		fixture.set_u64(
			LAST_DESCRIPTOR_BLOCK,
			FIRST_MAPPING_OFFSET + index * MAPPING_BYTES + MAPPING_PHYSICAL_OFFSET,
			block,
		);
	}
	let view = Container::open(fixture, OpenOptions::default()).unwrap();
	assert_eq!(view.descriptor(), BlockAddress(WRAPPED_NXSB));
	assert_eq!(view.mappings().len(), LATEST_MAPPING_COUNT);
	assert!(view.diagnostics().is_empty());
}

#[test]
fn wrapped_checkpoint_requires_its_map_even_with_a_verified_descriptor() {
	let options = OpenOptions::default();
	let complete = Container::open(Fixture::wrapped_descriptors(), options).unwrap();
	assert_eq!(complete.descriptor(), BlockAddress(WRAPPED_NXSB));
	assert_eq!(complete.superblock().object.transaction, LATEST_XID);
	assert!(complete.diagnostics().is_empty());

	let mut fixture = Fixture::wrapped_descriptors();
	fixture.0.insert(LAST_DESCRIPTOR_BLOCK, [0; BLOCK_BYTES]);
	assert_eq!(
		Header::decode(&fixture.0[&WRAPPED_NXSB])
			.unwrap()
			.transaction,
		LATEST_XID
	);
	assert!(matches!(
		Container::open_at(fixture, options, LATEST_XID),
		Err(Error::CandidateCorruption(damage))
			if damage.descriptor == BlockAddress(WRAPPED_NXSB)
				&& damage.transaction == Some(LATEST_XID)
	));

	let mut fixture = Fixture::wrapped_descriptors();
	fixture.0.insert(LAST_DESCRIPTOR_BLOCK, [0; BLOCK_BYTES]);
	let latest = Container::open(fixture, options).unwrap();
	assert_eq!(latest.descriptor(), BlockAddress(MOVED_EARLY_NXSB));
	assert_eq!(latest.superblock().object.transaction, EARLY_XID);
	assert!(matches!(
		latest.diagnostics(),
		[
			Diagnostic::Rejected(damage),
			Diagnostic::NewerBootstrap { advertised: LATEST_XID, selected: EARLY_XID },
		] if damage.descriptor == BlockAddress(WRAPPED_NXSB)
			&& damage.transaction == Some(LATEST_XID)
	));

	let mut fixture = Fixture::wrapped_descriptors();
	for map in [LAST_DESCRIPTOR_BLOCK, MOVED_EARLY_MAP] {
		fixture.0.insert(map, [0; BLOCK_BYTES]);
	}
	assert!(matches!(
		Container::open(fixture, options),
		Err(Error::NoCheckpoint { diagnostics })
			if matches!(diagnostics.as_slice(), [
				Diagnostic::Rejected(newer), Diagnostic::Rejected(older),
			] if newer.transaction == Some(LATEST_XID)
				&& older.transaction == Some(EARLY_XID))
	));
}

#[test]
fn rejects_duplicate_ids_and_checkpoint_mixing() {
	let mut fixture = Fixture::native();
	fixture.set_u64(
		LATEST_MAP,
		FIRST_MAPPING_OFFSET + MAPPING_BYTES + MAPPING_ID_OFFSET,
		1024,
	);
	let view = Container::open(fixture, OpenOptions::default()).unwrap();
	assert_eq!(view.superblock().object.transaction, EARLY_XID);
	assert!(
		matches!(&view.diagnostics()[0], Diagnostic::Rejected(damage) if damage.reason == Corruption::Object)
	);
	let mut fixture = Fixture::native();
	fixture.set_u64(LATEST_FIRST_DATA, XID_OFFSET, EARLY_XID.0);
	let view = Container::open(fixture, OpenOptions::default()).unwrap();
	assert_eq!(view.superblock().object.transaction, EARLY_XID);
	assert!(
		matches!(&view.diagnostics()[0], Diagnostic::Rejected(damage) if damage.reason == Corruption::Object)
	);
}

#[test]
fn does_not_mask_source_failures_or_budget_exhaustion() {
	let mut fixture = Fixture::native();
	fixture.0.remove(&LATEST_FIRST_DATA);
	assert!(matches!(
		Container::open(fixture, OpenOptions::default()),
		Err(Error::Read {
			source: LATEST_FIRST_DATA,
			..
		})
	));
	let default = OpenOptions::default();
	for (options, expected) in [
		(
			OpenOptions {
				max_descriptor_blocks: 7,
				..default
			},
			Limit::DescriptorBlocks,
		),
		(
			OpenOptions {
				max_mappings: LATEST_MAPPING_COUNT - 1,
				..default
			},
			Limit::Mappings,
		),
		(
			OpenOptions {
				max_object_bytes: BLOCK_BYTES - 1,
				..default
			},
			Limit::ObjectBytes,
		),
		(
			OpenOptions {
				max_read_bytes: BLOCK_BYTES as u64,
				..default
			},
			Limit::ReadBytes,
		),
	] {
		assert!(
			matches!(Container::open(Fixture::native(), options), Err(Error::Limit(limit)) if limit == expected)
		);
	}
}

#[test]
fn block_zero_is_not_a_candidate() {
	let mut fixture = Fixture::native();
	for missing in [EARLY_NXSB, LATEST_NXSB] {
		fixture.0.insert(missing, [0; BLOCK_BYTES]);
	}
	assert!(matches!(
		Container::open(fixture, OpenOptions::default()),
		Err(Error::NoCheckpoint { .. })
	));
}

#[test]
fn damaged_signature_and_old_incompatible_map_are_diagnosed_as_corruption() {
	let mut fixture = Fixture::native();
	fixture.0.get_mut(&LATEST_NXSB).unwrap()[apfs_format::object::HEADER_BYTES] ^= 1;
	let view = Container::open(fixture, OpenOptions::default()).unwrap();
	assert!(
		matches!(view.diagnostics(), [Diagnostic::Rejected(damage), Diagnostic::NewerBootstrap { .. }]
		if damage.descriptor == BlockAddress(LATEST_NXSB) && damage.transaction.is_none())
	);

	let mut fixture = Fixture::native();
	fixture.set_u64(LATEST_MAP, XID_OFFSET, EARLY_XID.0);
	fixture.set_u32(LATEST_MAP, MAP_FLAGS_OFFSET, 0x81);
	let view = Container::open(fixture, OpenOptions::default()).unwrap();
	assert!(
		matches!(view.diagnostics(), [Diagnostic::Rejected(damage), Diagnostic::NewerBootstrap { .. }]
		if damage.descriptor == BlockAddress(LATEST_NXSB) && damage.reason == Corruption::Object)
	);
}
