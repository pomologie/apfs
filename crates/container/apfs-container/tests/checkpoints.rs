use std::collections::BTreeMap;

use apfs_container::{Container, Corruption, Diagnostic, Error, Limit, OpenOptions, Unsupported};
use apfs_core::{ByteOffset, ReadAt};
use apfs_format::{
	object::{ObjectId, TransactionId, checksum},
	superblock::BlockAddress,
};

const BLOCK_BYTES: usize = 4096;
const DEVICE_BYTES: u64 = 64 << 20;
const BOOTSTRAP: u64 = 0;
const EARLY_MAP: u64 = 1;
const EARLY_NXSB: u64 = 2;
const LATEST_MAP: u64 = 3;
const LATEST_NXSB: u64 = 4;
const LAST_DESCRIPTOR_BLOCK: u64 = 8;
const DATA_RING_START: u64 = 9;
const LATEST_FIRST_DATA: u64 = 11;
const DATA_RING_BLOCKS: u64 = 160;
const EARLY_OMAP: u64 = 191;
const LATEST_OMAP: u64 = 199;
const CHECKSUM_BYTES: usize = 8;
const OBJECT_ID_OFFSET: usize = 8;
const XID_OFFSET: usize = 16;
const INCOMPATIBLE_OFFSET: usize = 64;
const DESCRIPTOR_NEXT_OFFSET: usize = 128;
const DATA_NEXT_OFFSET: usize = 132;
const DESCRIPTOR_INDEX_OFFSET: usize = 136;
const DATA_INDEX_OFFSET: usize = 144;
const MAP_FLAGS_OFFSET: usize = 32;
const FIRST_MAPPING_OFFSET: usize = 40;
const MAPPING_BYTES: usize = 40;
const MAPPING_ID_OFFSET: usize = 24;
const MAPPING_PHYSICAL_OFFSET: usize = 32;
const LATEST_MAPPING_COUNT: usize = 4;
const EARLY_XID: TransactionId = TransactionId(1);
const LATEST_XID: TransactionId = TransactionId(2);

macro_rules! native_block {
	($address:literal) => {
		*include_bytes!(concat!(
			"../../../../tests/fixtures/native-block-",
			stringify!($address),
			".bin"
		))
	};
}

#[derive(Debug)]
struct Fixture(BTreeMap<u64, [u8; BLOCK_BYTES]>);

impl Fixture {
	fn native() -> Self {
		Self(BTreeMap::from([
			(BOOTSTRAP, native_block!(0)),
			(EARLY_MAP, native_block!(1)),
			(EARLY_NXSB, native_block!(2)),
			(LATEST_MAP, native_block!(3)),
			(LATEST_NXSB, native_block!(4)),
			// The provenance ledger records these verified blank native slots.
			(5, [0; BLOCK_BYTES]),
			(6, [0; BLOCK_BYTES]),
			(7, [0; BLOCK_BYTES]),
			(LAST_DESCRIPTOR_BLOCK, [0; BLOCK_BYTES]),
			(DATA_RING_START, native_block!(9)),
			(10, native_block!(10)),
			(LATEST_FIRST_DATA, native_block!(11)),
			(12, native_block!(12)),
			(13, native_block!(13)),
			(14, native_block!(14)),
			(EARLY_OMAP, native_block!(191)),
			(LATEST_OMAP, native_block!(199)),
		]))
	}

	fn set_u32(&mut self, block: u64, offset: usize, value: u32) {
		let bytes = self.0.get_mut(&block).unwrap();
		bytes[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
		update_checksum(bytes);
	}

	fn set_u64(&mut self, block: u64, offset: usize, value: u64) {
		let bytes = self.0.get_mut(&block).unwrap();
		bytes[offset..offset + size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
		update_checksum(bytes);
	}
}

fn update_checksum(bytes: &mut [u8]) {
	let sum = checksum(bytes).unwrap();
	bytes[..CHECKSUM_BYTES].copy_from_slice(&sum.to_le_bytes());
}

impl ReadAt for Fixture {
	type Error = u64;

	fn len(&self) -> u64 {
		DEVICE_BYTES
	}

	fn read_exact_at(&self, offset: ByteOffset, out: &mut [u8]) -> Result<(), Self::Error> {
		let mut start = offset.0;
		let mut destination = out;
		while !destination.is_empty() {
			let block = start / BLOCK_BYTES as u64;
			let within = (start % BLOCK_BYTES as u64) as usize;
			let bytes = self.0.get(&block).ok_or(block)?;
			let take = destination.len().min(BLOCK_BYTES - within);
			let (head, tail) = destination.split_at_mut(take);
			head.copy_from_slice(&bytes[within..within + take]);
			destination = tail;
			start += take as u64;
		}
		Ok(())
	}
}

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
	let mut fixture = Fixture::native();
	let fusion = 0x102;
	fixture.set_u64(LATEST_NXSB, INCOMPATIBLE_OFFSET, fusion);
	assert!(
		matches!(Container::open(fixture, OpenOptions::default()), Err(Error::Unsupported { transaction: LATEST_XID, reason: Unsupported::IncompatibleFeatures(flags), .. }) if flags == fusion)
	);
	let mut fixture = Fixture::native();
	let unknown_flags = 0x81;
	fixture.set_u32(LATEST_MAP, MAP_FLAGS_OFFSET, unknown_flags);
	assert!(
		matches!(Container::open(fixture, OpenOptions::default()), Err(Error::Unsupported { transaction: LATEST_XID, reason: Unsupported::CheckpointMapFlags(flags), .. }) if flags == unknown_flags)
	);
}

#[test]
fn reads_descriptor_and_data_spans_across_ring_wrap() {
	let mut fixture = Fixture::native();
	let wrapped_map = LAST_DESCRIPTOR_BLOCK;
	let wrapped_nxsb = EARLY_MAP;
	fixture.0.insert(wrapped_map, fixture.0[&LATEST_MAP]);
	fixture.0.insert(wrapped_nxsb, fixture.0[&LATEST_NXSB]);
	for obsolete in [EARLY_NXSB, LATEST_MAP, LATEST_NXSB] {
		fixture.0.insert(obsolete, [0; BLOCK_BYTES]);
	}
	fixture.set_u64(wrapped_map, OBJECT_ID_OFFSET, wrapped_map);
	fixture.set_u32(wrapped_nxsb, DESCRIPTOR_INDEX_OFFSET, 7);
	fixture.set_u32(wrapped_nxsb, DESCRIPTOR_NEXT_OFFSET, 1);
	let start = DATA_RING_BLOCKS - 2;
	fixture.set_u32(wrapped_nxsb, DATA_INDEX_OFFSET, start as u32);
	fixture.set_u32(wrapped_nxsb, DATA_NEXT_OFFSET, 2);
	for index in 0..LATEST_MAPPING_COUNT {
		let block = DATA_RING_START + (start + index as u64) % DATA_RING_BLOCKS;
		fixture
			.0
			.insert(block, fixture.0[&(LATEST_FIRST_DATA + index as u64)]);
		fixture.set_u64(
			wrapped_map,
			FIRST_MAPPING_OFFSET + index * MAPPING_BYTES + MAPPING_PHYSICAL_OFFSET,
			block,
		);
	}
	let view = Container::open(fixture, OpenOptions::default()).unwrap();
	assert_eq!(view.descriptor(), BlockAddress(wrapped_nxsb));
	assert_eq!(view.mappings().len(), LATEST_MAPPING_COUNT);
	assert!(view.diagnostics().is_empty());
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
