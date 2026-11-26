use core::ops::Range;

use apfs_container::{Container, Error, Limit, OpenOptions};
use apfs_format::superblock::BlockAddress;

use super::{
	BLOCK_BYTES, DESCRIPTOR_INDEX_OFFSET, DESCRIPTOR_NEXT_OFFSET, EARLY_MAP, EARLY_NXSB,
	FIRST_MAPPING_OFFSET, Fixture, LAST_DESCRIPTOR_BLOCK, LATEST_MAP, LATEST_MAPPING_COUNT,
	LATEST_NXSB, LATEST_XID, MAP_FLAGS_OFFSET, MAPPING_BYTES, OBJECT_ID_OFFSET,
};

const MAP_COUNT_OFFSET: usize = MAP_FLAGS_OFFSET + size_of::<u32>();
const DESCRIPTOR_LENGTH_OFFSET: usize = DESCRIPTOR_INDEX_OFFSET + size_of::<u32>();
const FIRST_MAP_SLOT: u32 = 7;
const DESCRIPTOR_LENGTH: u32 = 3;
const NEXT_DESCRIPTOR_SLOT: u32 = 2;
const MAP_SPLIT_INDEX: usize = 2;

#[test]
fn selects_a_wrapped_checkpoint_with_two_map_blocks() {
	let options = OpenOptions {
		max_mappings: LATEST_MAPPING_COUNT,
		..OpenOptions::default()
	};
	let ordinary = Container::open(Fixture::native(), options).unwrap();
	let mut fixture = Fixture::native();
	let native_map = fixture.0[&LATEST_MAP];
	let native_descriptor = fixture.0[&LATEST_NXSB];
	for address in [LATEST_MAP, LATEST_NXSB] {
		fixture.0.insert(address, [0; BLOCK_BYTES]);
	}

	// The larger IDs appear first on disk. The returned mappings still have to
	// be sorted by object ID after validation of the complete data span.
	place_map(
		&mut fixture,
		&native_map,
		LAST_DESCRIPTOR_BLOCK,
		MAP_SPLIT_INDEX..LATEST_MAPPING_COUNT,
		false,
	);
	place_map(
		&mut fixture,
		&native_map,
		EARLY_MAP,
		0..MAP_SPLIT_INDEX,
		true,
	);
	fixture.0.insert(EARLY_NXSB, native_descriptor);
	fixture.set_u32(EARLY_NXSB, DESCRIPTOR_INDEX_OFFSET, FIRST_MAP_SLOT);
	fixture.set_u32(EARLY_NXSB, DESCRIPTOR_LENGTH_OFFSET, DESCRIPTOR_LENGTH);
	fixture.set_u32(EARLY_NXSB, DESCRIPTOR_NEXT_OFFSET, NEXT_DESCRIPTOR_SLOT);

	let automatic = Container::open(&fixture, options).unwrap();
	let exact = Container::open_at(&fixture, options, LATEST_XID).unwrap();
	for view in [automatic, exact] {
		assert_eq!(view.superblock().object.transaction, LATEST_XID);
		assert_eq!(view.descriptor(), BlockAddress(EARLY_NXSB));
		assert_eq!(view.mappings(), ordinary.mappings());
		assert!(view.diagnostics().is_empty());
	}
	let limited = OpenOptions {
		max_mappings: LATEST_MAPPING_COUNT - 1,
		..options
	};
	assert!(matches!(
		Container::open_at(&fixture, limited, LATEST_XID),
		Err(Error::Limit(Limit::Mappings))
	));
}

fn place_map(
	fixture: &mut Fixture,
	native_map: &[u8; BLOCK_BYTES],
	address: u64,
	records: Range<usize>,
	is_last: bool,
) {
	let mut map = [0; BLOCK_BYTES];
	let records_end = FIRST_MAPPING_OFFSET + records.len() * MAPPING_BYTES;
	let byte_offset = |index| FIRST_MAPPING_OFFSET + index * MAPPING_BYTES;
	map[..FIRST_MAPPING_OFFSET].copy_from_slice(&native_map[..FIRST_MAPPING_OFFSET]);
	map[FIRST_MAPPING_OFFSET..records_end]
		.copy_from_slice(&native_map[byte_offset(records.start)..byte_offset(records.end)]);
	fixture.0.insert(address, map);
	fixture.set_u64(address, OBJECT_ID_OFFSET, address);
	fixture.set_u32(address, MAP_COUNT_OFFSET, records.len() as u32);
	fixture.set_u32(address, MAP_FLAGS_OFFSET, u32::from(is_last));
}
