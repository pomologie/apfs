//! A-CONT-03-T01 container-map and A-CONT-04-T01 physical fixed-node coverage.

use apfs_container::{
	Container, Error, Limit, LookupOptions, ObjectMapError, OpenOptions, VirtualType,
};
use apfs_core::ByteOffset;
use apfs_format::{
	object::{ObjectId, TransactionId},
	superblock::BlockAddress,
};

use super::{
	BLOCK_BYTES, DATA_RING_START, DEVICE_BYTES, EARLY_XID, Fixture, LATEST_FIRST_DATA, LATEST_OMAP,
	LATEST_OMAP_ROOT, LATEST_XID, OBJECT_ID_OFFSET, VOLUME_SUPERBLOCK, XID_OFFSET, update_checksum,
};

const VOLUME_ID: ObjectId = ObjectId(1026);
const ABSENT_ID: ObjectId = ObjectId(VOLUME_ID.0 + 1);
const NATIVE_VOLUME_TYPE: VirtualType = VirtualType {
	kind: 0x000d,
	subtype: 0,
};
const APSB_MAGIC: &[u8; 4] = b"APSB";
const VOLUME_MAGIC_OFFSET: usize = 32;
const VOLUME_UUID_OFFSET: usize = 240;
const FSCK_VOLUME_UUID: [u8; 16] = 0x55dd_69c3_cb57_4400_bd30_0676_0ace_eaef_u128.to_be_bytes();
const OBJECT_TYPE_OFFSET: usize = 24;
const OBJECT_SUBTYPE_OFFSET: usize = 28;
const OBJECT_MAP_SUBTYPE: u32 = 0x000b;
const OBJECT_STORAGE_PHYSICAL: u32 = 1 << 30;
const CHILD_OBJECT_TYPE: u32 = OBJECT_STORAGE_PHYSICAL | 0x0003;
const FIXED_LEAF_FLAGS: u16 = 6;
const FIXED_ROOT_FLAGS: u16 = 5;
const EARLY_LEAF: u64 = 193;
const LATEST_LEAF: u64 = 194;
const EARLY_VOLUME_BLOCK: u64 = 197;

const NODE_FLAGS: usize = 32;
const NODE_LEVEL: usize = 34;
const NODE_RECORDS: usize = 36;
const NODE_TABLE_START: usize = 40;
const NODE_TABLE_LENGTH: usize = 42;
const NODE_FREE_START: usize = 44;
const NODE_FREE_LENGTH: usize = 46;
const NODE_KEY_LIST: usize = 48;
const NODE_VALUE_LIST: usize = 52;
const NODE_DATA_START: usize = 56;
const KEY_BYTES: usize = 16;
const LEAF_BYTES: usize = 16;
const CHILD_BYTES: usize = 8;
const SLOT_BYTES: usize = 4;
const FOOTER_BYTES: usize = 40;
const ROOT_VALUE_END: usize = BLOCK_BYTES - FOOTER_BYTES;
const ROOT_KEY_COUNT: usize = ROOT_VALUE_END + 24;
const ROOT_NODE_COUNT: usize = ROOT_VALUE_END + 32;
const ROOT_TABLE_BYTES: usize = 448;
const ROOT_KEYS: usize = NODE_DATA_START + ROOT_TABLE_BYTES;
const LEAF_TABLE_BYTES: usize = 2 * SLOT_BYTES;
const LEAF_KEYS: usize = NODE_DATA_START + LEAF_TABLE_BYTES;
const FIRST_LEAF_VALUE: usize = BLOCK_BYTES - LEAF_BYTES;
const MAPPING_FLAGS_OFFSET: usize = 0;
const MAPPING_SIZE_OFFSET: usize = 4;
const MAPPING_ADDRESS_OFFSET: usize = 8;
const TOMBSTONE_FLAG: u32 = 1;
const ENCRYPTED_FLAG: u32 = 1 << 2;

#[test]
fn reads_native_maps_and_verifies_the_selected_volume_object() {
	let view = open(Fixture::native());
	let opts = LookupOptions::default();

	assert_eq!(
		view.superblock().volume_ids().collect::<Vec<_>>(),
		[VOLUME_ID]
	);
	assert!(
		view.lookup_virtual_mapping(VOLUME_ID, EARLY_XID, opts)
			.unwrap()
			.is_none()
	);
	assert!(
		view.lookup_virtual_mapping(ABSENT_ID, LATEST_XID, opts)
			.unwrap()
			.is_none()
	);
	let object = view
		.read_virtual_object(VOLUME_ID, NATIVE_VOLUME_TYPE, opts)
		.unwrap()
		.unwrap();
	assert_eq!(object.header.id, VOLUME_ID);
	assert_eq!(object.header.transaction, LATEST_XID);
	assert_eq!(object.mapping.address, BlockAddress(VOLUME_SUPERBLOCK));
	assert_eq!(object.mapping.size, BLOCK_BYTES as u32);
	assert_eq!(
		&object.as_bytes()[VOLUME_MAGIC_OFFSET..][..APSB_MAGIC.len()],
		APSB_MAGIC
	);
	assert_eq!(
		object.as_bytes()[VOLUME_UUID_OFFSET..][..FSCK_VOLUME_UUID.len()],
		FSCK_VOLUME_UUID
	);

	let mut fixture = Fixture::native();
	fixture.0.get_mut(&LATEST_FIRST_DATA).unwrap()[BLOCK_BYTES - 1] ^= 1;
	let earlier = open(fixture);
	assert_eq!(earlier.superblock().object.transaction, EARLY_XID);
	assert!(
		earlier
			.lookup_virtual_mapping(VOLUME_ID, EARLY_XID, opts)
			.unwrap()
			.is_none()
	);
}

#[test]
fn resolves_a_version_across_child_boundaries_and_honors_tombstones() {
	let view = open(split_map(TOMBSTONE_FLAG));
	let opts = LookupOptions::default();
	let prior = view
		.lookup_virtual_mapping(VOLUME_ID, EARLY_XID, opts)
		.unwrap()
		.unwrap();
	assert_eq!(prior.transaction, EARLY_XID);
	assert_eq!(prior.address, BlockAddress(EARLY_VOLUME_BLOCK));
	assert!(
		view.lookup_virtual_mapping(VOLUME_ID, LATEST_XID, opts)
			.unwrap()
			.is_none()
	);
	assert!(
		view.read_virtual_object(VOLUME_ID, NATIVE_VOLUME_TYPE, opts)
			.unwrap()
			.is_none()
	);
	assert!(matches!(
		view.lookup_virtual_mapping(VOLUME_ID, TransactionId(LATEST_XID.0 + 1), opts),
		Err(Error::ObjectMap {
			reason: ObjectMapError::Transaction(_),
			..
		})
	));

	let view = open(split_map(0));
	let newest = view
		.lookup_virtual_mapping(VOLUME_ID, LATEST_XID, opts)
		.unwrap()
		.unwrap();
	assert_eq!(newest.transaction, LATEST_XID);
	assert_eq!(newest.address, BlockAddress(VOLUME_SUPERBLOCK));
}

#[test]
fn refuses_out_of_range_or_checkpoint_space_mappings() {
	let opts = LookupOptions::default();
	let blocks_outside_device = DEVICE_BYTES / BLOCK_BYTES as u64;
	for (mapped, expected) in [
		(
			blocks_outside_device,
			ObjectMapError::Format(apfs_format::Error::InvalidGeometry),
		),
		(DATA_RING_START, ObjectMapError::Address),
	] {
		let mut fixture = split_map(0);
		fixture.set_u64(
			LATEST_LEAF,
			FIRST_LEAF_VALUE + MAPPING_ADDRESS_OFFSET,
			mapped,
		);
		assert!(matches!(
			open(fixture).lookup_virtual_mapping(VOLUME_ID, LATEST_XID, opts),
			Err(Error::ObjectMap { reason, .. }) if reason == expected
		));
	}

	let mut fixture = split_map(0);
	fixture.set_u32(
		LATEST_LEAF,
		FIRST_LEAF_VALUE + MAPPING_FLAGS_OFFSET,
		ENCRYPTED_FLAG,
	);
	assert!(matches!(
		open(fixture).lookup_virtual_mapping(VOLUME_ID, LATEST_XID, opts),
		Err(Error::ObjectMap {
			reason: ObjectMapError::Format(apfs_format::Error::UnsupportedObjectMapFlags(
				ENCRYPTED_FLAG
			)),
			..
		})
	));
}

#[test]
fn refuses_corrupt_layout_keys_routes_and_cycles() {
	let opts = LookupOptions::default();
	let mut fixture = split_map(0);
	// The second TOC key starts eight bytes into the first key.
	let root = fixture.0.get_mut(&LATEST_OMAP_ROOT).unwrap();
	put_slot(root, 1, KEY_BYTES / 2, 2 * CHILD_BYTES);
	update_checksum(root);
	assert!(matches!(
		open(fixture).lookup_virtual_mapping(VOLUME_ID, LATEST_XID, opts),
		Err(Error::ObjectMap {
			reason: ObjectMapError::Format(apfs_format::Error::InvalidObjectMap),
			..
		})
	));
	let mut fixture = split_map(0);
	fixture.set_u64(LATEST_LEAF, LEAF_KEYS, ABSENT_ID.0);
	assert!(matches!(
		open(fixture).lookup_virtual_mapping(VOLUME_ID, LATEST_XID, opts),
		Err(Error::ObjectMap {
			reason: ObjectMapError::Routing,
			..
		})
	));
	let mut fixture = split_map(0);
	fixture.set_u64(
		LATEST_OMAP_ROOT,
		ROOT_VALUE_END - 2 * CHILD_BYTES,
		LATEST_OMAP_ROOT,
	);
	assert!(matches!(
		open(fixture).lookup_virtual_mapping(VOLUME_ID, LATEST_XID, opts),
		Err(Error::ObjectMap {
			reason: ObjectMapError::Cycle,
			..
		})
	));
	let mut fixture = split_map(0);
	// A child with valid local contents cannot be newer than its parent.
	fixture.set_u64(LATEST_LEAF, XID_OFFSET, LATEST_XID.0 + 1);
	assert!(matches!(
		open(fixture).lookup_virtual_mapping(VOLUME_ID, LATEST_XID, opts),
		Err(Error::ObjectMap {
			reason: ObjectMapError::Identity,
			..
		})
	));
}

#[test]
fn maps_and_mapped_objects_keep_independent_budgets_and_identity_checks() {
	let view = open(split_map(0));
	let opts = LookupOptions::default();
	assert!(matches!(
		view.lookup_virtual_mapping(
			VOLUME_ID,
			LATEST_XID,
			LookupOptions {
				max_nodes: 1,
				..opts
			}
		),
		Err(Error::Limit(Limit::ObjectMapNodes))
	));
	assert!(matches!(
		view.read_virtual_object(
			VOLUME_ID,
			NATIVE_VOLUME_TYPE,
			LookupOptions {
				max_read_bytes: 3 * BLOCK_BYTES as u64,
				..opts
			}
		),
		Err(Error::Limit(Limit::ReadBytes))
	));
	assert!(matches!(
		view.lookup_virtual_mapping(
			VOLUME_ID,
			LATEST_XID,
			LookupOptions {
				max_object_bytes: BLOCK_BYTES - 1,
				..opts
			}
		),
		Err(Error::Limit(Limit::ObjectBytes))
	));

	let mut fixture = Fixture::native();
	fixture.0.remove(&VOLUME_SUPERBLOCK);
	assert!(matches!(
		open(fixture).read_virtual_object(VOLUME_ID, NATIVE_VOLUME_TYPE, opts),
		Err(Error::Read { offset: ByteOffset(offset), source: VOLUME_SUPERBLOCK }) if offset == VOLUME_SUPERBLOCK * BLOCK_BYTES as u64
	));

	let mut fixture = Fixture::native();
	fixture.set_u32(
		VOLUME_SUPERBLOCK,
		OBJECT_TYPE_OFFSET,
		OBJECT_STORAGE_PHYSICAL | u32::from(NATIVE_VOLUME_TYPE.kind),
	);
	assert!(matches!(
		open(fixture).read_virtual_object(VOLUME_ID, NATIVE_VOLUME_TYPE, opts),
		Err(Error::ObjectMap {
			reason: ObjectMapError::Format(apfs_format::Error::UnexpectedObjectType(_)),
			..
		})
	));

	let mut fixture = Fixture::native();
	fixture.set_u64(VOLUME_SUPERBLOCK, OBJECT_ID_OFFSET, ABSENT_ID.0);
	assert!(matches!(
		open(fixture).read_virtual_object(VOLUME_ID, NATIVE_VOLUME_TYPE, opts),
		Err(Error::ObjectMap {
			reason: ObjectMapError::Identity,
			..
		})
	));
}

#[test]
fn keeps_object_map_status_separate_from_checkpoint_selection() {
	const MAP_FLAGS: usize = 32;
	const MANUALLY_MANAGED: u32 = 1;
	const ENCRYPTING: u32 = 1 << 1;

	let mut fixture = Fixture::native();
	fixture.set_u32(LATEST_OMAP, MAP_FLAGS, MANUALLY_MANAGED | ENCRYPTING);
	let view = open(fixture);
	assert_eq!(view.superblock().object.transaction, LATEST_XID);
	assert!(matches!(
		view.lookup_virtual_mapping(VOLUME_ID, LATEST_XID, LookupOptions::default()),
		Err(Error::ObjectMap {
			reason: ObjectMapError::Format(apfs_format::Error::UnsupportedObjectMapFlags(_)),
			..
		})
	));
}

fn open(fixture: Fixture) -> Container<Fixture> {
	Container::open(fixture, OpenOptions::default()).unwrap()
}

fn split_map(latest_flags: u32) -> Fixture {
	let mut fixture = Fixture::native();
	let root = fixture.0.get_mut(&LATEST_OMAP_ROOT).unwrap();
	put_u16(root, NODE_FLAGS, FIXED_ROOT_FLAGS);
	put_u16(root, NODE_LEVEL, 1);
	put_u32(root, NODE_RECORDS, 2);
	put_free(
		root,
		ROOT_KEYS,
		2 * KEY_BYTES,
		ROOT_VALUE_END - 2 * CHILD_BYTES,
	);
	put_u64(root, ROOT_KEY_COUNT, 2);
	put_u64(root, ROOT_NODE_COUNT, 3);
	for (index, (version, child)) in [(EARLY_XID, EARLY_LEAF), (LATEST_XID, LATEST_LEAF)]
		.into_iter()
		.enumerate()
	{
		put_slot(root, index, index * KEY_BYTES, (index + 1) * CHILD_BYTES);
		put_key(root, ROOT_KEYS + index * KEY_BYTES, VOLUME_ID, version);
		put_u64(root, ROOT_VALUE_END - (index + 1) * CHILD_BYTES, child);
	}
	update_checksum(root);

	fixture.0.insert(
		EARLY_LEAF,
		leaf(EARLY_LEAF, EARLY_XID, 0, EARLY_VOLUME_BLOCK),
	);
	fixture.0.insert(
		LATEST_LEAF,
		leaf(LATEST_LEAF, LATEST_XID, latest_flags, VOLUME_SUPERBLOCK),
	);
	fixture
}

fn leaf(block: u64, transaction: TransactionId, flags: u32, mapped: u64) -> [u8; BLOCK_BYTES] {
	let mut bytes = [0; BLOCK_BYTES];
	put_u64(&mut bytes, OBJECT_ID_OFFSET, block);
	put_u64(&mut bytes, XID_OFFSET, transaction.0);
	put_u32(&mut bytes, OBJECT_TYPE_OFFSET, CHILD_OBJECT_TYPE);
	put_u32(&mut bytes, OBJECT_SUBTYPE_OFFSET, OBJECT_MAP_SUBTYPE);
	put_u16(&mut bytes, NODE_FLAGS, FIXED_LEAF_FLAGS);
	put_u32(&mut bytes, NODE_RECORDS, 1);
	put_u16(&mut bytes, NODE_TABLE_START, 0);
	put_u16(&mut bytes, NODE_TABLE_LENGTH, LEAF_TABLE_BYTES as u16);
	put_free(&mut bytes, LEAF_KEYS, KEY_BYTES, FIRST_LEAF_VALUE);
	put_u16(&mut bytes, NODE_KEY_LIST, u16::MAX);
	put_u16(&mut bytes, NODE_VALUE_LIST, u16::MAX);
	put_slot(&mut bytes, 0, 0, LEAF_BYTES);
	put_key(&mut bytes, LEAF_KEYS, VOLUME_ID, transaction);
	put_u32(&mut bytes, FIRST_LEAF_VALUE + MAPPING_FLAGS_OFFSET, flags);
	put_u32(
		&mut bytes,
		FIRST_LEAF_VALUE + MAPPING_SIZE_OFFSET,
		BLOCK_BYTES as u32,
	);
	put_u64(
		&mut bytes,
		FIRST_LEAF_VALUE + MAPPING_ADDRESS_OFFSET,
		mapped,
	);
	update_checksum(&mut bytes);
	bytes
}

fn put_free(bytes: &mut [u8], keys: usize, key_bytes: usize, value_start: usize) {
	put_u16(bytes, NODE_FREE_START, key_bytes as u16);
	put_u16(
		bytes,
		NODE_FREE_LENGTH,
		(value_start - keys - key_bytes) as u16,
	);
}

fn put_slot(bytes: &mut [u8], index: usize, key_offset: usize, value_offset: usize) {
	let slot = NODE_DATA_START + index * SLOT_BYTES;
	put_u16(bytes, slot, key_offset as u16);
	put_u16(bytes, slot + size_of::<u16>(), value_offset as u16);
}

fn put_key(bytes: &mut [u8], offset: usize, id: ObjectId, transaction: TransactionId) {
	put_u64(bytes, offset, id.0);
	put_u64(bytes, offset + size_of::<u64>(), transaction.0);
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
	bytes[offset..][..size_of::<u16>()].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
	bytes[offset..][..size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
	bytes[offset..][..size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
}
