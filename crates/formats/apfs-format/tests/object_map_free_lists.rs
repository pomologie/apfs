//! Populated native nodes and bounded free-list rejection for A-CONT-04-T01.

use apfs_format::{
	Error,
	object::{ObjectId, TransactionId, checksum},
	object_map::{Key, Mapping, Node, Record, Value},
	superblock::{BlockAddress, Geometry, Superblock},
};

const BLOCK_BYTES: usize = 4096;
const DEVICE_BYTES: u64 = 64 << 20;
const BOOTSTRAP: &[u8] = include_bytes!("fixtures/native-block-0.bin");
const CONTAINER_NODE: &[u8; BLOCK_BYTES] =
	include_bytes!("fixtures/sonoma-populated-omap-container.bin");
const VOLUME_NODE: &[u8; BLOCK_BYTES] = include_bytes!("fixtures/sonoma-populated-omap-volume.bin");

const KEY_LIST: usize = 48;
const VALUE_LIST: usize = 52;
const KEY_BASE: usize = 504;
const VALUE_END: usize = BLOCK_BYTES - 40;
const KEY_HOLE_OFFSET: u16 = 16;
const KEY_HOLE_START: usize = KEY_BASE + KEY_HOLE_OFFSET as usize;
const VALUE_HOLE_OFFSET: u16 = 32;
const VALUE_HOLE_START: usize = VALUE_END - VALUE_HOLE_OFFSET as usize;
const NATIVE_HOLE_BYTES: u16 = 16;
const ALIGNED_FRAGMENT_BYTES: u16 = 8;
const NONE: u16 = u16::MAX;
const BLOCK_CHECKSUM_BYTES: usize = size_of::<u64>();
const TOMBSTONE: u32 = 1;

#[test]
fn admits_populated_native_container_and_volume_nodes() {
	for (bytes, oid, xid, address) in [
		(
			CONTAINER_NODE,
			ObjectId(1026),
			TransactionId(4),
			BlockAddress(211),
		),
		(
			VOLUME_NODE,
			ObjectId(1028),
			TransactionId(3),
			BlockAddress(205),
		),
	] {
		let node = Node::decode(bytes, geometry(), true).unwrap();
		assert_eq!(node.len(), 1);
		assert_eq!(
			node.record(0).unwrap(),
			Record {
				key: Key {
					id: oid,
					transaction: xid
				},
				value: Value::Mapping(Mapping::Object {
					address,
					size: BLOCK_BYTES as u32
				}),
			}
		);
	}
}

#[test]
fn accounts_for_multiple_aligned_fragments_in_both_directions() {
	let mut bytes = *CONTAINER_NODE;
	let fragment = ALIGNED_FRAGMENT_BYTES as usize;
	put_link(
		&mut bytes,
		KEY_HOLE_START,
		KEY_HOLE_OFFSET + ALIGNED_FRAGMENT_BYTES,
		ALIGNED_FRAGMENT_BYTES,
	);
	put_link(
		&mut bytes,
		KEY_HOLE_START + fragment,
		NONE,
		ALIGNED_FRAGMENT_BYTES,
	);
	put_link(
		&mut bytes,
		VALUE_HOLE_START,
		VALUE_HOLE_OFFSET - ALIGNED_FRAGMENT_BYTES,
		ALIGNED_FRAGMENT_BYTES,
	);
	put_link(
		&mut bytes,
		VALUE_HOLE_START + fragment,
		NONE,
		ALIGNED_FRAGMENT_BYTES,
	);
	update_checksum(&mut bytes);
	let changed = Node::decode(&bytes, geometry(), true).unwrap();
	let native = Node::decode(CONTAINER_NODE, geometry(), true).unwrap();
	assert_eq!(changed.record(0), native.record(0));
}

#[test]
fn rejects_cycles_length_mismatches_and_escaped_free_list_offsets() {
	for (at, next, length) in [
		(KEY_HOLE_START, KEY_HOLE_OFFSET, NATIVE_HOLE_BYTES),
		(KEY_HOLE_START, NONE, ALIGNED_FRAGMENT_BYTES),
		(
			KEY_HOLE_START,
			NONE,
			NATIVE_HOLE_BYTES + ALIGNED_FRAGMENT_BYTES,
		),
		(KEY_HOLE_START, NONE, 0),
		(KEY_LIST, NONE, NATIVE_HOLE_BYTES),
		(KEY_LIST, KEY_HOLE_OFFSET + 1, NATIVE_HOLE_BYTES),
		(KEY_LIST, VALUE_HOLE_OFFSET, NATIVE_HOLE_BYTES),
		(VALUE_LIST, 0, NATIVE_HOLE_BYTES),
		(VALUE_LIST, NONE - 1, NATIVE_HOLE_BYTES),
	] {
		let mut bytes = *CONTAINER_NODE;
		put_link(&mut bytes, at, next, length);
		update_checksum(&mut bytes);
		assert!(
			matches!(
				Node::decode(&bytes, geometry(), true),
				Err(Error::InvalidObjectMap)
			),
			"accepted offset {at}, head {next}, length {length}"
		);
	}
}

#[test]
fn rejects_free_fragments_overlapping_an_occupied_tombstone_slot() {
	let mut bytes = *CONTAINER_NODE;
	let value_start = VALUE_END - usize::from(NATIVE_HOLE_BYTES);
	bytes[value_start..value_start + size_of::<u32>()].copy_from_slice(&TOMBSTONE.to_le_bytes());
	let false_fragment = VALUE_END - usize::from(ALIGNED_FRAGMENT_BYTES);
	put_link(&mut bytes, false_fragment, NONE, ALIGNED_FRAGMENT_BYTES);
	update_checksum(&mut bytes);
	let node = Node::decode(&bytes, geometry(), true).unwrap();
	assert_eq!(
		node.record(0).unwrap().value,
		Value::Mapping(Mapping::Deleted)
	);

	put_link(
		&mut bytes,
		VALUE_LIST,
		ALIGNED_FRAGMENT_BYTES,
		ALIGNED_FRAGMENT_BYTES,
	);
	update_checksum(&mut bytes);
	assert!(matches!(
		Node::decode(&bytes, geometry(), true),
		Err(Error::InvalidObjectMap)
	));
}

fn geometry() -> Geometry {
	Superblock::decode(BOOTSTRAP, DEVICE_BYTES)
		.unwrap()
		.geometry
}

fn put_link(node: &mut [u8], position: usize, next: u16, length: u16) {
	let length_position = position + size_of::<u16>();
	node[position..length_position].copy_from_slice(&next.to_le_bytes());
	node[length_position..length_position + size_of::<u16>()]
		.copy_from_slice(&length.to_le_bytes());
}

fn update_checksum(node: &mut [u8]) {
	let sum = checksum(node).unwrap();
	node[..BLOCK_CHECKSUM_BYTES].copy_from_slice(&sum.to_le_bytes());
}
