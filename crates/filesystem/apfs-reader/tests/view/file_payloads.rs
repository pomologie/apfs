use apfs_format::Error as FormatError;
use apfs_reader::Unsupported;

use super::*;

const NATIVE_APFS_CHECKPOINT: TransactionId = TransactionId(4);
const FRAGMENTED_CHECKPOINT: TransactionId = TransactionId(6);
const LARGE_ID: InodeId = InodeId::from_raw(105).unwrap();
const LINK_ID: InodeId = InodeId::from_raw(120).unwrap();
const LARGE_NAME: &str = "large.bin";
const LARGE_BYTES: usize = 19_000;
const PATTERN_STRIDE: usize = 17;
const PATTERN_MODULUS: usize = 251;
const FRAGMENTED_BLOCKS: usize = 4;
const FRAGMENTED_BLOCK_STRIDE: usize = 19;
const CROSS_BLOCK_START: usize = BLOCK_BYTES - 9;
const CROSS_BLOCK_BYTES: usize = 73;
const FIRST_DATA_BLOCK: u64 = 290;
const EXTENT_REFERENCE_ROOT: u64 = 202;
const EXTENT_REFERENCE_LEAF: u64 = 318;
const LARGE_RECORD_LEAF: u64 = 400;
const LINK_RECORD_LEAF: u64 = 401;
const INODE_FLAGS_OFFSET: usize = 48;
const BSD_FLAGS_OFFSET: usize = 68;
const BSD_COMPRESSED: u32 = 1 << 5;
const INODE_CLONED: u64 = 1 << 4;
const FILE_EXTENT_BLOCK_OFFSET: usize = 8;
const FILE_EXTENT_CRYPTO_OFFSET: usize = 16;
const PHYSICAL_REF_OWNER_OFFSET: usize = 8;
const PHYSICAL_REF_COUNT_OFFSET: usize = 16;
const RECORD_KIND_SHIFT: u32 = 60;
const INODE_KIND: u64 = 3;
const XATTR_KIND: u64 = 4;
const FILE_EXTENT_KIND: u64 = 8;
const PHYSICAL_EXTENT_KIND: u64 = 2;
const BTREE_SLOT_BYTES: usize = 8;
const BTREE_NUM_SLOTS_OFFSET: usize = 36;
const BTREE_TABLE_LOCATION_OFFSET: usize = 40;
const TARGET_ATTRIBUTE: &[u8] = b"com.apple.fs.symlink\0";
const TARGET_STORAGE_FORK: u16 = (1 << 0) | (1 << 2);

fn fixture() -> Fixture {
	Fixture::from_packed_blocks(include_bytes!("../fixtures/sonoma-payload-blocks.bin"))
}

fn open(container: &Container<Fixture>) -> VolumeView<'_, Fixture> {
	VolumeView::open(
		container,
		VOLUME_ID,
		LookupOptions::default(),
		TreeLimits::default(),
	)
	.unwrap()
	.unwrap()
}

fn large_content() -> Vec<u8> {
	(0..LARGE_BYTES)
		.map(|index| ((index * PATTERN_STRIDE + index / BLOCK_BYTES) % PATTERN_MODULUS) as u8)
		.collect()
}

#[test]
fn compares_native_full_and_unaligned_ranges_through_split_reference_tree() {
	let container = container(fixture());
	let mut view = open(&container);
	assert_eq!(view.volume().checkpoint, NATIVE_APFS_CHECKPOINT);
	assert_eq!(
		view.volume().superblock.trees.extent_references.0,
		EXTENT_REFERENCE_ROOT
	);
	let large = view
		.lookup_stored_name(InodeId::ROOT, LARGE_NAME)
		.unwrap()
		.unwrap();
	assert_eq!(large.inode, LARGE_ID);
	{
		let mut file = view.open_file(large.inode).unwrap().unwrap();
		assert_eq!(file.len(), LARGE_BYTES as u64);
		assert!(!file.is_empty());

		let content = large_content();
		let mut out = vec![0; LARGE_BYTES];
		file.read_exact_at(ByteOffset(0), &mut out).unwrap();
		assert_eq!(out, content);
		let mut cross = [0; CROSS_BLOCK_BYTES];
		file.read_exact_at(ByteOffset(CROSS_BLOCK_START as u64), &mut cross)
			.unwrap();
		assert_eq!(
			cross,
			content[CROSS_BLOCK_START..CROSS_BLOCK_START + CROSS_BLOCK_BYTES]
		);
		file.read_exact_at(ByteOffset(file.len()), &mut []).unwrap();

		let mut unchanged = [0xA5];
		for offset in [file.len(), u64::MAX] {
			assert!(matches!(
				file.read_exact_at(ByteOffset(offset), &mut unchanged),
				Err(Error::FileRange { .. })
			));
			assert_eq!(unchanged, [0xA5]);
		}
	}

	for index in [0, 179] {
		let name = format!("Slot-{index:03}.txt");
		let data = format!("APFS extent-reference fixture record {index}\n");
		let slot = view
			.lookup_stored_name(InodeId::ROOT, &name)
			.unwrap()
			.unwrap();
		let mut file = view.open_file(slot.inode).unwrap().unwrap();
		let mut out = vec![0; data.len()];
		file.read_exact_at(ByteOffset(0), &mut out).unwrap();
		assert_eq!(out, data.as_bytes());
	}
}

#[test]
fn reads_native_empty_file_and_relative_symlink_bytes() {
	let container = container(fixture());
	let mut view = open(&container);
	let empty = view
		.lookup_stored_name(InodeId::ROOT, "empty.txt")
		.unwrap()
		.unwrap();
	{
		let mut file = view.open_file(empty.inode).unwrap().unwrap();
		assert!(file.is_empty());
		assert_eq!(file.len(), 0);
		file.read_exact_at(ByteOffset(0), &mut []).unwrap();
	}
	let link = view
		.lookup_stored_name(InodeId::ROOT, "link")
		.unwrap()
		.unwrap();
	assert_eq!(link.inode, LINK_ID);
	assert_eq!(
		view.read_link(link.inode).unwrap().as_deref(),
		Some(b"../large.bin".as_slice())
	);
	assert!(matches!(
		view.open_file(link.inode),
		Err(Error::NotRegularFile)
	));
	assert!(matches!(
		view.read_link(empty.inode),
		Err(Error::NotSymlink)
	));
}

#[test]
fn reads_a_physically_fragmented_native_file_across_extent_boundaries() {
	let fixture =
		Fixture::from_packed_blocks(include_bytes!("../fixtures/sonoma-fragmented-blocks.bin"));
	let container = container(fixture);
	let mut view = open(&container);
	assert_eq!(view.volume().checkpoint, FRAGMENTED_CHECKPOINT);
	let entry = view
		.lookup_stored_name(InodeId::ROOT, "fragmented.bin")
		.unwrap()
		.unwrap();
	let mut file = view.open_file(entry.inode).unwrap().unwrap();
	let length = FRAGMENTED_BLOCKS * BLOCK_BYTES;
	assert_eq!(file.len(), length as u64);
	let expected = (0..length)
		.map(|index| {
			let block = index / BLOCK_BYTES;
			let within_block = index % BLOCK_BYTES;
			((block * FRAGMENTED_BLOCK_STRIDE + within_block * PATTERN_STRIDE) % PATTERN_MODULUS)
				as u8
		})
		.collect::<Vec<_>>();
	let mut entire_file = vec![0; length];
	file.read_exact_at(ByteOffset(0), &mut entire_file).unwrap();
	assert_eq!(entire_file, expected);
	for boundary in 0..FRAGMENTED_BLOCKS - 1 {
		let start = boundary * BLOCK_BYTES + CROSS_BLOCK_START;
		let mut cross = [0; CROSS_BLOCK_BYTES];
		file.read_exact_at(ByteOffset(start as u64), &mut cross)
			.unwrap();
		assert_eq!(cross, expected[start..start + CROSS_BLOCK_BYTES]);
	}
}

#[test]
fn reports_sparse_encrypted_compressed_and_shared_data_states() {
	for (kind, value_offset, value, unsupported) in [
		(
			FILE_EXTENT_KIND,
			FILE_EXTENT_BLOCK_OFFSET,
			0u64.to_le_bytes().to_vec(),
			Unsupported::SparseData,
		),
		(
			FILE_EXTENT_KIND,
			FILE_EXTENT_CRYPTO_OFFSET,
			1u64.to_le_bytes().to_vec(),
			Unsupported::EncryptedData,
		),
		(
			INODE_KIND,
			INODE_FLAGS_OFFSET,
			INODE_CLONED.to_le_bytes().to_vec(),
			Unsupported::SharedData,
		),
		(
			INODE_KIND,
			BSD_FLAGS_OFFSET,
			BSD_COMPRESSED.to_le_bytes().to_vec(),
			Unsupported::CompressedData,
		),
	] {
		let mut source = fixture();
		change_record_value(
			&mut source,
			LARGE_RECORD_LEAF,
			LARGE_ID.as_raw(),
			kind,
			value_offset,
			&value,
		);
		let container = container(source);
		let mut view = open(&container);
		assert!(
			matches!(view.open_file(LARGE_ID), Err(Error::Unsupported(reason)) if reason == unsupported)
		);
	}
}

#[test]
fn rejects_wrong_extent_reference_ownership_and_shared_references() {
	for (offset, value, shared) in [
		(
			PHYSICAL_REF_OWNER_OFFSET,
			106u64.to_le_bytes().to_vec(),
			false,
		),
		(PHYSICAL_REF_COUNT_OFFSET, 2u32.to_le_bytes().to_vec(), true),
	] {
		let mut source = fixture();
		change_record_value(
			&mut source,
			EXTENT_REFERENCE_LEAF,
			FIRST_DATA_BLOCK,
			PHYSICAL_EXTENT_KIND,
			offset,
			&value,
		);
		let container = container(source);
		let mut view = open(&container);
		let Err(error) = view.open_file(LARGE_ID) else {
			panic!("accepted an unqualified extent-reference record");
		};
		if shared {
			assert!(matches!(error, Error::Unsupported(Unsupported::SharedData)));
		} else {
			assert!(matches!(error, Error::Corrupt(Corruption::ExtentReference)));
		}
	}
}

#[test]
fn rejects_bad_referenced_metadata_and_metadata_aliases() {
	let mut source = fixture();
	source.0.get_mut(&EXTENT_REFERENCE_ROOT).unwrap()[0] ^= 1;
	let broken = container(source);
	assert!(matches!(
		open(&broken).open_file(LARGE_ID),
		Err(Error::Corrupt(Corruption::PhysicalNode(
			FormatError::InvalidChecksum
		)))
	));

	let mut source = fixture();
	change_record_value(
		&mut source,
		LARGE_RECORD_LEAF,
		LARGE_ID.as_raw(),
		FILE_EXTENT_KIND,
		FILE_EXTENT_BLOCK_OFFSET,
		&EXTENT_REFERENCE_ROOT.to_le_bytes(),
	);
	let aliased = container(source);
	assert!(matches!(
		open(&aliased).open_file(LARGE_ID),
		Err(Error::Corrupt(Corruption::ExtentMetadataAlias))
	));
}

#[test]
fn rejects_a_gap_at_the_start_of_the_logical_data_stream() {
	let mut source = fixture();
	let node = source.0.get_mut(&LARGE_RECORD_LEAF).unwrap();
	let slot = matching_slot(node, LARGE_ID.as_raw(), FILE_EXTENT_KIND);
	let at = key_offset(node, slot) + size_of::<u64>();
	node[at..at + size_of::<u64>()].copy_from_slice(&(BLOCK_BYTES as u64).to_le_bytes());
	update_checksum(node);
	let container = container(source);
	assert!(matches!(
		open(&container).open_file(LARGE_ID),
		Err(Error::Corrupt(Corruption::ExtentCoverage))
	));
}

#[test]
fn preserves_a_source_failure_for_missing_file_bytes() {
	let mut source = fixture();
	source.0.remove(&FIRST_DATA_BLOCK);
	let container = container(source);
	let mut view = open(&container);
	let mut file = view.open_file(LARGE_ID).unwrap().unwrap();
	assert!(matches!(
		file.read_exact_at(ByteOffset(0), &mut [0]),
		Err(Error::Container(apfs_container::Error::Read {
			source: FIRST_DATA_BLOCK,
			..
		}))
	));
}

#[test]
fn preserves_non_utf8_link_targets_and_rejects_unsupported_target_storage() {
	let mut source = fixture();
	let link_leaf = source.0.get_mut(&LINK_RECORD_LEAF).unwrap();
	let offset = value_offset(link_leaf, LINK_ID.as_raw(), XATTR_KIND);
	// The first attribute sorted by this volume is the symlink target.
	const NAME_OFFSET: usize = 10;
	let slot = matching_slot(link_leaf, LINK_ID.as_raw(), XATTR_KIND);
	let location = key_offset(link_leaf, slot);
	assert_eq!(
		&link_leaf[location + NAME_OFFSET..location + NAME_OFFSET + TARGET_ATTRIBUTE.len()],
		TARGET_ATTRIBUTE
	);
	const TARGET_VALUE_HEADER: usize = 4;
	link_leaf[offset + TARGET_VALUE_HEADER] = 0xFF;
	update_checksum(link_leaf);
	let opaque = container(source);
	let bytes = open(&opaque).read_link(LINK_ID).unwrap().unwrap();
	assert_eq!(bytes[0], 0xFF);
	assert_eq!(&bytes[1..], b"./large.bin");

	let mut source = fixture();
	change_record_value(
		&mut source,
		LINK_RECORD_LEAF,
		LINK_ID.as_raw(),
		XATTR_KIND,
		0,
		&TARGET_STORAGE_FORK.to_le_bytes(),
	);
	let unsupported = container(source);
	assert!(matches!(
		open(&unsupported).read_link(LINK_ID),
		Err(Error::Unsupported(Unsupported::SymlinkStorage(
			TARGET_STORAGE_FORK
		)))
	));
}

fn change_record_value(
	source: &mut Fixture,
	leaf: u64,
	id: u64,
	record_kind: u64,
	offset: usize,
	value: &[u8],
) {
	let block = source.0.get_mut(&leaf).unwrap();
	let at = value_offset(block, id, record_kind) + offset;
	block[at..at + value.len()].copy_from_slice(value);
	update_checksum(block);
}

fn value_offset(block: &[u8], id: u64, record_kind: u64) -> usize {
	let slot = matching_slot(block, id, record_kind);
	block.len() - usize::from(u16_at(block, slot + BTREE_VALUE_OFFSET_IN_SLOT))
}

fn matching_slot(block: &[u8], id: u64, record_kind: u64) -> usize {
	let slots = u32::from_le_bytes(
		block[BTREE_NUM_SLOTS_OFFSET..][..size_of::<u32>()]
			.try_into()
			.unwrap(),
	) as usize;
	let table = BTREE_DATA_OFFSET + usize::from(u16_at(block, BTREE_TABLE_LOCATION_OFFSET));
	let expected = id | (record_kind << RECORD_KIND_SHIFT);
	(0..slots)
		.map(|step| table + step * BTREE_SLOT_BYTES)
		.find(|&slot| {
			let key = key_offset(block, slot);
			u64::from_le_bytes(block[key..key + size_of::<u64>()].try_into().unwrap()) == expected
		})
		.unwrap()
}

fn key_offset(block: &[u8], slot: usize) -> usize {
	BTREE_DATA_OFFSET
		+ usize::from(u16_at(block, BTREE_TABLE_LOCATION_OFFSET))
		+ usize::from(u16_at(block, BTREE_TABLE_LENGTH_OFFSET))
		+ usize::from(u16_at(block, slot))
}
