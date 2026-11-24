use apfs_reader::{Unsupported, XattrStorage};

use super::*;

const CHECKPOINT: TransactionId = TransactionId(6);
const INODE: InodeId = InodeId::from_raw(199).unwrap();
const MISSING_INODE: InodeId = InodeId::from_raw(500).unwrap();
const ATTRIBUTE_FILE: &str = "attributes.txt";
const FINDER_INFO: &str = "com.apple.FinderInfo";
const FORK: &str = "com.apple.ResourceFork";
const PROVENANCE: &str = "com.apple.provenance";
const BINARY: &str = "com.pomologie.binary";
const EMPTY: &str = "com.pomologie.empty";
const LARGE: &str = "com.pomologie.large";
const UNICODE: &str = "com.pomologie.unicode.é";
const UNICODE_DECOMPOSED: &str = "com.pomologie.unicode.e\u{301}";
const FORK_CONTENT: &[u8] = b"\0Native APFS fork\xff\0";
const BINARY_CONTENT: &[u8] = b"\0APFS\xff\0fixture";
const UNICODE_CONTENT: &[u8] = b"raw composed name";
const LARGE_BYTES: usize = 9001;
const CROSS_BLOCK_OFFSET: usize = BLOCK_BYTES - 7;
const CROSS_BLOCK_BYTES: usize = 19;
const QUERY_BUDGET_BLOCKS: u64 = 64;
const LARGE_PATTERN_STRIDE: usize = 19;
const PATTERN_MODULUS: usize = 251;
const FINDER_INFO_BYTES: usize = 32;
const FINDER_INFO_TYPE_AND_CREATOR: &[u8] = b"TEXTttxt";
const SONOMA_EXTERNAL_USER_FLAG: u16 = 1 << 4;
const DATA_STREAM: u16 = 1;
const EMBEDDED: u16 = 1 << 1;
const UNKNOWN_FLAG: u16 = 1 << 8;
const XATTR_LEAF: u64 = 427;
const RESOURCE_FORK_DATA_BLOCK: u64 = 422;
const RESOURCE_FORK_STREAM: ObjectId = ObjectId(201);
const LARGE_STREAM: ObjectId = ObjectId(200);
const EXTENT_REF_LEAF: u64 = 418;
const RECORD_TYPE_SHIFT: u32 = 60;
const XATTR_TYPE: u64 = 4;
const PHYSICAL_EXTENT_TYPE: u64 = 2;
const BTREE_TABLE_OFFSET: usize = 40;
const BTREE_SLOT_BYTES: usize = 8;
const BTREE_RECORD_COUNT: usize = 36;
const SLOT_KEY_LENGTH: usize = 2;
const XATTR_KEY_NAME_OFFSET: usize = size_of::<u64>() + size_of::<u16>();
const XATTR_RECORD_DATA_OFFSET: usize = 2 * size_of::<u16>();
const XATTR_STREAM_CRYPTO: usize = XATTR_RECORD_DATA_OFFSET + 3 * size_of::<u64>();
const PHYSICAL_EXTENT_OWNER: usize = size_of::<u64>();
const PHYSICAL_EXTENT_REFCOUNT: usize = 2 * size_of::<u64>();

fn fixture() -> Fixture {
	Fixture::from_packed_blocks(include_bytes!("../fixtures/sonoma-xattr-blocks.bin"))
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

#[test]
fn enumerates_native_attributes_in_bounded_pages_and_checks_cursor_scope() {
	let source = container(fixture());
	let mut view = open(&source);
	assert_eq!(view.volume().checkpoint, CHECKPOINT);
	assert_eq!(
		view.lookup_stored_name(InodeId::ROOT, ATTRIBUTE_FILE)
			.unwrap()
			.unwrap()
			.inode,
		INODE
	);
	let mut cursor = None;
	let mut entries = Vec::new();
	loop {
		let page = view
			.list_xattrs(INODE, cursor, FIRST_PAGE)
			.unwrap()
			.unwrap();
		assert!(page.entries.len() <= usize::from(FIRST_PAGE.get()));
		entries.extend(page.entries);
		cursor = page.next;
		if cursor.is_none() {
			break;
		}
		assert!(matches!(
			view.list_xattrs(InodeId::ROOT, cursor, FIRST_PAGE),
			Err(Error::InvalidCursor)
		));
		let older_source = container(Fixture::native_empty());
		assert!(matches!(
			open(&older_source).list_xattrs(INODE, cursor, FIRST_PAGE),
			Err(Error::InvalidCursor)
		));
	}
	assert_eq!(
		entries
			.iter()
			.map(|entry| entry.name.as_str())
			.collect::<Vec<_>>(),
		[FINDER_INFO, FORK, PROVENANCE, BINARY, EMPTY, LARGE, UNICODE],
	);
	assert_eq!(
		(entries[1].storage, entries[1].length, entries[1].flags),
		(
			XattrStorage::DataStream(RESOURCE_FORK_STREAM),
			FORK_CONTENT.len() as u64,
			DATA_STREAM
		)
	);
	assert_eq!(
		(entries[4].storage, entries[4].length, entries[4].flags),
		(XattrStorage::Inline, 0, EMBEDDED)
	);
	assert_eq!(
		(entries[5].storage, entries[5].length, entries[5].flags),
		(
			XattrStorage::DataStream(LARGE_STREAM),
			LARGE_BYTES as u64,
			DATA_STREAM | SONOMA_EXTERNAL_USER_FLAG
		)
	);
	assert!(
		view.list_xattrs(MISSING_INODE, None, FIRST_PAGE)
			.unwrap()
			.is_none()
	);
	assert!(
		view.list_xattrs(PRIVATE_INODE, None, FIRST_PAGE)
			.unwrap()
			.unwrap()
			.entries
			.is_empty()
	);
	assert!(matches!(
		view.list_xattrs(INODE, None, NonZeroU16::MAX),
		Err(Error::Limit(Limit::Page))
	));
}

#[test]
fn reads_inline_attributes_and_both_native_external_owner_forms() {
	let source = container(fixture());
	let mut view = open(&source);
	let mut finder_bytes = [0; FINDER_INFO_BYTES];
	finder_bytes[..FINDER_INFO_TYPE_AND_CREATOR.len()]
		.copy_from_slice(FINDER_INFO_TYPE_AND_CREATOR);
	let large_content = (0..LARGE_BYTES)
		.map(|index| ((index * LARGE_PATTERN_STRIDE + index / BLOCK_BYTES) % PATTERN_MODULUS) as u8)
		.collect::<Vec<_>>();
	for (name, expected) in [
		(FINDER_INFO, finder_bytes.as_slice()),
		(BINARY, BINARY_CONTENT),
		(EMPTY, &[][..]),
		(LARGE, large_content.as_slice()),
		(UNICODE, UNICODE_CONTENT),
	] {
		let mut data = view.open_xattr(INODE, name).unwrap().unwrap();
		assert_eq!(data.len(), expected.len() as u64);
		assert_eq!(data.is_empty(), expected.is_empty());
		let mut out = vec![0; expected.len()];
		data.read_exact_at(ByteOffset(0), &mut out).unwrap();
		assert_eq!(out, expected);
		data.read_exact_at(ByteOffset(data.len()), &mut []).unwrap();
		let mut out = [0xA5];
		for offset in [data.len(), u64::MAX] {
			assert!(matches!(
				data.read_exact_at(ByteOffset(offset), &mut out),
				Err(Error::FileRange { .. })
			));
			assert_eq!(out, [0xA5]);
		}
	}
	{
		let mut data = view.open_xattr(INODE, LARGE).unwrap().unwrap();
		let mut cross = [0; CROSS_BLOCK_BYTES];
		data.read_exact_at(ByteOffset(CROSS_BLOCK_OFFSET as u64), &mut cross)
			.unwrap();
		assert_eq!(
			cross,
			large_content[CROSS_BLOCK_OFFSET..CROSS_BLOCK_OFFSET + CROSS_BLOCK_BYTES]
		);
	}
	let mut data = view.open_resource_fork(INODE).unwrap().unwrap();
	let mut fork = [0; FORK_CONTENT.len()];
	data.read_exact_at(ByteOffset(0), &mut fork).unwrap();
	assert_eq!(fork, FORK_CONTENT);
	assert!(view.open_resource_fork(InodeId::ROOT).unwrap().is_none());
	assert!(view.open_xattr(MISSING_INODE, BINARY).unwrap().is_none());
	assert!(
		view.open_xattr(INODE, UNICODE_DECOMPOSED)
			.unwrap()
			.is_none()
	);
	assert!(matches!(
		view.open_xattr(INODE, "invalid\0name"),
		Err(Error::InvalidXattrName)
	));
}

#[test]
fn lists_the_fork_without_reading_its_data_and_propagates_source_failures() {
	let mut fixture = fixture();
	assert!(fixture.0.remove(&RESOURCE_FORK_DATA_BLOCK).is_some());
	let source = container(fixture);
	let mut view = open(&source);
	let page = view.list_xattrs(INODE, None, FIRST_PAGE).unwrap().unwrap();
	assert_eq!(page.entries[1].name, FORK);
	let mut data = view.open_resource_fork(INODE).unwrap().unwrap();
	assert!(matches!(
		data.read_exact_at(ByteOffset(0), &mut [0]),
		Err(Error::Container(_))
	));
}

#[test]
fn refuses_inconsistent_or_unqualified_xattr_storage_and_crypto() {
	for (name, offset, replacement) in [
		(BINARY, 0, (EMBEDDED | DATA_STREAM).to_le_bytes().to_vec()),
		(BINARY, size_of::<u16>(), u16::MAX.to_le_bytes().to_vec()),
		(FORK, 0, (DATA_STREAM | UNKNOWN_FLAG).to_le_bytes().to_vec()),
		(FORK, XATTR_STREAM_CRYPTO, 1u64.to_le_bytes().to_vec()),
	] {
		let mut fixture = fixture();
		let block = fixture.0.get_mut(&XATTR_LEAF).unwrap();
		let value = value_offset(block, INODE.as_raw(), XATTR_TYPE, Some(name)) + offset;
		block[value..value + replacement.len()].copy_from_slice(&replacement);
		update_checksum(block);
		let source = container(fixture);
		let mut view = open(&source);
		let Err(error) = view.open_xattr(INODE, name) else {
			panic!("accepted altered {name} storage");
		};
		match (name, offset) {
			(BINARY, _) => assert!(matches!(error, Error::Corrupt(Corruption::XattrRecord))),
			(FORK, 0) => assert!(
				matches!(error, Error::Unsupported(Unsupported::XattrStorage(flags)) if flags == DATA_STREAM | UNKNOWN_FLAG)
			),
			(FORK, XATTR_STREAM_CRYPTO) => assert!(matches!(
				error,
				Error::Unsupported(Unsupported::EncryptedData)
			)),
			_ => unreachable!(),
		}
	}
}

#[test]
fn checks_resource_fork_ownership_and_refuses_shared_ranges() {
	for (offset, replacement) in [
		(
			PHYSICAL_EXTENT_OWNER,
			RESOURCE_FORK_STREAM.0.to_le_bytes().to_vec(),
		),
		(PHYSICAL_EXTENT_REFCOUNT, 2u32.to_le_bytes().to_vec()),
	] {
		let mut fixture = fixture();
		let block = fixture.0.get_mut(&EXTENT_REF_LEAF).unwrap();
		let value =
			value_offset(block, RESOURCE_FORK_DATA_BLOCK, PHYSICAL_EXTENT_TYPE, None) + offset;
		block[value..value + replacement.len()].copy_from_slice(&replacement);
		update_checksum(block);
		let source = container(fixture);
		let Err(error) = open(&source).open_resource_fork(INODE) else {
			panic!("accepted altered resource fork reference");
		};
		if offset == PHYSICAL_EXTENT_OWNER {
			assert!(matches!(error, Error::Corrupt(Corruption::ExtentReference)));
		} else {
			assert!(matches!(error, Error::Unsupported(Unsupported::SharedData)));
		}
	}
}

#[test]
fn rejects_duplicate_or_internal_nul_names_beyond_the_first_page() {
	for (original, altered, error) in [
		(EMPTY, LARGE.as_bytes(), Corruption::DuplicateXattr),
		(
			UNICODE,
			b"invalid\0attribute".as_slice(),
			Corruption::RecordKey,
		),
	] {
		let mut fixture = fixture();
		let block = fixture.0.get_mut(&XATTR_LEAF).unwrap();
		let (_, key) = record_offsets(block, INODE.as_raw(), XATTR_TYPE, Some(original));
		let at = key + XATTR_KEY_NAME_OFFSET;
		block[at..at + altered.len()].copy_from_slice(altered);
		update_checksum(block);
		let source = container(fixture);
		let mut view = open(&source);
		assert!(
			matches!(view.list_xattrs(INODE, None, FIRST_PAGE), Err(Error::Corrupt(actual)) if actual == error)
		);
	}
}

#[test]
fn charges_repeated_attribute_pages_to_the_same_source_budget() {
	let source = container(fixture());
	let mut view = VolumeView::open(
		&source,
		VOLUME_ID,
		LookupOptions {
			max_read_bytes: QUERY_BUDGET_BLOCKS * BLOCK_BYTES as u64,
			..LookupOptions::default()
		},
		TreeLimits::default(),
	)
	.unwrap()
	.unwrap();
	assert_eq!(
		view.list_xattrs(INODE, None, FIRST_PAGE)
			.unwrap()
			.unwrap()
			.entries
			.len(),
		usize::from(FIRST_PAGE.get())
	);
	for _ in 0..QUERY_BUDGET_BLOCKS {
		match view.list_xattrs(INODE, None, FIRST_PAGE) {
			Ok(_) => {}
			Err(Error::Container(apfs_container::Error::Limit(_))) => return,
			Err(error) => panic!("unexpected source error {error:?}"),
		}
	}
	panic!("attribute pages kept reading after the aggregate budget");
}

fn value_offset(block: &[u8], id: u64, kind: u64, name: Option<&str>) -> usize {
	let (slot, _) = record_offsets(block, id, kind, name);
	block.len() - usize::from(u16_at(block, slot + BTREE_VALUE_OFFSET_IN_SLOT))
}

fn record_offsets(block: &[u8], id: u64, kind: u64, name: Option<&str>) -> (usize, usize) {
	let count = u32::from_le_bytes(
		block[BTREE_RECORD_COUNT..][..size_of::<u32>()]
			.try_into()
			.unwrap(),
	) as usize;
	let table = BTREE_DATA_OFFSET + usize::from(u16_at(block, BTREE_TABLE_OFFSET));
	let keys = table + usize::from(u16_at(block, BTREE_TABLE_LENGTH_OFFSET));
	let expected = id | (kind << RECORD_TYPE_SHIFT);
	for index in 0..count {
		let slot = table + index * BTREE_SLOT_BYTES;
		let key = keys + usize::from(u16_at(block, slot));
		if u64::from_le_bytes(block[key..][..size_of::<u64>()].try_into().unwrap()) != expected {
			continue;
		}
		let end = key + usize::from(u16_at(block, slot + SLOT_KEY_LENGTH));
		if name.is_some_and(|name| block[key + XATTR_KEY_NAME_OFFSET..end - 1] != *name.as_bytes())
		{
			continue;
		}
		return (slot, key);
	}
	panic!("native fixture does not contain the requested record");
}
