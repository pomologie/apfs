use std::{
	collections::{BTreeMap, BTreeSet},
	num::NonZeroU16,
};

use apfs_container::{Container, LookupOptions, OpenOptions};
use apfs_core::{ByteOffset, ReadAt};
use apfs_format::object::{ObjectId, TransactionId, checksum};
use apfs_reader::{
	Corruption, Error, FileKind, InodeCount, InodeId, Limit, TreeLimits, VolumeView,
};

const BLOCK_BYTES: usize = 4096;
const DEVICE_BYTES: u64 = 64 << 20;
const VOLUME_ID: ObjectId = ObjectId(1026);
const EMPTY_CHECKPOINT: TransactionId = TransactionId(2);
const POPULATED_CHECKPOINT: TransactionId = TransactionId(4);
const FSROOT_BLOCK: u64 = 197;
const POPULATED_FSROOT_BLOCK: u64 = 205;
const SPLIT_FSROOT_BLOCK: u64 = 290;
const FSROOT_OID: ObjectId = ObjectId(1028);
const ROOT_COUNT_OFFSET: usize = 56;
const NATIVE_ROOT_INODE_BYTES: usize = 108;
const DIRECTORY_ENTRY_BYTES: usize = 18;
const BTREE_ROOT_FOOTER_BYTES: usize = 40;
const BTREE_DATA_OFFSET: usize = 56;
const BTREE_TABLE_LENGTH_OFFSET: usize = 42;
const FIRST_USER_NAME_BYTE: usize = 12;
const BTREE_VALUE_OFFSET_IN_SLOT: usize = 4;
const FIRST_PAGE: NonZeroU16 = NonZeroU16::new(2).unwrap();
const WIDE_PAGE: NonZeroU16 = NonZeroU16::new(16).unwrap();
const SPLIT_FILES: usize = 88;
const PRIVATE_INODE: InodeId = InodeId::from_raw(3).unwrap();

macro_rules! native_block {
	($address:literal) => {
		*include_bytes!(concat!(
			"fixtures/native-block-",
			stringify!($address),
			".bin"
		))
	};
}

struct Fixture(BTreeMap<u64, [u8; BLOCK_BYTES]>);

impl Fixture {
	fn native_empty() -> Self {
		Self(BTreeMap::from([
			(0, native_block!(0)),
			(1, native_block!(1)),
			(2, native_block!(2)),
			(3, native_block!(3)),
			(4, native_block!(4)),
			// Source ledger confirms these unused descriptor slots are blank.
			(5, [0; BLOCK_BYTES]),
			(6, [0; BLOCK_BYTES]),
			(7, [0; BLOCK_BYTES]),
			(8, [0; BLOCK_BYTES]),
			(9, native_block!(9)),
			(10, native_block!(10)),
			(11, native_block!(11)),
			(12, native_block!(12)),
			(13, native_block!(13)),
			(14, native_block!(14)),
			(191, native_block!(191)),
			(192, native_block!(192)),
			(193, native_block!(193)),
			(194, native_block!(194)),
			(FSROOT_BLOCK, native_block!(197)),
			(198, native_block!(198)),
			(199, native_block!(199)),
			(200, native_block!(200)),
		]))
	}

	fn native_populated() -> Self {
		let mut fixture =
			Self::from_packed_blocks(include_bytes!("fixtures/sonoma-populated-metadata.bin"));
		assert_eq!(
			fixture.0.insert(
				POPULATED_FSROOT_BLOCK,
				*include_bytes!("fixtures/sonoma-populated-fsroot.bin")
			),
			None
		);
		fixture
	}

	fn native_split() -> Self {
		Self::from_packed_blocks(include_bytes!("fixtures/sonoma-split-metadata.bin"))
	}

	fn from_packed_blocks(data: &[u8]) -> Self {
		const ADDRESS_BYTES: usize = size_of::<u64>();
		const RECORD_BYTES: usize = ADDRESS_BYTES + BLOCK_BYTES;
		let (records, trailing) = data.as_chunks::<RECORD_BYTES>();
		assert!(trailing.is_empty());
		let mut blocks = BTreeMap::new();
		for record in records {
			let (address, data) = record.split_at(ADDRESS_BYTES);
			let block = u64::from_le_bytes(address.try_into().unwrap());
			assert_eq!(blocks.insert(block, data.try_into().unwrap()), None);
		}
		Self(blocks)
	}
}

fn update_checksum(block: &mut [u8; BLOCK_BYTES]) {
	let sum = checksum(block).unwrap();
	block[..size_of::<u64>()].copy_from_slice(&sum.to_le_bytes());
}

impl ReadAt for Fixture {
	type Error = u64;

	fn len(&self) -> u64 {
		DEVICE_BYTES
	}

	fn read_exact_at(&self, at: ByteOffset, mut destination: &mut [u8]) -> Result<(), Self::Error> {
		let mut offset = at.0;
		while !destination.is_empty() {
			let block = offset / BLOCK_BYTES as u64;
			let within = (offset % BLOCK_BYTES as u64) as usize;
			let take = destination.len().min(BLOCK_BYTES - within);
			let bytes = self.0.get(&block).ok_or(block)?;
			let (head, tail) = destination.split_at_mut(take);
			head.copy_from_slice(&bytes[within..within + take]);
			destination = tail;
			offset += take as u64;
		}
		Ok(())
	}
}

fn container(fixture: Fixture) -> Container<Fixture> {
	Container::open(fixture, OpenOptions::default()).unwrap()
}

#[test]
fn opens_the_checked_root_of_an_empty_native_volume() {
	let container = container(Fixture::native_empty());
	let mut view = VolumeView::open(
		&container,
		VOLUME_ID,
		LookupOptions::default(),
		TreeLimits::default(),
	)
	.unwrap()
	.unwrap();
	assert_eq!(view.volume().checkpoint, EMPTY_CHECKPOINT);
	assert_eq!(view.root().id, InodeId::ROOT);
	assert_eq!(view.root().kind, FileKind::Directory);
	assert_eq!(view.root().count, InodeCount::Children(0));
	assert_eq!(view.root().parent, None);
	assert_eq!(
		view.stat(PRIVATE_INODE).unwrap().unwrap().kind,
		FileKind::Directory
	);

	let page = view.read_dir(InodeId::ROOT, None, FIRST_PAGE).unwrap();
	assert!(page.entries.is_empty());
	assert!(page.next.is_none());
	assert!(
		view.lookup_stored_name(InodeId::ROOT, "missing")
			.unwrap()
			.is_none()
	);
}

#[test]
fn paginates_native_record_order_and_checks_exact_lookup_targets() {
	let container = container(Fixture::native_populated());
	let mut view = VolumeView::open(
		&container,
		VOLUME_ID,
		LookupOptions::default(),
		TreeLimits::default(),
	)
	.unwrap()
	.unwrap();
	assert_eq!(view.volume().checkpoint, POPULATED_CHECKPOINT);
	let first = view.read_dir(InodeId::ROOT, None, FIRST_PAGE).unwrap();
	assert_eq!(
		first
			.entries
			.iter()
			.map(|entry| entry.name.as_str())
			.collect::<Vec<_>>(),
		["ALPHA.txt", "Empty"]
	);
	let second = view
		.read_dir(InodeId::ROOT, first.next, FIRST_PAGE)
		.unwrap();
	assert_eq!(
		second
			.entries
			.iter()
			.map(|entry| entry.name.as_str())
			.collect::<Vec<_>>(),
		["Étude.txt", "Docs"]
	);
	let last = view
		.read_dir(InodeId::ROOT, second.next, FIRST_PAGE)
		.unwrap();
	assert_eq!(last.entries[0].name, "link");
	assert_eq!(last.entries[0].kind, FileKind::Symlink);
	assert!(last.next.is_none());

	let docs = view
		.lookup_stored_name(InodeId::ROOT, "Docs")
		.unwrap()
		.unwrap();
	assert_eq!(docs.kind, FileKind::Directory);
	let note = view
		.lookup_stored_name(docs.inode, "note.txt")
		.unwrap()
		.unwrap();
	let metadata = view.stat(note.inode).unwrap().unwrap();
	assert_eq!(metadata.parent, Some(docs.inode));
	assert_eq!(metadata.stream.unwrap().logical_bytes, 30);
	assert!(matches!(
		view.read_dir(docs.inode, first.next, FIRST_PAGE),
		Err(Error::InvalidCursor)
	));
	let empty = self::container(Fixture::native_empty());
	let mut other_view = VolumeView::open(
		&empty,
		VOLUME_ID,
		LookupOptions::default(),
		TreeLimits::default(),
	)
	.unwrap()
	.unwrap();
	assert!(matches!(
		other_view.read_dir(InodeId::ROOT, first.next, FIRST_PAGE),
		Err(Error::InvalidCursor)
	));
	assert!(matches!(
		view.read_dir(note.inode, None, FIRST_PAGE),
		Err(Error::NotDirectory)
	));
	assert!(matches!(
		view.lookup_stored_name(InodeId::ROOT, ".."),
		Err(Error::InvalidName)
	));
	assert!(
		view.lookup_stored_name(InodeId::ROOT, "E\u{301}tude.txt")
			.unwrap()
			.is_none()
	);
}

#[test]
fn traverses_a_native_split_tree_and_visits_each_name_once() {
	let container = container(Fixture::native_split());
	let mut view = VolumeView::open(
		&container,
		VOLUME_ID,
		LookupOptions::default(),
		TreeLimits::default(),
	)
	.unwrap()
	.unwrap();
	assert_eq!(view.volume().checkpoint, POPULATED_CHECKPOINT);
	assert_eq!(view.root().count, InodeCount::Children(SPLIT_FILES as u32));
	let mut names = BTreeSet::new();
	let mut cursor = None;
	loop {
		let page = view.read_dir(InodeId::ROOT, cursor, WIDE_PAGE).unwrap();
		for entry in page.entries {
			let metadata = view.stat(entry.inode).unwrap().unwrap();
			assert_eq!(metadata.kind, FileKind::Regular);
			assert_eq!(metadata.parent, Some(InodeId::ROOT));
			let looked_up = view
				.lookup_stored_name(InodeId::ROOT, &entry.name)
				.unwrap()
				.unwrap();
			assert_eq!(looked_up.inode, entry.inode);
			assert!(names.insert(entry.name));
		}
		cursor = page.next;
		if cursor.is_none() {
			break;
		}
	}
	assert_eq!(
		names,
		(0..SPLIT_FILES)
			.map(|index| format!("Entry-{index:03}.txt"))
			.collect()
	);
}

#[test]
fn rejects_a_split_child_that_does_not_begin_at_its_separator() {
	let mut fixture = Fixture::native_split();
	let root = fixture.0.get_mut(&SPLIT_FSROOT_BLOCK).unwrap();
	let toc_length = usize::from(u16_at(root, BTREE_TABLE_LENGTH_OFFSET));
	let first_key_offset = usize::from(u16_at(root, BTREE_DATA_OFFSET));
	let name = BTREE_DATA_OFFSET + toc_length + first_key_offset + FIRST_USER_NAME_BYTE;
	root[name] ^= 1;
	update_checksum(root);

	let container = container(fixture);
	assert!(matches!(
		VolumeView::open(
			&container,
			VOLUME_ID,
			LookupOptions::default(),
			TreeLimits::default()
		),
		Err(Error::Corrupt(Corruption::Route))
	));
}

#[test]
fn rejects_a_split_child_that_reuses_the_root_object() {
	let mut fixture = Fixture::native_split();
	let root = fixture.0.get_mut(&SPLIT_FSROOT_BLOCK).unwrap();
	let value_offset = usize::from(u16_at(root, BTREE_DATA_OFFSET + BTREE_VALUE_OFFSET_IN_SLOT));
	let value = root.len() - BTREE_ROOT_FOOTER_BYTES - value_offset;
	root[value..value + size_of::<u64>()].copy_from_slice(&FSROOT_OID.0.to_le_bytes());
	update_checksum(root);

	let container = container(fixture);
	assert!(matches!(
		VolumeView::open(
			&container,
			VOLUME_ID,
			LookupOptions::default(),
			TreeLimits::default()
		),
		Err(Error::Corrupt(Corruption::ReusedNode(FSROOT_OID)))
	));
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
	u16::from_le_bytes(bytes[at..at + size_of::<u16>()].try_into().unwrap())
}

#[test]
fn rejects_directory_counts_that_disagree_with_checked_records() {
	let mut fixture = Fixture::native_empty();
	let root = fixture.0.get_mut(&FSROOT_BLOCK).unwrap();
	let root_inode_count =
		root.len() - BTREE_ROOT_FOOTER_BYTES - NATIVE_ROOT_INODE_BYTES - DIRECTORY_ENTRY_BYTES
			+ ROOT_COUNT_OFFSET;
	root[root_inode_count..root_inode_count + size_of::<u32>()]
		.copy_from_slice(&1u32.to_le_bytes());
	update_checksum(root);

	let container = container(fixture);
	let mut view = VolumeView::open(
		&container,
		VOLUME_ID,
		LookupOptions::default(),
		TreeLimits::default(),
	)
	.unwrap()
	.unwrap();
	assert_eq!(view.root().count, InodeCount::Children(1));
	assert!(matches!(
		view.read_dir(InodeId::ROOT, None, FIRST_PAGE),
		Err(Error::Corrupt(Corruption::DirectoryCount))
	));
}

#[test]
fn enforces_per_tree_scan_and_page_limits() {
	let container = container(Fixture::native_empty());
	let options = LookupOptions::default();
	for (limits, error) in [
		(
			TreeLimits {
				max_depth: 0,
				..TreeLimits::default()
			},
			Limit::Depth,
		),
		(
			TreeLimits {
				max_nodes: 0,
				..TreeLimits::default()
			},
			Limit::Nodes,
		),
		(
			TreeLimits {
				max_records: 3,
				..TreeLimits::default()
			},
			Limit::Records,
		),
	] {
		assert!(matches!(
			VolumeView::open(&container, VOLUME_ID, options, limits),
			Err(Error::Limit(actual)) if actual == error
		));
	}
	let limits = TreeLimits {
		max_entries_per_page: 1,
		..TreeLimits::default()
	};
	let mut view = VolumeView::open(&container, VOLUME_ID, options, limits)
		.unwrap()
		.unwrap();
	assert!(matches!(
		view.read_dir(InodeId::ROOT, None, FIRST_PAGE),
		Err(Error::Limit(Limit::Page))
	));
}

#[path = "view/reachable_check.rs"]
mod check;
#[path = "view/hard_links.rs"]
mod hard_links;
#[path = "view/native_names.rs"]
mod native_names;
#[path = "view/file_payloads.rs"]
mod payload;
#[path = "view/sparse_files.rs"]
mod sparse;
#[path = "view/extended_attributes.rs"]
mod xattr;
