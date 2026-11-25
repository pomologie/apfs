//! A-READ-01 native regular-file sibling identities and shared fork bytes.

use super::*;

const INODE: InodeId = InodeId::from_raw(17).unwrap();
const DOCS: InodeId = InodeId::from_raw(16).unwrap();
const MORE: InodeId = InodeId::from_raw(19).unwrap();
const MISSING: InodeId = InodeId::from_raw(300).unwrap();
const NATIVE_LINKS: [(u64, InodeId, &str); 3] = [
	(20, DOCS, "alias.bin"),
	(21, MORE, "Écho.bin"),
	(22, InodeId::ROOT, "primary.bin"),
];
const DATA_PATTERN: &[u8] = b"APFS shared data fork\n";
const DATA_REPETITIONS: usize = 250;
const FORK_PATTERN: &[u8] = b"APFS shared resource fork\n";
const FORK_REPETITIONS: usize = 200;
const RESOURCE_FORK: &str = "com.apple.ResourceFork";

pub(super) const FSROOT: u64 = 206;
const TYPE_SHIFT: u32 = 60;
const INODE_TYPE: u64 = 3;
const SIBLING_LINK_TYPE: u64 = 5;
const SIBLING_MAP_TYPE: u64 = 12;
const BTREE_COUNT_OFFSET: usize = 36;
const BTREE_TABLE_OFFSET: usize = 40;
const SLOT_BYTES: usize = 4 * size_of::<u16>();
const INODE_NLINK_OFFSET: usize = 56;
const SIBLING_NAME_OFFSET: usize = size_of::<u64>() + size_of::<u16>();

pub(super) fn fixture() -> Fixture {
	Fixture::from_packed_blocks(include_bytes!("../fixtures/sonoma-hard-link-blocks.bin"))
}

fn open(container: &Container<Fixture>, limits: TreeLimits) -> VolumeView<'_, Fixture> {
	VolumeView::open(container, VOLUME_ID, LookupOptions::default(), limits)
		.unwrap()
		.unwrap()
}

#[test]
fn lists_native_siblings_and_reads_both_exact_shared_forks() {
	let container = container(fixture());
	let mut view = open(&container, TreeLimits::default());
	assert_eq!(view.volume().checkpoint, POPULATED_CHECKPOINT);
	let inode = view.stat(INODE).unwrap().unwrap();
	assert_eq!(inode.parent, Some(DOCS));
	assert_eq!(inode.count, InodeCount::Links(NATIVE_LINKS.len() as u32));
	assert_eq!(inode.data_stream_id, ObjectId(INODE.as_raw()));
	let links = view.hard_links(INODE).unwrap().unwrap();
	assert_eq!(links.len(), NATIVE_LINKS.len());
	let data = DATA_PATTERN.repeat(DATA_REPETITIONS);
	let resource = FORK_PATTERN.repeat(FORK_REPETITIONS);
	for (link, (sibling, parent, name)) in links.iter().zip(NATIVE_LINKS) {
		assert_eq!(
			(link.sibling.as_raw(), link.parent, link.name.as_str()),
			(sibling, parent, name)
		);
		assert_eq!(link.inode, INODE);
		let entry = view.lookup_stored_name(parent, name).unwrap().unwrap();
		assert_eq!(entry.inode, INODE);
		assert_eq!(entry.sibling, Some(ObjectId(sibling)));
		let page = view.read_checked_dir(parent, None, WIDE_PAGE).unwrap();
		assert!(page.entries.contains(&entry));
		let selected = view
			.stat_entry(entry.inode, Some(parent), entry.sibling)
			.unwrap()
			.unwrap();
		assert_eq!(selected.inode, inode);
		assert_eq!(
			selected.hard_link_count.unwrap().get(),
			NATIVE_LINKS.len() as u32
		);
		let mut file = view.open_file(entry.inode).unwrap().unwrap();
		assert_eq!(file.len(), data.len() as u64);
		let mut observed = vec![0; data.len()];
		file.read_exact_at(ByteOffset(0), &mut observed).unwrap();
		assert_eq!(observed, data);
		let mut fork = view
			.open_xattr(entry.inode, RESOURCE_FORK)
			.unwrap()
			.unwrap();
		assert_eq!(fork.len(), resource.len() as u64);
		let mut observed = vec![0; resource.len()];
		fork.read_exact_at(ByteOffset(0), &mut observed).unwrap();
		assert_eq!(observed, resource);
	}
}

#[test]
fn distinguishes_missing_inodes_untracked_regular_files_and_page_limits() {
	let source = container(fixture());
	let mut view = open(&source, TreeLimits::default());
	assert!(view.hard_links(MISSING).unwrap().is_none());
	assert!(matches!(view.hard_links(DOCS), Err(Error::NotRegularFile)));
	assert!(
		view.stat_entry(MISSING, Some(DOCS), None)
			.unwrap()
			.is_none()
	);
	assert!(matches!(
		view.stat_entry(INODE, Some(DOCS), None),
		Err(Error::Corrupt(Corruption::HardLinkDirectory))
	));
	assert!(matches!(
		view.stat_entry(INODE, Some(MORE), Some(ObjectId(NATIVE_LINKS[0].0))),
		Err(Error::Corrupt(Corruption::HardLinkDirectory))
	));

	let source = container(Fixture::native_populated());
	let mut view = open(&source, TreeLimits::default());
	let regular = view
		.lookup_stored_name(InodeId::ROOT, "ALPHA.txt")
		.unwrap()
		.unwrap();
	assert!(view.hard_links(regular.inode).unwrap().unwrap().is_empty());

	let source = container(fixture());
	let mut view = open(
		&source,
		TreeLimits {
			max_entries_per_page: 2,
			..TreeLimits::default()
		},
	);
	assert!(matches!(
		view.hard_links(INODE),
		Err(Error::Limit(Limit::Page))
	));
	assert_eq!(
		view.lookup_stored_name(DOCS, NATIVE_LINKS[0].2)
			.unwrap()
			.unwrap()
			.inode,
		INODE
	);
}

#[test]
fn rejects_inconsistent_directory_links_counts_and_inverse_maps() {
	let first_sibling = NATIVE_LINKS[0].0;
	let claimed_count = (NATIVE_LINKS.len() as u32 + 1).to_le_bytes();
	let different_target = DOCS.as_raw().to_le_bytes();
	for (oid, kind, offset, bytes, reason) in [
		(
			INODE.as_raw(),
			INODE_TYPE,
			INODE_NLINK_OFFSET,
			claimed_count.as_slice(),
			Corruption::HardLinkCount,
		),
		(
			INODE.as_raw(),
			SIBLING_LINK_TYPE,
			SIBLING_NAME_OFFSET,
			b"A",
			Corruption::HardLinkDirectory,
		),
		(
			first_sibling,
			SIBLING_MAP_TYPE,
			0,
			different_target.as_slice(),
			Corruption::SiblingMap,
		),
	] {
		let mut image = fixture();
		mutate_value(&mut image, oid, kind, offset, bytes);
		let source = container(image);
		let mut view = open(&source, TreeLimits::default());
		assert!(matches!(view.hard_links(INODE), Err(Error::Corrupt(actual)) if actual == reason));
		assert!(
			matches!(view.lookup_stored_name(DOCS, NATIVE_LINKS[0].2), Err(Error::Corrupt(actual)) if actual == reason)
		);
		assert!(view.read_dir(DOCS, None, FIRST_PAGE).is_ok());
		assert!(
			matches!(view.read_checked_dir(DOCS, None, FIRST_PAGE), Err(Error::Corrupt(actual)) if actual == reason)
		);
	}
}

pub(super) fn mutate_value(
	source: &mut Fixture,
	oid: u64,
	kind: u64,
	within: usize,
	replacement: &[u8],
) {
	let block = source.0.get_mut(&FSROOT).unwrap();
	let table = BTREE_DATA_OFFSET + usize::from(u16_at(block, BTREE_TABLE_OFFSET));
	let keys = table + usize::from(u16_at(block, BTREE_TABLE_LENGTH_OFFSET));
	let count = u32::from_le_bytes(
		block[BTREE_COUNT_OFFSET..BTREE_COUNT_OFFSET + size_of::<u32>()]
			.try_into()
			.unwrap(),
	);
	let expected = kind << TYPE_SHIFT | oid;
	for index in 0..count as usize {
		let slot = table + index * SLOT_BYTES;
		let key = keys + usize::from(u16_at(block, slot));
		if u64::from_le_bytes(block[key..key + size_of::<u64>()].try_into().unwrap()) == expected {
			let value = BLOCK_BYTES
				- BTREE_ROOT_FOOTER_BYTES
				- usize::from(u16_at(block, slot + BTREE_VALUE_OFFSET_IN_SLOT));
			let address = value + within;
			block[address..address + replacement.len()].copy_from_slice(replacement);
			update_checksum(block);
			return;
		}
	}
	panic!("missing native record {expected}");
}

fn u16_at(block: &[u8], offset: usize) -> u16 {
	u16::from_le_bytes(block[offset..offset + size_of::<u16>()].try_into().unwrap())
}
