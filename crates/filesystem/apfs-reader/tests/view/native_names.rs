//! Native equality in one directory, with exact-name lookup retained.

use std::ops::Range;

use apfs_reader::{NameError, NameProfile};

use super::{
	BLOCK_BYTES, BTREE_DATA_OFFSET, BTREE_TABLE_LENGTH_OFFSET, Corruption, Error, FileKind,
	Fixture, InodeId, LookupOptions, ObjectId, POPULATED_FSROOT_BLOCK, TreeLimits, VOLUME_ID,
	VolumeView, container, hard_links, u16_at, update_checksum,
};

const ROOT: InodeId = InodeId::ROOT;
const STORED_TITLE: &str = "Étude.txt";
const DECOMPOSED_TITLE: &str = "E\u{301}tude.txt";
const FOLDED_TITLE: &str = "e\u{301}TUDE.TXT";
const STORED_DOCS: &str = "Docs";
const FOLDED_DOCS: &str = "docs";
const STORED_NOTE: &str = "note.txt";
const FOLDED_NOTE: &str = "NoTe.TxT";
const STORED_ALPHA: &str = "ALPHA.txt";
const STORED_EMPTY: &str = "Empty";
const STORED_LINK: &str = "link";
const AFTER_UNICODE_9: &str = "\u{1c90}x";
const INVALID_COMPONENT: &str = "Docs/note.txt";
const LINK_DIRECTORY: InodeId = InodeId::from_raw(19).unwrap();
const LINK_INODE: InodeId = InodeId::from_raw(17).unwrap();
const SIBLING: ObjectId = ObjectId(21);
const STORED_ALIAS: &str = "Écho.bin";
const FOLDED_ALIAS: &str = "e\u{301}CHO.BIN";

#[test]
fn matches_composition_and_case_on_the_native_sonoma_volume() {
	let source = container(Fixture::native_populated());
	let mut view = VolumeView::open(
		&source,
		VOLUME_ID,
		LookupOptions::default(),
		TreeLimits::default(),
	)
	.unwrap()
	.unwrap();
	assert_eq!(view.name_profile(), NameProfile::Unicode9Folded);

	let stored = view
		.lookup_stored_name(ROOT, STORED_TITLE)
		.unwrap()
		.unwrap();
	for query in [DECOMPOSED_TITLE, FOLDED_TITLE] {
		assert!(view.lookup_stored_name(ROOT, query).unwrap().is_none());
		let native = view.lookup_native_name(ROOT, query).unwrap().unwrap();
		assert_eq!(native, stored);
		assert_eq!(native.name, STORED_TITLE);
	}
	let docs = view.lookup_native_name(ROOT, FOLDED_DOCS).unwrap().unwrap();
	assert_eq!(docs.name, STORED_DOCS);
	assert_eq!(docs.kind, FileKind::Directory);
	assert!(
		view.lookup_native_name(ROOT, FOLDED_NOTE)
			.unwrap()
			.is_none()
	);
	let note = view
		.lookup_native_name(docs.inode, FOLDED_NOTE)
		.unwrap()
		.unwrap();
	assert_eq!(note.name, STORED_NOTE);
	assert!(matches!(
		view.lookup_native_name(note.inode, FOLDED_NOTE),
		Err(Error::NotDirectory)
	));
	assert!(matches!(
		view.lookup_native_name(ROOT, INVALID_COMPONENT),
		Err(Error::Name(NameError::InvalidComponent))
	));
}

#[test]
fn selects_normalization_only_for_a_case_sensitive_feature_word() {
	const VOLUME_SUPERBLOCK: u64 = 211;
	const INCOMPATIBLE_FEATURES_OFFSET: usize = 56;
	const NORMALIZATION_INSENSITIVE: u64 = 1 << 3;
	let mut fixture = Fixture::native_populated();
	let superblock = fixture.0.get_mut(&VOLUME_SUPERBLOCK).unwrap();
	// A constructed case-sensitive profile keeps the native hashed key layout.
	superblock[INCOMPATIBLE_FEATURES_OFFSET..][..size_of::<u64>()]
		.copy_from_slice(&NORMALIZATION_INSENSITIVE.to_le_bytes());
	update_checksum(superblock);

	let source = container(fixture);
	let mut view = VolumeView::open(
		&source,
		VOLUME_ID,
		LookupOptions::default(),
		TreeLimits::default(),
	)
	.unwrap()
	.unwrap();
	assert_eq!(view.name_profile(), NameProfile::Unicode9Normalized);
	let stored = view
		.lookup_stored_name(ROOT, STORED_TITLE)
		.unwrap()
		.unwrap();
	assert_eq!(
		view.lookup_native_name(ROOT, DECOMPOSED_TITLE).unwrap(),
		Some(stored)
	);
	assert!(
		view.lookup_native_name(ROOT, FOLDED_TITLE)
			.unwrap()
			.is_none()
	);
	assert!(
		view.lookup_native_name(ROOT, FOLDED_DOCS)
			.unwrap()
			.is_none()
	);
}

#[test]
fn resolves_the_stored_spelling_and_sibling_of_a_native_hard_link() {
	let source = container(hard_links::fixture());
	let mut view = VolumeView::open(
		&source,
		VOLUME_ID,
		LookupOptions::default(),
		TreeLimits::default(),
	)
	.unwrap()
	.unwrap();
	assert!(
		view.lookup_stored_name(LINK_DIRECTORY, FOLDED_ALIAS)
			.unwrap()
			.is_none()
	);
	let link = view
		.lookup_native_name(LINK_DIRECTORY, FOLDED_ALIAS)
		.unwrap()
		.unwrap();
	assert_eq!(link.name, STORED_ALIAS);
	assert_eq!(link.inode, LINK_INODE);
	assert_eq!(link.sibling, Some(SIBLING));
}

#[test]
fn preserves_distinct_keys_with_equal_stored_hashes() {
	let mut fixture = Fixture::native_populated();
	let root = fixture.0.get_mut(&POPULATED_FSROOT_BLOCK).unwrap();
	// These records are adjacent in the captured leaf. Hold their order fixed.
	copy_directory_hash(root, STORED_ALPHA, STORED_EMPTY);
	update_checksum(root);

	let source = container(fixture);
	let mut view = VolumeView::open(
		&source,
		VOLUME_ID,
		LookupOptions::default(),
		TreeLimits::default(),
	)
	.unwrap()
	.unwrap();
	let alpha = view
		.lookup_native_name(ROOT, STORED_ALPHA)
		.unwrap()
		.unwrap();
	let empty = view
		.lookup_native_name(ROOT, STORED_EMPTY)
		.unwrap()
		.unwrap();
	assert!(alpha.name_hash.is_some());
	assert_eq!(alpha.name_hash, empty.name_hash);
	assert_eq!(alpha.name, STORED_ALPHA);
	assert_eq!(empty.name, STORED_EMPTY);
	assert_ne!(alpha.inode, empty.inode);
}

#[test]
fn refuses_ambiguous_equivalent_stored_names() {
	let mut fixture = Fixture::native_populated();
	let root = fixture.0.get_mut(&POPULATED_FSROOT_BLOCK).unwrap();
	copy_directory_hash(root, STORED_DOCS, STORED_LINK);
	replace_directory_name(root, STORED_LINK, FOLDED_DOCS);
	update_checksum(root);

	let source = container(fixture);
	let mut view = VolumeView::open(
		&source,
		VOLUME_ID,
		LookupOptions::default(),
		TreeLimits::default(),
	)
	.unwrap()
	.unwrap();
	assert!(
		view.lookup_stored_name(ROOT, STORED_DOCS)
			.unwrap()
			.is_some()
	);
	assert!(
		view.lookup_stored_name(ROOT, FOLDED_DOCS)
			.unwrap()
			.is_some()
	);
	assert!(matches!(
		view.lookup_native_name(ROOT, FOLDED_DOCS),
		Err(Error::Corrupt(Corruption::EquivalentDirectoryNames))
	));
}

#[test]
fn rejects_a_later_unicode_scalar_in_the_query_or_directory() {
	let mut fixture = Fixture::native_populated();
	let root = fixture.0.get_mut(&POPULATED_FSROOT_BLOCK).unwrap();
	// This unqualified name occurs after Docs in the scanned directory.
	replace_directory_name(root, STORED_LINK, AFTER_UNICODE_9);
	update_checksum(root);

	let source = container(fixture);
	let mut view = VolumeView::open(
		&source,
		VOLUME_ID,
		LookupOptions::default(),
		TreeLimits::default(),
	)
	.unwrap()
	.unwrap();
	assert!(
		view.lookup_stored_name(ROOT, AFTER_UNICODE_9)
			.unwrap()
			.is_some()
	);
	for query in [AFTER_UNICODE_9, STORED_DOCS] {
		assert!(matches!(
			view.lookup_native_name(ROOT, query),
			Err(Error::Name(NameError::UnsupportedScalar { scalar }))
				if AFTER_UNICODE_9.starts_with(scalar)
		));
	}
}

fn copy_directory_hash(root: &mut [u8; BLOCK_BYTES], from: &str, to: &str) {
	const NAME_LENGTH_BITS: u32 = 10;
	const NAME_LENGTH_MASK: u32 = (1 << NAME_LENGTH_BITS) - 1;
	let from = directory_key(root, from).start + size_of::<u64>();
	let to = directory_key(root, to).start + size_of::<u64>();
	let hash = u32_at(root, from) & !NAME_LENGTH_MASK;
	let name_length = u32_at(root, to) & NAME_LENGTH_MASK;
	root[to..][..size_of::<u32>()].copy_from_slice(&(hash | name_length).to_le_bytes());
}

fn replace_directory_name(root: &mut [u8; BLOCK_BYTES], from: &str, to: &str) {
	let key = directory_key(root, from);
	let name = key.end - from.len() - size_of::<u8>();
	root[name..key.end - size_of::<u8>()].copy_from_slice(to.as_bytes());
}

fn directory_key(root: &[u8; BLOCK_BYTES], name: &str) -> Range<usize> {
	const NODE_KEY_COUNT: usize = 36;
	const NODE_TABLE_OFFSET: usize = 40;
	const VARIABLE_SLOT_BYTES: usize = 4 * size_of::<u16>();
	const OBJECT_TYPE_SHIFT: u32 = 60;
	const DIRECTORY_RECORD: u64 = 9;
	let header = (DIRECTORY_RECORD << OBJECT_TYPE_SHIFT | ROOT.as_raw()).to_le_bytes();
	let table = BTREE_DATA_OFFSET + usize::from(u16_at(root, NODE_TABLE_OFFSET));
	let keys = table + usize::from(u16_at(root, BTREE_TABLE_LENGTH_OFFSET));
	let slots = u32_at(root, NODE_KEY_COUNT) as usize;
	for index in 0..slots {
		let slot = table + index * VARIABLE_SLOT_BYTES;
		let start = keys + usize::from(u16_at(root, slot));
		let end = start + usize::from(u16_at(root, slot + size_of::<u16>()));
		let key = &root[start..end];
		if key.starts_with(&header)
			&& key[size_of::<u64>() + size_of::<u32>()..].strip_suffix(&[0])
				== Some(name.as_bytes())
		{
			return start..end;
		}
	}
	panic!("missing root directory record {name}");
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
	u32::from_le_bytes(bytes[offset..][..size_of::<u32>()].try_into().unwrap())
}
