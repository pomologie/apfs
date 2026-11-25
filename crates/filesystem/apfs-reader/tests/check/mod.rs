use apfs_reader::{CheckData, CheckOptions, CheckReport, Unsupported};

use super::{hard_links::fixture, hard_links::mutate_value, *};

const CHECKPOINT: TransactionId = TransactionId(4);
const HARD_LINK_INODE: InodeId = InodeId::from_raw(17).unwrap();
const DOCS_INODE: InodeId = InodeId::from_raw(16).unwrap();
const FORK_STREAM_ID: u64 = 18;
const DATA_BLOCK: u64 = 201;
const FORK_BLOCK: u64 = 204;
const DATA_BYTES: u64 = 5500;
const FORK_BYTES: u64 = 5200;
const PROVENANCE_BYTES: u64 = 4 * 11;
const LOGICAL_BYTES: u64 = DATA_BYTES + FORK_BYTES + PROVENANCE_BYTES;
const INODE_TYPE: u64 = 3;
const FILE_EXTENT_TYPE: u64 = 8;
const DIRECTORY_ENTRY_TYPE: u64 = 9;
const SIBLING_MAP_TYPE: u64 = 12;
const PRIMARY_SIBLING: u64 = 20;
const INODE_FLAGS_OFFSET: usize = 48;
const INODE_HAS_RESOURCE_FORK: u64 = 1 << 14;
const INODE_NO_RESOURCE_FORK: u64 = 1 << 15;
const INODE_LINK_COUNT_OFFSET: usize = 56;
const INODE_BSD_FLAGS_OFFSET: usize = 68;
const BSD_COMPRESSED: u32 = 1 << 5;
const EXTENT_PHYSICAL_BLOCK_OFFSET: usize = size_of::<u64>();
const DIRECTORY_ENTRY_TARGET_OFFSET: usize = 0;

#[test]
fn checks_native_hard_link_cardinality_and_reads_each_fork_once() {
	let report = check(fixture(), CheckOptions::default()).unwrap();
	assert_eq!(report.volume, VOLUME_ID);
	assert_eq!(report.checkpoint, CHECKPOINT);
	assert_eq!(report.directories, 3);
	assert_eq!(report.regular_files, 1);
	assert_eq!(report.symlinks, 0);
	assert_eq!(report.directory_entries, 5);
	assert_eq!(report.hard_link_entries, 3);
	assert_eq!(report.attributes, 5);
	assert_eq!(report.extent_ranges, 2);
	assert_eq!(report.payload_bytes_read, 0);

	let read = check(fixture(), read_options(LOGICAL_BYTES)).unwrap();
	assert_eq!(read.payload_bytes_read, LOGICAL_BYTES);
}

#[test]
fn checks_native_empty_root_under_zero_entry_and_payload_budgets() {
	let report = check(
		Fixture::native_empty(),
		CheckOptions {
			max_directory_depth: 0,
			max_directory_entries: 0,
			max_attributes: 0,
			max_extent_ranges: 0,
			data: CheckData::Read { max_bytes: 0 },
		},
	)
	.unwrap();
	assert_eq!(report.directories, 1);
	assert_eq!(report.directory_entries, 0);
	assert_eq!(report.payload_bytes_read, 0);
	assert_eq!(report.checkpoint, EMPTY_CHECKPOINT);
}

#[test]
fn checks_external_extent_metadata_before_optional_payload_reads() {
	for block in [DATA_BLOCK, FORK_BLOCK] {
		let mut source = fixture();
		assert!(source.0.remove(&block).is_some());
		let source = container(source);
		let mut view = open(&source);
		assert_eq!(
			view.check_reachable(CheckOptions::default(), || false)
				.unwrap()
				.extent_ranges,
			2
		);
		assert!(matches!(
			view.check_reachable(read_options(LOGICAL_BYTES), || false),
			Err(Error::Container(apfs_container::Error::Read { source: failed_block, .. })) if failed_block == block
		));
	}
}

#[test]
fn rejects_cross_fork_physical_aliases_even_with_matching_extent_owner() {
	let mut source = fixture();
	mutate_value(
		&mut source,
		FORK_STREAM_ID,
		FILE_EXTENT_TYPE,
		EXTENT_PHYSICAL_BLOCK_OFFSET,
		&DATA_BLOCK.to_le_bytes(),
	);
	let source = container(source);
	let mut view = open(&source);
	assert!(view.open_file(HARD_LINK_INODE).is_ok());
	assert!(view.open_resource_fork(HARD_LINK_INODE).is_ok());
	assert!(matches!(
		view.check_reachable(CheckOptions::default(), || false),
		Err(Error::Corrupt(Corruption::OverlappingPayloadExtents))
	));
}

#[test]
fn rejects_inconsistent_reachable_targets_link_counts_and_sibling_maps() {
	for (id, kind, offset, bytes, expected) in [
		(
			DOCS_INODE.as_raw(),
			DIRECTORY_ENTRY_TYPE,
			DIRECTORY_ENTRY_TARGET_OFFSET,
			InodeId::ROOT.as_raw().to_le_bytes().to_vec(),
			Corruption::DirectoryTarget,
		),
		(
			HARD_LINK_INODE.as_raw(),
			INODE_TYPE,
			INODE_LINK_COUNT_OFFSET,
			2u32.to_le_bytes().to_vec(),
			Corruption::HardLinkCount,
		),
		(
			PRIMARY_SIBLING,
			SIBLING_MAP_TYPE,
			0,
			DOCS_INODE.as_raw().to_le_bytes().to_vec(),
			Corruption::SiblingMap,
		),
	] {
		let mut source = fixture();
		mutate_value(&mut source, id, kind, offset, &bytes);
		assert!(
			matches!(check(source, CheckOptions::default()), Err(Error::Corrupt(error)) if error == expected)
		);
	}
}

#[test]
fn reconciles_resource_fork_presence_with_inode_flags() {
	for flags in [0, INODE_HAS_RESOURCE_FORK | INODE_NO_RESOURCE_FORK] {
		let mut source = fixture();
		mutate_value(
			&mut source,
			HARD_LINK_INODE.as_raw(),
			INODE_TYPE,
			INODE_FLAGS_OFFSET,
			&flags.to_le_bytes(),
		);
		assert!(matches!(
			check(source, CheckOptions::default()),
			Err(Error::Corrupt(Corruption::ResourceForkFlags))
		));
	}
}

#[test]
fn returns_typed_unsupported_for_unadmitted_file_payloads_in_metadata_mode() {
	let mut source = fixture();
	mutate_value(
		&mut source,
		HARD_LINK_INODE.as_raw(),
		INODE_TYPE,
		INODE_BSD_FLAGS_OFFSET,
		&BSD_COMPRESSED.to_le_bytes(),
	);
	assert!(matches!(
		check(source, CheckOptions::default()),
		Err(Error::Unsupported(Unsupported::CompressedData))
	));
}

#[test]
fn enforces_aggregate_budgets_and_cancellation() {
	for (options, limit) in [
		(
			CheckOptions {
				max_directory_depth: 0,
				..CheckOptions::default()
			},
			Limit::CheckDirectoryDepth,
		),
		(
			CheckOptions {
				max_directory_entries: 4,
				..CheckOptions::default()
			},
			Limit::CheckDirectoryEntries,
		),
		(
			CheckOptions {
				max_attributes: 4,
				..CheckOptions::default()
			},
			Limit::CheckAttributes,
		),
		(
			CheckOptions {
				max_extent_ranges: 1,
				..CheckOptions::default()
			},
			Limit::CheckExtentRanges,
		),
		(read_options(LOGICAL_BYTES - 1), Limit::CheckPayloadBytes),
	] {
		assert!(matches!(check(fixture(), options), Err(Error::Limit(actual)) if actual == limit));
	}
	let source = container(fixture());
	let mut view = open(&source);
	let mut polls = 0;
	assert!(matches!(
		view.check_reachable(CheckOptions::default(), || {
			polls += 1;
			polls == 3
		}),
		Err(Error::Cancelled)
	));
	assert!(
		view.check_reachable(CheckOptions::default(), || false)
			.is_ok()
	);
}

fn open(source: &Container<Fixture>) -> VolumeView<'_, Fixture> {
	VolumeView::open(
		source,
		VOLUME_ID,
		LookupOptions::default(),
		TreeLimits::default(),
	)
	.unwrap()
	.unwrap()
}

fn check(source: Fixture, options: CheckOptions) -> Result<CheckReport, Error<u64>> {
	let source = container(source);
	open(&source).check_reachable(options, || false)
}

fn read_options(max_bytes: u64) -> CheckOptions {
	CheckOptions {
		data: CheckData::Read { max_bytes },
		..CheckOptions::default()
	}
}
