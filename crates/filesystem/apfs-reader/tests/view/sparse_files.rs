use apfs_reader::{CheckData, CheckOptions, Unsupported};

use super::{
	BLOCK_BYTES, ByteOffset, Container, Corruption, Error, Fixture, InodeId, LookupOptions,
	TransactionId, TreeLimits, VOLUME_ID, VolumeView, container, update_checksum,
};

const CHECKPOINT: TransactionId = TransactionId(4);
const SPARSE_ID: InodeId = InodeId::from_raw(16).unwrap();
const ALL_HOLE_ID: InodeId = InodeId::from_raw(17).unwrap();
const SPARSE_NAME: &str = "sparse.bin";
const ALL_HOLE_NAME: &str = "all-hole.bin";
const SPARSE_LOGICAL_BYTES: usize = 192 * BLOCK_BYTES + 37;
const SPARSE_ALLOCATED_BYTES: u64 = 193 * BLOCK_BYTES as u64;
const SPARSE_HOLE_BYTES: u64 = 185 * BLOCK_BYTES as u64;
const ALL_HOLE_LOGICAL_BYTES: usize = 3 * BLOCK_BYTES + 29;
const ALL_HOLE_ALLOCATED_BYTES: u64 = 4 * BLOCK_BYTES as u64;
const FIRST_DATA_BLOCK: u64 = 201;
const FILESYSTEM_ROOT_BLOCK: u64 = 212;
const FIRST_WRITE: usize = 32 * BLOCK_BYTES;
const SECOND_WRITE: usize = 128 * BLOCK_BYTES;
const WRITES: [(usize, usize, usize, usize); 2] =
	[(FIRST_WRITE, 17, 23, 251), (SECOND_WRITE, 29, 67, 253)];
// SEEK_DATA / SEEK_HOLE reported these interior and trailing boundaries.
const FIRST_END: usize = FIRST_WRITE + 4 * BLOCK_BYTES;
const SECOND_END: usize = SECOND_WRITE + 4 * BLOCK_BYTES;
const BOUNDARY_OFFSETS: [usize; 4] = [FIRST_WRITE, FIRST_END, SECOND_WRITE, SECOND_END];
const BYTES_BEFORE_BOUNDARY: usize = 9;
const CROSSING_BYTES: usize = 73;
const MARKER: u8 = 0xA5;
const FORK_PATTERN: &[u8] = b"APFS sparse-file resource fork\n";
const FORK_REPETITIONS: usize = 174;
const PROVENANCE_ATTRIBUTES_BYTES: usize = 2 * 11;
const PHYSICAL_RANGES: u32 = 4;

// Observed value locations within the captured filesystem root leaf.
const FIRST_HOLE_LENGTH_OFFSET: usize = 3619;
const SPARSE_FIELD_DATA_OFFSET: usize = 3599;
const SPARSE_FIELD_FLAGS_OFFSET: usize = 3540;
const QUALIFIED_SPARSE_FLAGS: u8 = 0x28;
const UNQUALIFIED_SPARSE_FLAGS: u8 = 0x20;

fn fixture() -> Fixture {
	Fixture::from_packed_blocks(include_bytes!("../fixtures/sonoma-sparse-blocks.bin"))
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

fn sparse_content() -> Vec<u8> {
	let mut contents = vec![0; SPARSE_LOGICAL_BYTES];
	for (start, stride, seed, modulus) in WRITES {
		for (index, byte) in contents[start..start + BLOCK_BYTES].iter_mut().enumerate() {
			*byte = ((stride * index + seed) % modulus) as u8;
		}
	}
	contents
}

#[test]
fn matches_native_sparse_bytes_at_every_data_boundary_and_reads_the_resource_fork() {
	let source = container(fixture());
	let mut view = open(&source);
	assert_eq!(view.volume().checkpoint, CHECKPOINT);
	let entry = view
		.lookup_stored_name(InodeId::ROOT, SPARSE_NAME)
		.unwrap()
		.unwrap();
	assert_eq!(entry.inode, SPARSE_ID);
	let inode = view.stat(entry.inode).unwrap().unwrap();
	let stream = inode.stream.unwrap();
	assert_eq!(stream.logical_bytes, SPARSE_LOGICAL_BYTES as u64);
	assert_eq!(stream.allocated_bytes, SPARSE_ALLOCATED_BYTES);
	assert_eq!(inode.sparse_bytes(), Some(SPARSE_HOLE_BYTES));

	let expected = sparse_content();
	{
		let mut data = view.open_file(entry.inode).unwrap().unwrap();
		let mut actual = vec![MARKER; expected.len()];
		assert_eq!(data.len(), expected.len() as u64);
		data.read_exact_at(ByteOffset(0), &mut actual).unwrap();
		assert_eq!(actual, expected);
		for boundary in BOUNDARY_OFFSETS {
			let start = boundary - BYTES_BEFORE_BOUNDARY;
			let mut cross = [MARKER; CROSSING_BYTES];
			data.read_exact_at(ByteOffset(start as u64), &mut cross)
				.unwrap();
			assert_eq!(cross, expected[start..start + CROSSING_BYTES]);
		}
		data.read_exact_at(ByteOffset(data.len()), &mut []).unwrap();
		let mut unchanged = [MARKER];
		assert!(matches!(
			data.read_exact_at(ByteOffset(data.len()), &mut unchanged),
			Err(Error::FileRange { .. })
		));
		assert_eq!(unchanged, [MARKER]);
	}

	let expected_fork = FORK_PATTERN.repeat(FORK_REPETITIONS);
	let mut res = view.open_resource_fork(entry.inode).unwrap().unwrap();
	let mut fork = vec![MARKER; expected_fork.len()];
	assert_eq!(res.len(), expected_fork.len() as u64);
	res.read_exact_at(ByteOffset(0), &mut fork).unwrap();
	assert_eq!(fork, expected_fork);
}

#[test]
fn distinguishes_an_entire_native_hole_from_an_unreadable_allocated_block() {
	let mut image = fixture();
	assert!(image.0.remove(&FIRST_DATA_BLOCK).is_some());
	let source = container(image);
	let mut view = open(&source);
	let all_hole = view
		.lookup_stored_name(InodeId::ROOT, ALL_HOLE_NAME)
		.unwrap()
		.unwrap();
	assert_eq!(all_hole.inode, ALL_HOLE_ID);
	let inode = view.stat(all_hole.inode).unwrap().unwrap();
	assert_eq!(inode.sparse_bytes(), Some(ALL_HOLE_ALLOCATED_BYTES));
	{
		let mut data = view.open_file(all_hole.inode).unwrap().unwrap();
		let mut zeros = vec![MARKER; ALL_HOLE_LOGICAL_BYTES];
		assert_eq!(data.len(), zeros.len() as u64);
		data.read_exact_at(ByteOffset(0), &mut zeros).unwrap();
		assert!(zeros.iter().all(|&byte| byte == 0));
	}
	assert!(view.open_resource_fork(all_hole.inode).unwrap().is_none());

	let mut data = view.open_file(SPARSE_ID).unwrap().unwrap();
	let mut zero = [MARKER];
	data.read_exact_at(ByteOffset(0), &mut zero).unwrap();
	assert_eq!(zero, [0]);
	assert!(matches!(
		data.read_exact_at(ByteOffset(FIRST_WRITE as u64), &mut zero),
		Err(Error::Container(apfs_container::Error::Read {
			source: FIRST_DATA_BLOCK,
			..
		}))
	));
}

#[test]
fn validates_whole_file_coverage_and_the_declared_sparse_count() {
	const GAP_WITH_MATCHING_COUNT: &[(usize, u64)] = &[
		(FIRST_HOLE_LENGTH_OFFSET, FIRST_WRITE as u64),
		(SPARSE_FIELD_DATA_OFFSET, SPARSE_HOLE_BYTES),
	];
	const BAD_COUNT_WITHOUT_GAP: &[(usize, u64)] = &[(SPARSE_FIELD_DATA_OFFSET, SPARSE_HOLE_BYTES)];
	for changes in [GAP_WITH_MATCHING_COUNT, BAD_COUNT_WITHOUT_GAP] {
		let mut image = fixture();
		let leaf = image.0.get_mut(&FILESYSTEM_ROOT_BLOCK).unwrap();
		for &(offset, original) in changes {
			let target = &mut leaf[offset..offset + size_of::<u64>()];
			assert_eq!(target, original.to_le_bytes());
			target.copy_from_slice(&(original - BLOCK_BYTES as u64).to_le_bytes());
		}
		update_checksum(leaf);
		let source = container(image);
		assert!(matches!(
			open(&source).open_file(SPARSE_ID),
			Err(Error::Corrupt(Corruption::ExtentCoverage))
		));
	}

	let mut image = fixture();
	let leaf = image.0.get_mut(&FILESYSTEM_ROOT_BLOCK).unwrap();
	assert_eq!(leaf[SPARSE_FIELD_FLAGS_OFFSET], QUALIFIED_SPARSE_FLAGS);
	leaf[SPARSE_FIELD_FLAGS_OFFSET] = UNQUALIFIED_SPARSE_FLAGS;
	update_checksum(leaf);
	let source = container(image);
	assert!(matches!(
		open(&source).open_file(SPARSE_ID),
		Err(Error::Unsupported(Unsupported::SparseData))
	));
}

#[test]
fn counts_sparse_logical_bytes_without_registering_holes_as_physical_extents() {
	let source = container(fixture());
	let logical_bytes = (SPARSE_LOGICAL_BYTES
		+ ALL_HOLE_LOGICAL_BYTES
		+ FORK_PATTERN.len() * FORK_REPETITIONS
		+ PROVENANCE_ATTRIBUTES_BYTES) as u64;
	let report = open(&source)
		.check_reachable(
			CheckOptions {
				data: CheckData::Read {
					max_bytes: logical_bytes,
				},
				..CheckOptions::default()
			},
			|| false,
		)
		.unwrap();
	assert_eq!(report.regular_files, 2);
	assert_eq!(report.extent_ranges, PHYSICAL_RANGES);
	assert_eq!(report.payload_bytes_read, logical_bytes);
}
