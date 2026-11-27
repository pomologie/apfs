use std::{cell::RefCell, num::NonZeroU64};

use apfs_container::{Container, Error, OpenOptions, Unsupported, probe_extent};
use apfs_core::{ByteOffset, ReadAt};
use apfs_format::{
	Error as FormatError,
	object::checksum,
	superblock::{BLOCK_SIZE_PREFIX_BYTES, BlockAddress, Superblock},
};

const BLOCK_BYTES: usize = 4096;
const CONTAINER_BYTES: u64 = 64 << 20;
const TRAILING_BYTES: u64 = 1024;
const BOOTSTRAP: ByteOffset = ByteOffset(0);
const BOOTSTRAP_DESCRIPTOR: BlockAddress = BlockAddress(0);
const PREFIX_READS: [(ByteOffset, usize); 1] = [(BOOTSTRAP, BLOCK_SIZE_PREFIX_BYTES)];
const BOOTSTRAP_READS: [(ByteOffset, usize); 2] = [
	(BOOTSTRAP, BLOCK_SIZE_PREFIX_BYTES),
	(BOOTSTRAP, BLOCK_BYTES),
];
const BLOCK_SIZE_OFFSET: usize = BLOCK_SIZE_PREFIX_BYTES - size_of::<u32>();
const BLOCK_COUNT_OFFSET: usize = BLOCK_SIZE_PREFIX_BYTES;
const INCOMPATIBLE_OFFSET: usize = 64;
const NATIVE_INCOMPATIBLE_FEATURES: u64 = 1 << 1;
const UNKNOWN_PROFILE: u64 = NATIVE_INCOMPATIBLE_FEATURES | (1 << 63);
const LARGER_BLOCK_BYTES: u32 = 8192;

#[derive(Debug)]
struct Source {
	block: [u8; BLOCK_BYTES],
	length: u64,
	reads: RefCell<Vec<(ByteOffset, usize)>>,
}

impl Source {
	fn native() -> Self {
		Self {
			block: *include_bytes!("fixtures/native-block-0.bin"),
			length: CONTAINER_BYTES + TRAILING_BYTES,
			reads: RefCell::default(),
		}
	}

	fn set_u64(&mut self, offset: usize, value: u64) {
		self.block[offset..offset + size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
		let checksum = checksum(&self.block).unwrap().to_le_bytes();
		self.block[..checksum.len()].copy_from_slice(&checksum);
	}
}

impl ReadAt for Source {
	type Error = usize;

	fn len(&self) -> u64 {
		self.length
	}

	fn read_exact_at(&self, offset: ByteOffset, output: &mut [u8]) -> Result<(), Self::Error> {
		self.reads.borrow_mut().push((offset, output.len()));
		if offset != BOOTSTRAP {
			return Err(output.len());
		}
		let bytes = self.block.get(..output.len()).ok_or(output.len())?;
		output.copy_from_slice(bytes);
		Ok(())
	}
}

#[test]
fn native_geometry_ignores_trailing_bytes_and_reads_only_block_zero() {
	let source = Source::native();
	assert_eq!(
		probe_extent(&source).unwrap(),
		NonZeroU64::new(CONTAINER_BYTES)
	);
	assert_eq!(*source.reads.borrow(), BOOTSTRAP_READS);
}

#[test]
fn probes_a_second_apple_geometry_from_its_native_block_zero() {
	const NATIVE_BYTES: u64 = 128 << 20;
	const NATIVE_BLOCKS: u64 = 32_768;
	const NATIVE_CHECKSUM: u64 = 0xa5b5_616f_e64c_89d5;
	const NATIVE_BLOCK: [u8; BLOCK_BYTES] = *include_bytes!("fixtures/sonoma-128m-bootstrap.bin");
	let superblock = Superblock::decode(&NATIVE_BLOCK, NATIVE_BYTES).unwrap();
	assert_eq!(superblock.object.checksum, NATIVE_CHECKSUM);
	assert_eq!(superblock.geometry.block_bytes() as usize, BLOCK_BYTES);
	assert_eq!(superblock.geometry.block_count(), NATIVE_BLOCKS);

	for length in [NATIVE_BYTES, NATIVE_BYTES + TRAILING_BYTES] {
		let source = Source {
			block: NATIVE_BLOCK,
			length,
			reads: RefCell::default(),
		};
		assert_eq!(
			probe_extent(&source).unwrap(),
			NonZeroU64::new(NATIVE_BYTES)
		);
		assert_eq!(*source.reads.borrow(), BOOTSTRAP_READS);
	}
}

#[test]
fn short_source_and_missing_magic_are_absent() {
	let mut source = Source::native();
	source.length = BLOCK_SIZE_PREFIX_BYTES as u64 - 1;
	assert_eq!(probe_extent(&source).unwrap(), None);
	assert!(source.reads.borrow().is_empty());

	source.length = BLOCK_SIZE_PREFIX_BYTES as u64;
	source.block.fill(0);
	assert_eq!(probe_extent(&source).unwrap(), None);
	assert_eq!(*source.reads.borrow(), PREFIX_READS);
}

#[test]
fn recognized_bad_size_or_truncated_block_stops_after_prefix() {
	let mut truncated = Source::native();
	truncated.length = BLOCK_BYTES as u64 - 1;
	let mut bad_size = Source::native();
	bad_size.block[BLOCK_SIZE_OFFSET..BLOCK_SIZE_PREFIX_BYTES].fill(0);
	for source in [truncated, bad_size] {
		assert!(matches!(
			probe_extent(&source),
			Err(Error::Bootstrap(FormatError::InvalidGeometry))
		));
		assert_eq!(*source.reads.borrow(), PREFIX_READS);
	}
}

#[test]
fn checksum_and_container_bounds_fail_after_recognition() {
	let mut bad_checksum = Source::native();
	bad_checksum.block[BLOCK_BYTES - 1] ^= 1;
	assert!(matches!(
		probe_extent(&bad_checksum),
		Err(Error::Bootstrap(FormatError::InvalidChecksum))
	));

	let mut bad_count = Source::native();
	bad_count.set_u64(BLOCK_COUNT_OFFSET, u64::MAX);
	assert!(matches!(
		probe_extent(&bad_count),
		Err(Error::Bootstrap(FormatError::InvalidGeometry))
	));
}

#[test]
fn larger_valid_hint_propagates_a_full_block_read_failure() {
	let mut source = Source::native();
	source.block[BLOCK_SIZE_OFFSET..BLOCK_SIZE_PREFIX_BYTES]
		.copy_from_slice(&LARGER_BLOCK_BYTES.to_le_bytes());
	assert!(matches!(
		probe_extent(&source),
		Err(Error::Read { offset: BOOTSTRAP, source }) if source == LARGER_BLOCK_BYTES as usize
	));
}

#[test]
fn geometry_recognition_and_unsupported_checkpoint_profile_stay_distinct() {
	let mut source = Source::native();
	source.set_u64(INCOMPATIBLE_OFFSET, UNKNOWN_PROFILE);
	assert_eq!(
		probe_extent(&source).unwrap(),
		NonZeroU64::new(CONTAINER_BYTES)
	);
	source.reads.borrow_mut().clear();
	assert!(matches!(
		Container::open(&source, OpenOptions::default()),
		Err(Error::Unsupported {
			descriptor: BOOTSTRAP_DESCRIPTOR,
			reason: Unsupported::IncompatibleFeatures(UNKNOWN_PROFILE),
			..
		})
	));
	assert_eq!(*source.reads.borrow(), BOOTSTRAP_READS);
}

#[test]
fn malformed_bootstrap_never_reads_checkpoint_blocks() {
	let mut bad_size = Source::native();
	bad_size.block[BLOCK_SIZE_OFFSET..BLOCK_SIZE_PREFIX_BYTES]
		.copy_from_slice(&u32::MAX.to_le_bytes());
	assert!(matches!(
		Container::open(&bad_size, OpenOptions::default()),
		Err(Error::Bootstrap(FormatError::InvalidGeometry))
	));
	assert_eq!(*bad_size.reads.borrow(), PREFIX_READS);

	let mut bad_count = Source::native();
	bad_count.set_u64(BLOCK_COUNT_OFFSET, u64::MAX);
	let mut bad_checksum = Source::native();
	bad_checksum.block[BLOCK_BYTES - 1] ^= 1;
	for (source, expected) in [
		(bad_count, FormatError::InvalidGeometry),
		(bad_checksum, FormatError::InvalidChecksum),
	] {
		assert!(matches!(
			Container::open(&source, OpenOptions::default()),
			Err(Error::Bootstrap(error)) if error == expected
		));
		assert_eq!(*source.reads.borrow(), BOOTSTRAP_READS);
	}
}
