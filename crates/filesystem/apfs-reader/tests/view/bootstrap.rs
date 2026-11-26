use std::{cell::Cell, num::NonZeroU64};

use apfs_container::{Container, Error, OpenOptions, Unsupported, probe_extent};
use apfs_core::{ByteOffset, ReadAt};
use apfs_format::{
	Error as FormatError,
	checkpoint::Map,
	superblock::{BLOCK_SIZE_PREFIX_BYTES, BlockAddress},
};

use super::{BLOCK_BYTES, DEVICE_BYTES, Fixture, POPULATED_CHECKPOINT, container, update_checksum};

const BOOTSTRAP_BLOCK: BlockAddress = BlockAddress(0);
const BOOTSTRAP_OFFSET: ByteOffset = ByteOffset(0);
const NATIVE_BOOTSTRAP_CHECKSUM: u64 = 0xdd93_6844_4871_caee;
const CHECKSUM_OFFSET: usize = 0;
const OBJECT_TYPE_OFFSET: usize = 24;
const BLOCK_SIZE_OFFSET: usize = 36;
const BLOCK_COUNT_OFFSET: usize = 40;
const INCOMPATIBLE_FEATURES_OFFSET: usize = 64;
const UNKNOWN_REQUIRED_FEATURE: u64 = 1 << 63;
const NATIVE_INCOMPATIBLE_FEATURES: u64 = 1 << 1;
const UNKNOWN_PROFILE: u64 = UNKNOWN_REQUIRED_FEATURE | NATIVE_INCOMPATIBLE_FEATURES;
const CHECKPOINT_MAP_TYPE: u32 = Map::OBJECT_TYPE;

#[test]
fn recognizes_the_populated_sonoma_bootstrap() {
	let fixture = Fixture::native_populated();
	let source = BootstrapOnly::new(&fixture);
	let extent = probe_extent(&source).unwrap();
	assert_eq!(extent, NonZeroU64::new(DEVICE_BYTES));
	assert_eq!(source.reads.get(), 2);
	let reads = source.reads.get();
	let source = container(fixture);
	let checkpoint = source.superblock();
	assert_eq!(checkpoint.object.transaction, POPULATED_CHECKPOINT);
	assert_eq!(
		source.source().0[&BOOTSTRAP_BLOCK.0][..size_of::<u64>()],
		NATIVE_BOOTSTRAP_CHECKSUM.to_le_bytes()
	);
	println!(
		"\nAPFS native bootstrap admitted {} {} {} {} {:016x} {reads}",
		extent.unwrap().get(),
		checkpoint.geometry.block_bytes(),
		checkpoint.geometry.block_count(),
		checkpoint.object.transaction.0,
		NATIVE_BOOTSTRAP_CHECKSUM,
	);
}

#[test]
fn rejects_bad_bootstrap_size_before_the_full_block_read() {
	let mut fixture = Fixture::native_populated();
	let block = fixture.0.get_mut(&BOOTSTRAP_BLOCK.0).unwrap();
	block[BLOCK_SIZE_OFFSET..BLOCK_COUNT_OFFSET].copy_from_slice(&u32::MAX.to_le_bytes());
	let source = BootstrapOnly::new(&fixture);
	assert!(matches!(
		Container::open(&source, OpenOptions::default()),
		Err(Error::Bootstrap(FormatError::InvalidGeometry))
	));
	assert_eq!(source.reads.get(), 1);
	println!(
		"\nAPFS native bootstrap refused size {}",
		source.reads.get()
	);
}

#[test]
fn rejects_bad_bootstrap_count_type_and_checksum_without_traversal() {
	let cases: [(&str, usize, &[u8], FormatError); 3] = [
		(
			"count",
			BLOCK_COUNT_OFFSET,
			&u64::MAX.to_le_bytes(),
			FormatError::InvalidGeometry,
		),
		(
			"type",
			OBJECT_TYPE_OFFSET,
			&CHECKPOINT_MAP_TYPE.to_le_bytes(),
			FormatError::UnexpectedObjectType(CHECKPOINT_MAP_TYPE),
		),
		(
			"checksum",
			CHECKSUM_OFFSET,
			&(NATIVE_BOOTSTRAP_CHECKSUM ^ 1).to_le_bytes(),
			FormatError::InvalidChecksum,
		),
	];
	for (case, offset, bytes, expected) in cases {
		let mut fixture = Fixture::native_populated();
		let block = fixture.0.get_mut(&BOOTSTRAP_BLOCK.0).unwrap();
		block[offset..offset + bytes.len()].copy_from_slice(bytes);
		if expected != FormatError::InvalidChecksum {
			update_checksum(block);
		}
		let source = BootstrapOnly::new(&fixture);
		assert!(matches!(
			Container::open(&source, OpenOptions::default()),
			Err(Error::Bootstrap(error)) if error == expected
		));
		assert_eq!(source.reads.get(), 2);
		println!(
			"\nAPFS native bootstrap refused {case} {}",
			source.reads.get()
		);
	}
}

#[test]
fn reports_the_populated_bootstrap_as_unsupported_for_an_unknown_required_feature() {
	let mut fixture = Fixture::native_populated();
	let block = fixture.0.get_mut(&BOOTSTRAP_BLOCK.0).unwrap();
	block[INCOMPATIBLE_FEATURES_OFFSET..][..size_of::<u64>()]
		.copy_from_slice(&UNKNOWN_PROFILE.to_le_bytes());
	update_checksum(block);
	let source = BootstrapOnly::new(&fixture);
	assert!(matches!(
		Container::open(&source, OpenOptions::default()),
		Err(Error::Unsupported {
			descriptor: BOOTSTRAP_BLOCK,
			transaction: POPULATED_CHECKPOINT,
			reason: Unsupported::IncompatibleFeatures(UNKNOWN_PROFILE),
		})
	));
	assert_eq!(source.reads.get(), 2);
	println!(
		"\nAPFS native bootstrap refused required-feature {}",
		source.reads.get()
	);
}

struct BootstrapOnly<'a> {
	fixture: &'a Fixture,
	reads: Cell<usize>,
}

impl<'a> BootstrapOnly<'a> {
	fn new(fixture: &'a Fixture) -> Self {
		Self {
			fixture,
			reads: Cell::new(0),
		}
	}
}

impl ReadAt for BootstrapOnly<'_> {
	type Error = <Fixture as ReadAt>::Error;

	fn len(&self) -> u64 {
		self.fixture.len()
	}

	fn read_exact_at(&self, at: ByteOffset, destination: &mut [u8]) -> Result<(), Self::Error> {
		let expected_reads = [BLOCK_SIZE_PREFIX_BYTES, BLOCK_BYTES];
		let read = self.reads.get();
		assert_eq!(at, BOOTSTRAP_OFFSET);
		assert_eq!(destination.len(), expected_reads[read]);
		self.reads.set(read + 1);
		self.fixture.read_exact_at(at, destination)
	}
}
