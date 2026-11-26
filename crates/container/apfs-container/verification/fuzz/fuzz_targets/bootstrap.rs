#![no_main]
#![forbid(unsafe_code)]

use apfs_container::probe_extent;
use apfs_core::{BoundsError, ByteOffset, ReadAt};
use apfs_format::object::checksum;
use libfuzzer_sys::fuzz_target;

const SOURCE_BYTES: u64 = 64 << 20;
const MAX_BLOCK_BYTES: usize = 64 << 10;
const RECOMPUTE_CHECKSUM: u8 = 1;
const BLOCK_BYTES_OFFSET: usize = 36;
const BLOCK_COUNT_OFFSET: usize = 40;

fuzz_target!(|input: &[u8]| {
	let Some((&mode, block)) = input.split_first() else {
		return;
	};
	if block.len() > MAX_BLOCK_BYTES {
		return;
	}
	if mode & RECOMPUTE_CHECKSUM != 0 {
		let mut block = block.to_vec();
		if let Ok(value) = checksum(&block) {
			block[..size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
		}
		check_extent(&block);
	} else {
		check_extent(block);
	}
});

fn check_extent(block: &[u8]) {
	if let Ok(Some(extent)) = probe_extent(&BlockZero(block)) {
		let block_bytes = u32::from_le_bytes(
			block[BLOCK_BYTES_OFFSET..BLOCK_COUNT_OFFSET]
				.try_into()
				.unwrap(),
		);
		let block_count = u64::from_le_bytes(
			block[BLOCK_COUNT_OFFSET..][..size_of::<u64>()]
				.try_into()
				.unwrap(),
		);
		assert_eq!(
			u128::from(extent.get()),
			u128::from(block_bytes) * u128::from(block_count)
		);
		assert!(extent.get() <= SOURCE_BYTES);
	}
}

struct BlockZero<'a>(&'a [u8]);

impl ReadAt for BlockZero<'_> {
	type Error = BoundsError;

	fn len(&self) -> u64 {
		SOURCE_BYTES
	}

	fn read_exact_at(&self, offset: ByteOffset, output: &mut [u8]) -> Result<(), Self::Error> {
		assert_eq!(offset, ByteOffset(0));
		assert!(output.len() <= MAX_BLOCK_BYTES);
		self.0.read_exact_at(offset, output)
	}
}
