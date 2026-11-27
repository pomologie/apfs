use std::{cell::RefCell, num::NonZeroU64};

use apfs_container::probe_extent;
use apfs_core::{ByteOffset, ReadAt};
use apfs_format::superblock::{BLOCK_SIZE_PREFIX_BYTES, Superblock};

use super::{BOOTSTRAP, NATIVE_INCOMPATIBLE_FEATURES, TRAILING_BYTES};

const CONTAINER_BYTES: u64 = 128 << 20;

struct Capture {
	bytes: &'static [u8],
	block_bytes: u32,
	block_count: u64,
	checksum: u64,
}

const CAPTURES: [Capture; 5] = [
	Capture {
		bytes: include_bytes!("../fixtures/native-bootstrap-sizes/native-block-zero-4096.bin"),
		block_bytes: 4096,
		block_count: 32_768,
		checksum: 0xff6b_7d4b_7fef_6594,
	},
	Capture {
		bytes: include_bytes!("../fixtures/native-bootstrap-sizes/native-block-zero-8192.bin"),
		block_bytes: 8192,
		block_count: 16_384,
		checksum: 0x93df_e781_b706_a414,
	},
	Capture {
		bytes: include_bytes!("../fixtures/native-bootstrap-sizes/native-block-zero-16384.bin"),
		block_bytes: 16_384,
		block_count: 8192,
		checksum: 0x5f28_f8fa_40ab_799f,
	},
	Capture {
		bytes: include_bytes!("../fixtures/native-bootstrap-sizes/native-block-zero-32768.bin"),
		block_bytes: 32_768,
		block_count: 4096,
		checksum: 0x0f77_b0d4_dc41_16d7,
	},
	Capture {
		bytes: include_bytes!("../fixtures/native-bootstrap-sizes/native-block-zero-65536.bin"),
		block_bytes: 65_536,
		block_count: 2048,
		checksum: 0x4bcc_7609_f30e_3ca2,
	},
];

#[test]
fn native_probe_matches_all_admitted_block_sizes() {
	for capture in CAPTURES {
		let superblock = Superblock::decode(capture.bytes, CONTAINER_BYTES).unwrap();
		assert_eq!(superblock.geometry.block_bytes(), capture.block_bytes);
		assert_eq!(superblock.geometry.block_count(), capture.block_count);
		assert_eq!(superblock.object.checksum, capture.checksum);
		assert_eq!(superblock.incompatible, NATIVE_INCOMPATIBLE_FEATURES);
		for length in [CONTAINER_BYTES, CONTAINER_BYTES + TRAILING_BYTES] {
			let source = BootstrapSource {
				bytes: capture.bytes,
				length,
				reads: RefCell::default(),
			};
			let extent = probe_extent(&source).unwrap();
			assert_eq!(extent, NonZeroU64::new(CONTAINER_BYTES));
			let reads = source.reads.borrow();
			assert_eq!(
				*reads,
				[
					(BOOTSTRAP, BLOCK_SIZE_PREFIX_BYTES),
					(BOOTSTRAP, capture.block_bytes as usize)
				]
			);
			let (prefix_offset, prefix_bytes) = reads[0];
			let (block_offset, block_bytes) = reads[1];
			println!(
				"APFS native bootstrap matrix probe {} {length} {} {} {prefix_bytes} {} {block_bytes}",
				capture.block_bytes,
				extent.unwrap().get(),
				prefix_offset.0,
				block_offset.0,
			);
		}
		println!(
			"APFS native bootstrap matrix {} {} {} {:016x}",
			capture.block_bytes, capture.block_count, CONTAINER_BYTES, capture.checksum
		);
	}
}

struct BootstrapSource {
	bytes: &'static [u8],
	length: u64,
	reads: RefCell<Vec<(ByteOffset, usize)>>,
}

impl ReadAt for BootstrapSource {
	type Error = usize;

	fn len(&self) -> u64 {
		self.length
	}

	fn read_exact_at(&self, offset: ByteOffset, output: &mut [u8]) -> Result<(), Self::Error> {
		self.reads.borrow_mut().push((offset, output.len()));
		if offset != BOOTSTRAP {
			return Err(output.len());
		}
		output.copy_from_slice(self.bytes.get(..output.len()).ok_or(output.len())?);
		Ok(())
	}
}
