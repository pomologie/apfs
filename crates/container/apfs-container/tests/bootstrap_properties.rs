use std::cell::Cell;

use apfs_container::{Container, Error, OpenOptions, Unsupported, probe_extent};
use apfs_core::{BoundsError, ByteOffset, ReadAt};
use apfs_format::{
	Error as FormatError,
	object::{Header, ObjectId, TransactionId, checksum},
	superblock::{BLOCK_SIZE_PREFIX_BYTES, BlockAddress, Superblock},
};

const NATIVE: &[u8; 4096] = include_bytes!("fixtures/native-block-0.bin");
const BLOCK_SIZES: [u32; 5] = [4096, 8192, 16_384, 32_768, 65_536];
const INVALID_SIZES: [u32; 7] = [0, 1, 2048, 4095, 4097, 65_537, u32::MAX];
const MIN_CONTAINER_BYTES: u64 = 1 << 20;
const DEVICE_BYTES: u64 = 64 << 20;
const BOOTSTRAP: ByteOffset = ByteOffset(0);
const CHECKSUM_BYTES: usize = size_of::<u64>();
const BLOCK_SIZE: usize = 36;
const BLOCK_COUNT: usize = 40;
const OPTIONAL: usize = 48;
const READ_ONLY_COMPATIBLE: usize = 56;
const INCOMPATIBLE: usize = 64;
const DESCRIPTOR_COUNT: usize = 104;
const DATA_COUNT: usize = 108;
const DESCRIPTOR_BASE: usize = 112;
const DATA_BASE: usize = 120;
const OBJECT_MAP: usize = 160;
const KNOWN_FEATURE_BIT: u32 = 1;
const KNOWN_PROFILE: u64 = 1 << KNOWN_FEATURE_BIT;
const OPTIONAL_DEFRAG: u64 = 1;
const READ_ONLY_EXTENSION: u64 = 1 << 63;
const REQUIRED_EXTENSION_A: u64 = 1 << 62;
const REQUIRED_EXTENSION_B: u64 = 1 << 63;
const HEADER_BYTES: usize = 32;
const WORD_BYTES: usize = 4;
const HEADER_SAMPLE_BYTES: usize = 64;
const SAMPLE_OBJECT_ID: ObjectId = ObjectId(0x0f0e_0d0c_0b0a_0908);
const SAMPLE_TRANSACTION: TransactionId = TransactionId(0x1716_1514_1312_1110);
const SAMPLE_TYPE: u32 = 0x1b1a_1918;
const SAMPLE_SUBTYPE: u32 = 0x1f1e_1d1c;

#[test]
fn nxsb_size_prefix_matches_supported_block_dimensions() {
	let mut prefix: [u8; BLOCK_SIZE_PREFIX_BYTES] =
		NATIVE[..BLOCK_SIZE_PREFIX_BYTES].try_into().unwrap();
	for size in BLOCK_SIZES {
		prefix[BLOCK_SIZE..].copy_from_slice(&size.to_le_bytes());
		assert_eq!(Superblock::block_size_hint(&prefix), Ok(size));
	}
	for size in INVALID_SIZES {
		prefix[BLOCK_SIZE..].copy_from_slice(&size.to_le_bytes());
		assert_eq!(
			Superblock::block_size_hint(&prefix),
			Err(FormatError::InvalidGeometry)
		);
	}
	println!(
		"\nAPFS bootstrap property size-prefix {} {}",
		BLOCK_SIZES.len(),
		INVALID_SIZES.len()
	);
}

#[test]
fn nxsb_count_and_byte_ranges_match_widened_arithmetic() {
	println!();
	for size in BLOCK_SIZES {
		let min_blocks = MIN_CONTAINER_BYTES / u64::from(size);
		let mut block = single_store_nxsb(size, min_blocks);
		let max_blocks = u64::MAX / u64::from(size);
		let cases = [
			(min_blocks - 1, MIN_CONTAINER_BYTES),
			(min_blocks, MIN_CONTAINER_BYTES - 1),
			(min_blocks, MIN_CONTAINER_BYTES),
			(min_blocks, MIN_CONTAINER_BYTES + 1),
			(max_blocks, u64::MAX),
			(max_blocks + 1, u64::MAX),
			(u64::MAX, u64::MAX),
		];
		let (mut admitted, mut ranges) = (0, 0);
		let (mut rejected, mut refused_invocations) = (0, 0);
		for (count, device_bytes) in cases {
			put(&mut block, BLOCK_COUNT, count.to_le_bytes());
			seal(&mut block);
			let result = Superblock::decode(&block, device_bytes);
			let extent = u128::from(count) * u128::from(size);
			if !(u128::from(MIN_CONTAINER_BYTES)..=u128::from(device_bytes)).contains(&extent) {
				assert_eq!(result, Err(FormatError::InvalidGeometry));
				refused_invocations += check_geometry_cutoff(&block, device_bytes);
				rejected += 1;
				continue;
			}
			let geometry = result.unwrap().geometry;
			assert_eq!(
				(geometry.block_bytes(), geometry.block_count()),
				(size, count)
			);
			let source = BlockZero {
				block: &block,
				device_bytes,
				reads: Cell::new(0),
			};
			assert_eq!(
				probe_extent(&source).unwrap().unwrap().get(),
				u64::try_from(extent).unwrap()
			);
			assert_eq!(source.reads.get(), 2);
			admitted += 1;
			for (base, blocks) in [
				(0, 0),
				(0, count),
				(count - 1, 1),
				(count, 0),
				(count, 1),
				(count + 1, 0),
				(u64::MAX, 1),
				(1, u64::MAX),
			] {
				let end = u128::from(base) + u128::from(blocks);
				let expected = if end <= u128::from(count) {
					let start = u128::from(base) * u128::from(size);
					let end = end * u128::from(size);
					Ok(u64::try_from(start).unwrap()..u64::try_from(end).unwrap())
				} else {
					Err(FormatError::InvalidGeometry)
				};
				assert_eq!(geometry.byte_range(BlockAddress(base), blocks), expected);
				ranges += 1;
			}
		}
		println!(
			"APFS bootstrap property geometry {size} {} {admitted} {ranges}",
			cases.len()
		);
		println!("APFS bootstrap property geometry-cutoff {size} {rejected} {refused_invocations}");
	}
}

fn check_geometry_cutoff(block: &[u8], device_bytes: u64) -> usize {
	let xid = Header::decode(block).unwrap().transaction;
	let source = BlockZero {
		block,
		device_bytes,
		reads: Cell::new(0),
	};
	assert!(matches!(
		probe_extent(&source),
		Err(Error::Bootstrap(FormatError::InvalidGeometry))
	));
	assert_eq!(source.reads.replace(0), 2);

	let mut refused = 1;
	for transaction in [None, Some(xid)] {
		let options = OpenOptions {
			max_object_bytes: block.len(),
			..OpenOptions::default()
		};
		let result = match transaction {
			Some(xid) => Container::open_at(&source, options, xid),
			None => Container::open(&source, options),
		};
		assert!(matches!(
			result,
			Err(Error::Bootstrap(FormatError::InvalidGeometry))
		));
		assert_eq!(source.reads.replace(0), 2);
		refused += 1;
	}
	refused
}

#[test]
fn header_and_checksum_window_match_the_wire_alignment() {
	let mut sample: [u8; HEADER_SAMPLE_BYTES] =
		std::array::from_fn(|index| u8::try_from(index).unwrap());
	let mut complete = 0;
	for len in 0..=sample.len() {
		let object = &mut sample[..len];
		if len < HEADER_BYTES || !len.is_multiple_of(WORD_BYTES) {
			assert_eq!(checksum(object), Err(FormatError::Truncated));
			assert_eq!(Header::decode(object), Err(FormatError::Truncated));
			continue;
		}
		seal(object);
		let header = Header::decode(object).unwrap();
		assert_eq!(header.id, SAMPLE_OBJECT_ID);
		assert_eq!(header.transaction, SAMPLE_TRANSACTION);
		assert_eq!(header.object_type, SAMPLE_TYPE);
		assert_eq!(header.subtype, SAMPLE_SUBTYPE);
		object[0] ^= 1;
		assert_eq!(checksum(object), Ok(header.checksum));
		assert_eq!(Header::decode(object), Err(FormatError::InvalidChecksum));
		complete += 1;
	}
	println!(
		"\nAPFS bootstrap property checksum-window {} {complete}",
		sample.len() + 1
	);
}

#[test]
fn each_additional_required_feature_bit_stops_before_traversal() {
	let mut feature_bits = 0;
	for bit in (0..u64::BITS).filter(|&bit| bit != KNOWN_FEATURE_BIT) {
		let flag = KNOWN_PROFILE | (1 << bit);
		let mut block = *NATIVE;
		put(&mut block, INCOMPATIBLE, flag.to_le_bytes());
		seal(&mut block);
		let source = BlockZero {
			block: &block,
			device_bytes: DEVICE_BYTES,
			reads: Cell::new(0),
		};
		assert!(matches!(
			Container::open(&source, OpenOptions::default()),
			Err(Error::Unsupported { descriptor: BlockAddress(0), reason: Unsupported::IncompatibleFeatures(bits), .. })
				if bits == flag
		));
		assert_eq!(source.reads.get(), 2);
		feature_bits += 1;
	}
	println!("\nAPFS bootstrap property required-feature {feature_bits}");
}

#[test]
fn mixed_feature_masks_stop_both_open_paths_at_each_supported_size() {
	let expected_xid = Header::decode(NATIVE).unwrap().transaction;
	let unsupported = [
		0,
		KNOWN_PROFILE | REQUIRED_EXTENSION_A,
		KNOWN_PROFILE | REQUIRED_EXTENSION_B,
		KNOWN_PROFILE | REQUIRED_EXTENSION_A | REQUIRED_EXTENSION_B,
	];
	let compatible = [
		(0, 0),
		(OPTIONAL_DEFRAG, 0),
		(0, READ_ONLY_EXTENSION),
		(OPTIONAL_DEFRAG, READ_ONLY_EXTENSION),
	];
	println!();
	for size in BLOCK_SIZES {
		let mut block = single_store_nxsb(size, DEVICE_BYTES / u64::from(size));
		let mut refused_opens = 0;
		for required in unsupported {
			for (optional, read_only) in compatible {
				put(&mut block, OPTIONAL, optional.to_le_bytes());
				put(&mut block, READ_ONLY_COMPATIBLE, read_only.to_le_bytes());
				put(&mut block, INCOMPATIBLE, required.to_le_bytes());
				seal(&mut block);
				let decoded = Superblock::decode(&block, DEVICE_BYTES).unwrap();
				assert_eq!(
					(
						decoded.features,
						decoded.read_only_compatible,
						decoded.incompatible
					),
					(optional, read_only, required)
				);
				for transaction in [None, Some(expected_xid)] {
					let source = BlockZero {
						block: &block,
						device_bytes: DEVICE_BYTES,
						reads: Cell::new(0),
					};
					let options = OpenOptions::default();
					let result = match transaction {
						Some(xid) => Container::open_at(&source, options, xid),
						None => Container::open(&source, options),
					};
					assert!(matches!(result, Err(Error::Unsupported {
						descriptor: BlockAddress(0), transaction: xid,
						reason: Unsupported::IncompatibleFeatures(bits),
					}) if xid == expected_xid && bits == required));
					assert_eq!(source.reads.get(), 2);
					refused_opens += 1;
				}
			}
		}
		println!("APFS bootstrap property mixed-feature-cutoff {size} {refused_opens}");
	}
}

fn single_store_nxsb(size: u32, count: u64) -> Vec<u8> {
	let mut block = NATIVE.to_vec();
	block.resize(size as usize, 0);
	put(&mut block, BLOCK_SIZE, size.to_le_bytes());
	put(&mut block, BLOCK_COUNT, count.to_le_bytes());
	// Use two one-block rings and a map that fit even the smallest extent.
	put(&mut block, DESCRIPTOR_COUNT, 1_u32.to_le_bytes());
	put(&mut block, DATA_COUNT, 1_u32.to_le_bytes());
	put(&mut block, DESCRIPTOR_BASE, 1_u64.to_le_bytes());
	put(&mut block, DATA_BASE, 2_u64.to_le_bytes());
	put(&mut block, OBJECT_MAP, 3_u64.to_le_bytes());
	block
}

fn put<const N: usize>(bytes: &mut [u8], offset: usize, field: [u8; N]) {
	bytes[offset..offset + N].copy_from_slice(&field);
}

fn seal(object: &mut [u8]) {
	let check = checksum(object).unwrap();
	object[..CHECKSUM_BYTES].copy_from_slice(&check.to_le_bytes());
}

struct BlockZero<'a> {
	block: &'a [u8],
	device_bytes: u64,
	reads: Cell<usize>,
}

impl ReadAt for BlockZero<'_> {
	type Error = BoundsError;

	fn len(&self) -> u64 {
		self.device_bytes
	}

	fn read_exact_at(&self, at: ByteOffset, output: &mut [u8]) -> Result<(), Self::Error> {
		let sizes = [BLOCK_SIZE_PREFIX_BYTES, self.block.len()];
		let read = self.reads.get();
		assert_eq!(at, BOOTSTRAP);
		assert_eq!(output.len(), sizes[read]);
		self.reads.set(read + 1);
		self.block.read_exact_at(at, output)
	}
}
