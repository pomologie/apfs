#![no_main]

use std::sync::LazyLock;

use apfs_format::{
	Error,
	object::{Header, checksum},
	superblock::{BlockAddress, Geometry, Superblock},
};
use libfuzzer_sys::fuzz_target;

const DEVICE_BYTES: u64 = 64 << 20;
const FIXTURE_BLOCK_BYTES: u32 = 4096;
const FIXTURE_BLOCK_COUNT: u64 = 16_384;
const NXSB: &[u8] = include_bytes!("../../../tests/fixtures/native-block-0.bin");
const OBJECTS: &[&[u8]] = &[
	NXSB,
	include_bytes!("../../../tests/fixtures/native-block-1.bin"),
	include_bytes!("../../../tests/fixtures/native-block-2.bin"),
	include_bytes!("../../../tests/fixtures/native-block-3.bin"),
	include_bytes!("../../../tests/fixtures/native-block-4.bin"),
	include_bytes!("../../../tests/fixtures/sonoma-populated-omap-container.bin"),
	include_bytes!("../../../tests/fixtures/sonoma-populated-omap-volume.bin"),
];
const CHECKSUM_BYTES: usize = size_of::<u64>();
const WORD_BYTES: usize = size_of::<u32>();
const WIRE_TYPE_OFFSET: usize = 24;
const WIRE_HEADER_BYTES: usize = 32;
const MODULUS: u128 = u32::MAX as u128;

static GEOMETRY: LazyLock<Geometry> = LazyLock::new(|| {
	let geometry = Superblock::decode(NXSB, DEVICE_BYTES).unwrap().geometry;
	assert_eq!(geometry.block_bytes(), FIXTURE_BLOCK_BYTES);
	assert_eq!(geometry.block_count(), FIXTURE_BLOCK_COUNT);
	geometry
});

fuzz_target!(|request: &[u8]| {
	let Some((&selector, payload)) = request.split_first() else {
		return;
	};
	let (words, remainder) = payload.as_chunks::<{ size_of::<u64>() }>();
	let ([first, second], []) = (words, remainder) else {
		return;
	};
	let start = u64::from_le_bytes(*first);
	let count = u64::from_le_bytes(*second);
	match selector % 3 {
		0 => check_window(start, count),
		1 => check_range(start, count),
		_ => check_range(
			start % (FIXTURE_BLOCK_COUNT + 1),
			count % (FIXTURE_BLOCK_COUNT + 1),
		),
	}
});

fn check_range(start: u64, count: u64) {
	let end = u128::from(start) + u128::from(count);
	let expected = if end <= u128::from(FIXTURE_BLOCK_COUNT) {
		let width = u128::from(FIXTURE_BLOCK_BYTES);
		Ok(u64::try_from(u128::from(start) * width).unwrap()..u64::try_from(end * width).unwrap())
	} else {
		Err(Error::InvalidGeometry)
	};
	assert_eq!(GEOMETRY.byte_range(BlockAddress(start), count), expected);
}

fn check_window(fixture: u64, length: u64) {
	let index = (fixture % OBJECTS.len() as u64) as usize;
	let object = OBJECTS[index];
	let length = (length % (object.len() as u64 + 1)) as usize;
	let prefix = &object[..length];
	let expected_type = prefix
		.get(WIRE_TYPE_OFFSET..WIRE_TYPE_OFFSET + WORD_BYTES)
		.map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
		.ok_or(Error::Truncated);
	assert_eq!(Header::type_hint(prefix), expected_type);
	if length < WIRE_HEADER_BYTES || !length.is_multiple_of(WORD_BYTES) {
		assert_eq!(checksum(prefix), Err(Error::Truncated));
		return;
	}
	let (words, remainder) = prefix[CHECKSUM_BYTES..].as_chunks::<WORD_BYTES>();
	assert!(remainder.is_empty());
	let weights = (1..=words.len() as u128).rev();
	let (sum, weighted) =
		words
			.iter()
			.zip(weights)
			.fold((0, 0), |(sum, weighted), (word, weight)| {
				let word = u128::from(u32::from_le_bytes(*word));
				(sum + word, weighted + word * weight)
			});
	let low = MODULUS - (sum + weighted) % MODULUS;
	let high = 1 + ((weighted + MODULUS - 1) % MODULUS);
	let expected = (u64::try_from(high).unwrap() << u32::BITS) | u64::try_from(low).unwrap();
	assert_eq!(checksum(prefix), Ok(expected));
}
