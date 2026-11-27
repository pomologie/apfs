#![no_main]

use std::sync::LazyLock;

use apfs_format::{
	Error,
	object::{Header, checksum},
	superblock::{BlockAddress, Geometry, Superblock},
};
use libfuzzer_sys::fuzz_target;

const NATIVE_SUPERBLOCKS: [&[u8]; 6] = [
	include_bytes!("../../../tests/fixtures/native-block-0.bin"),
	include_bytes!(
		"../../../../../container/apfs-container/tests/fixtures/native-bootstrap-sizes/native-block-zero-4096.bin"
	),
	include_bytes!(
		"../../../../../container/apfs-container/tests/fixtures/native-bootstrap-sizes/native-block-zero-8192.bin"
	),
	include_bytes!(
		"../../../../../container/apfs-container/tests/fixtures/native-bootstrap-sizes/native-block-zero-16384.bin"
	),
	include_bytes!(
		"../../../../../container/apfs-container/tests/fixtures/native-bootstrap-sizes/native-block-zero-32768.bin"
	),
	include_bytes!(
		"../../../../../container/apfs-container/tests/fixtures/native-bootstrap-sizes/native-block-zero-65536.bin"
	),
];
const OBJECTS: &[&[u8]] = &[
	NATIVE_SUPERBLOCKS[0],
	include_bytes!("../../../tests/fixtures/native-block-1.bin"),
	include_bytes!("../../../tests/fixtures/native-block-2.bin"),
	include_bytes!("../../../tests/fixtures/native-block-3.bin"),
	include_bytes!("../../../tests/fixtures/native-block-4.bin"),
	include_bytes!("../../../tests/fixtures/sonoma-populated-omap-container.bin"),
	include_bytes!("../../../tests/fixtures/sonoma-populated-omap-volume.bin"),
	NATIVE_SUPERBLOCKS[1],
	NATIVE_SUPERBLOCKS[2],
	NATIVE_SUPERBLOCKS[3],
	NATIVE_SUPERBLOCKS[4],
	NATIVE_SUPERBLOCKS[5],
];
const CHECKSUM_BYTES: usize = size_of::<u64>();
const WORD_BYTES: usize = size_of::<u32>();
const WIRE_TYPE_OFFSET: usize = 24;
const WIRE_HEADER_BYTES: usize = 32;
const WIRE_BLOCK_SIZE: usize = 36;
const WIRE_BLOCK_COUNT: usize = 40;
const REQUEST_KINDS: u8 = 4;
const MODULUS: u128 = u32::MAX as u128;

struct Fixture {
	bytes: &'static [u8],
	width: u32,
	count: u64,
	extent: u64,
	geometry: Geometry,
}

static FIXTURES: LazyLock<[Fixture; NATIVE_SUPERBLOCKS.len()]> = LazyLock::new(|| {
	NATIVE_SUPERBLOCKS.map(|bytes| {
		let width =
			u32::from_le_bytes(bytes[WIRE_BLOCK_SIZE..WIRE_BLOCK_COUNT].try_into().unwrap());
		let count = wire_u64(bytes, WIRE_BLOCK_COUNT);
		assert_eq!(width as usize, bytes.len());
		let extent = u64::from(width).checked_mul(count).unwrap();
		let geometry = Superblock::decode(bytes, extent).unwrap().geometry;
		assert_eq!(
			(geometry.block_bytes(), geometry.block_count()),
			(width, count)
		);
		Fixture {
			bytes,
			width,
			count,
			extent,
			geometry,
		}
	})
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
	let fixture = &FIXTURES[usize::from(selector / REQUEST_KINDS) % FIXTURES.len()];
	match selector % REQUEST_KINDS {
		0 => check_window(start, count),
		1 => check_range(fixture, start, count),
		2 => check_range(
			fixture,
			start % (fixture.count + 1),
			count % (fixture.count + 1),
		),
		_ => check_extent(fixture, start, count),
	}
});

fn check_range(fixture: &Fixture, start: u64, count: u64) {
	let end = u128::from(start) + u128::from(count);
	let expected = if end <= u128::from(fixture.count) {
		let width = u128::from(fixture.width);
		Ok(u64::try_from(u128::from(start) * width).unwrap()..u64::try_from(end * width).unwrap())
	} else {
		Err(Error::InvalidGeometry)
	};
	assert_eq!(
		fixture.geometry.byte_range(BlockAddress(start), count),
		expected
	);
}

fn check_extent(fixture: &Fixture, length: u64, mode: u64) {
	let source_bytes = if mode.is_multiple_of(2) {
		length
	} else {
		length % (fixture.extent * 2)
	};
	let observed = Superblock::decode(fixture.bytes, source_bytes);
	if source_bytes < fixture.extent {
		assert_eq!(observed, Err(Error::InvalidGeometry));
	} else {
		assert_eq!(observed.unwrap().geometry, fixture.geometry);
	}
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
		assert_eq!(Header::decode(prefix), Err(Error::Truncated));
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
	let observed = Header::decode(prefix);
	if wire_u64(prefix, 0) != expected {
		assert_eq!(observed, Err(Error::InvalidChecksum));
	} else {
		let header = observed.unwrap();
		assert_eq!(header.checksum, expected);
		assert_eq!(header.id.0, wire_u64(prefix, CHECKSUM_BYTES));
		assert_eq!(header.transaction.0, wire_u64(prefix, 2 * CHECKSUM_BYTES));
		assert_eq!(Ok(header.object_type), expected_type);
		assert_eq!(
			header.subtype,
			u32::from_le_bytes(
				prefix[WIRE_TYPE_OFFSET + WORD_BYTES..WIRE_HEADER_BYTES]
					.try_into()
					.unwrap()
			)
		);
	}
}

fn wire_u64(bytes: &[u8], offset: usize) -> u64 {
	u64::from_le_bytes(bytes[offset..offset + size_of::<u64>()].try_into().unwrap())
}
