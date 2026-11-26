use std::cell::Cell;

use apfs_format::{
	Error,
	object::checksum,
	superblock::{Area, AreaLocation, BlockAddress, Geometry, Superblock},
};
use proptest::{
	prelude::*,
	test_runner::{Config, RngAlgorithm, RngSeed, TestRunner},
};

const NATIVE: &[u8] = include_bytes!("fixtures/native-block-0.bin");
const BLOCK_SIZES: [u32; 5] = [4096, 8192, 16_384, 32_768, 65_536];
const CASES: u32 = 64;
const SEED: u64 = 7;
const MIN_CONTAINER_BYTES: u64 = 1 << 20;
const TREE_FLAG: u32 = 1 << 31;
const BLOCK_SIZE_OFFSET: usize = 36;
const BLOCK_COUNT_OFFSET: usize = 40;
const OBJECT_MAP_OFFSET: usize = 160;
const CHECKSUM_BYTES: usize = size_of::<u64>();
const MAX_SPAN_ENTRIES: usize = 8;
const NATIVE_BLOCK_BYTES: u32 = 4096;
const NATIVE_DEVICE_BYTES: u64 = 64 << 20;

const DESCRIPTOR: Layout = Layout {
	name: "descriptor",
	count: 104,
	base: 112,
	next: 128,
	index: 136,
	length: 140,
	select: |superblock| superblock.descriptors,
};
const DATA: Layout = Layout {
	name: "data",
	count: 108,
	base: 120,
	next: 132,
	index: 144,
	length: 148,
	select: |superblock| superblock.data,
};

struct Layout {
	name: &'static str,
	count: usize,
	base: usize,
	next: usize,
	index: usize,
	length: usize,
	select: fn(&Superblock) -> Area,
}

impl Layout {
	fn write(&self, bytes: &mut [u8], locator: Locator, cursor: Cursor) {
		put(bytes, self.count, locator.count.to_le_bytes());
		put(bytes, self.base, locator.base.to_le_bytes());
		put(bytes, self.next, cursor.next.to_le_bytes());
		put(bytes, self.index, cursor.index.to_le_bytes());
		put(bytes, self.length, cursor.length.to_le_bytes());
	}
}

#[derive(Clone, Copy, Debug)]
struct Locator {
	base: u64,
	count: u32,
}

#[derive(Clone, Copy, Debug, Default)]
struct Cursor {
	next: u32,
	index: u32,
	length: u32,
}

#[test]
fn generated_nxsb_locators_match_the_independent_wide_model() {
	println!("\nAPFS locator seed {SEED}");
	let cases = (
		any::<u64>(),
		any::<u64>(),
		any::<u32>(),
		any::<u32>(),
		any::<u32>(),
		any::<u32>(),
	);
	for layout in [&DESCRIPTOR, &DATA] {
		for block_bytes in BLOCK_SIZES {
			let mut runner = runner();
			let counts = std::cell::RefCell::new([0; SCENARIO_NAMES.len()]);
			runner
				.run(
					&cases,
					|(size, position, raw_count, next, index, length)| {
						let minimum = MIN_CONTAINER_BYTES / u64::from(block_bytes);
						let maximum = u64::MAX / u64::from(block_bytes);
						let blocks = minimum + size % (maximum - minimum + 1);
						let cursor = Cursor {
							next,
							index,
							length,
						};
						let mut object = superblock(block_bytes, blocks);
						for (slot, locator) in scenarios(blocks, position, raw_count)
							.into_iter()
							.enumerate()
						{
							layout.write(&mut object, locator, cursor);
							check_locator(
								&mut object,
								layout,
								locator,
								cursor,
								blocks,
								block_bytes,
							)?;
							counts.borrow_mut()[slot] += 1;
						}
						Ok(())
					},
				)
				.unwrap();
			for (name, count) in SCENARIO_NAMES.into_iter().zip(counts.into_inner()) {
				assert_eq!(count, CASES);
				println!(
					"APFS locator property {} {block_bytes} {name} {count}",
					layout.name
				);
			}
		}
	}
}

#[test]
fn generated_supported_span_sets_match_widened_endpoints() {
	println!("\nAPFS span seed {SEED}");
	let native = Superblock::decode(NATIVE, NATIVE_DEVICE_BYTES)
		.unwrap()
		.geometry;
	assert_eq!(
		native.block_count(),
		NATIVE_DEVICE_BYTES / u64::from(NATIVE_BLOCK_BYTES)
	);
	check_span_sets("native", NATIVE_BLOCK_BYTES, |_| native);
	for block_bytes in BLOCK_SIZES {
		check_span_sets("synthetic", block_bytes, |sample| {
			let size = u64::from(block_bytes);
			let minimum = MIN_CONTAINER_BYTES / size;
			let maximum = u64::MAX / size;
			let blocks = minimum + sample % (maximum - minimum + 1);
			let mut object = superblock(block_bytes, blocks);
			let check = checksum(&object).unwrap();
			object[..CHECKSUM_BYTES].copy_from_slice(&check.to_le_bytes());
			let geometry = Superblock::decode(&object, blocks * size).unwrap().geometry;
			assert_eq!(geometry.block_count(), blocks);
			geometry
		});
	}
}

fn check_span_sets(source: &str, block_bytes: u32, admit: impl Fn(u64) -> Geometry) {
	for entries in 0..=MAX_SPAN_ENTRIES {
		let cases = (
			any::<u64>(),
			proptest::collection::vec(any::<(u64, u64)>(), entries),
		);
		let completed = Cell::new(0);
		let checked_ranges = Cell::new(0);
		runner()
			.run(&cases, |(entropy, spans)| {
				let geometry = admit(entropy);
				let blocks = geometry.block_count();
				prop_assert_eq!(geometry.block_bytes(), block_bytes);
				prop_assert_eq!(spans.len(), entries);
				let ranges = spans.into_iter().map(|(position, length)| {
					let start = position % (blocks + 1);
					(start, length % (blocks - start + 1))
				});
				let boundaries = [(0, blocks), (blocks - 1, 1), (blocks, 0)];
				for (start, length) in ranges.chain(boundaries) {
					let size = u128::from(block_bytes);
					let first = u128::from(start) * size;
					let end = (u128::from(start) + u128::from(length)) * size;
					let expected = u64::try_from(first).unwrap()..u64::try_from(end).unwrap();
					prop_assert_eq!(
						geometry.byte_range(BlockAddress(start), length),
						Ok(expected)
					);
					checked_ranges.set(checked_ranges.get() + 1);
				}
				completed.set(completed.get() + 1);
				Ok(())
			})
			.unwrap();
		assert_eq!(completed.get(), CASES);
		println!(
			"APFS span property {source} {block_bytes} {entries} {} {}",
			completed.get(),
			checked_ranges.get(),
		);
	}
}

fn runner() -> TestRunner {
	TestRunner::new(Config {
		cases: CASES,
		failure_persistence: None,
		rng_algorithm: RngAlgorithm::ChaCha,
		rng_seed: RngSeed::Fixed(SEED),
		..Config::default()
	})
}

const SCENARIO_NAMES: [&str; 7] = [
	"contiguous-boundary",
	"fragment-locator",
	"beyond-source",
	"offset-overflow",
	"empty-ring",
	"missing-base",
	"raw-fields",
];

fn scenarios(blocks: u64, position: u64, raw_count: u32) -> [Locator; SCENARIO_NAMES.len()] {
	let max_count = u32::try_from((blocks - 1).min(u64::from(TREE_FLAG - 1))).unwrap();
	let contiguous = 1 + raw_count % max_count;
	let flags = raw_count & TREE_FLAG;
	[
		Locator {
			base: blocks - u64::from(contiguous),
			count: contiguous,
		},
		Locator {
			base: 1 + position % (blocks - 1),
			count: TREE_FLAG | contiguous,
		},
		Locator {
			base: blocks,
			count: flags | contiguous,
		},
		Locator {
			base: u64::MAX - (position % 8),
			count: 8,
		},
		Locator {
			base: 1 + position % (blocks - 1),
			count: flags,
		},
		Locator {
			base: 0,
			count: flags | contiguous,
		},
		Locator {
			base: position,
			count: raw_count,
		},
	]
}

fn check_locator(
	object: &mut [u8],
	layout: &Layout,
	locator: Locator,
	cursor: Cursor,
	blocks: u64,
	block_bytes: u32,
) -> Result<(), TestCaseError> {
	let check = checksum(object).unwrap();
	object[..CHECKSUM_BYTES].copy_from_slice(&check.to_le_bytes());
	let source_bytes = blocks * u64::from(block_bytes);
	let actual = Superblock::decode(object, source_bytes);
	let count = locator.count % TREE_FLAG;
	let fragmented = locator.count >= TREE_FLAG;
	let span = if fragmented { 1 } else { u64::from(count) };
	let end = u128::from(locator.base) + u128::from(span);
	if count == 0 || locator.base == 0 || end > u128::from(blocks) {
		prop_assert_eq!(actual, Err(Error::InvalidCheckpoint));
		return Ok(());
	}
	let superblock = actual
		.map_err(|error| TestCaseError::fail(format!("valid locator {locator:?}: {error}")))?;
	let area = (layout.select)(&superblock);
	let address = BlockAddress(locator.base);
	let location = if fragmented {
		AreaLocation::FragmentTree(address)
	} else {
		AreaLocation::Contiguous(address)
	};
	prop_assert_eq!(area.location, location);
	prop_assert_eq!(
		(area.blocks, area.next, area.index, area.length),
		(count, cursor.next, cursor.index, cursor.length)
	);
	prop_assert_eq!(
		(
			superblock.geometry.block_bytes(),
			superblock.geometry.block_count()
		),
		(block_bytes, blocks)
	);
	let start_bytes = u128::from(locator.base) * u128::from(block_bytes);
	let end_bytes = end * u128::from(block_bytes);
	let expected = u64::try_from(start_bytes).unwrap()..u64::try_from(end_bytes).unwrap();
	prop_assert_eq!(superblock.geometry.byte_range(address, span), Ok(expected));
	Ok(())
}

fn superblock(block_bytes: u32, blocks: u64) -> Vec<u8> {
	let mut object = NATIVE.to_vec();
	object.resize(block_bytes as usize, 0);
	put(&mut object, BLOCK_SIZE_OFFSET, block_bytes.to_le_bytes());
	put(&mut object, BLOCK_COUNT_OFFSET, blocks.to_le_bytes());
	put(&mut object, OBJECT_MAP_OFFSET, 3_u64.to_le_bytes());
	DESCRIPTOR.write(
		&mut object,
		Locator { base: 1, count: 1 },
		Cursor::default(),
	);
	DATA.write(
		&mut object,
		Locator { base: 2, count: 1 },
		Cursor::default(),
	);
	object
}

fn put<const N: usize>(object: &mut [u8], offset: usize, field: [u8; N]) {
	object[offset..offset + N].copy_from_slice(&field);
}
