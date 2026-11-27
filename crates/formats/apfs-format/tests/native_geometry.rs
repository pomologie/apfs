use std::{env, fs, path::PathBuf};

use apfs_format::{
	checkpoint::Map,
	object::Header,
	superblock::{AreaLocation, BlockAddress, Superblock},
};

const DEVICE_BYTES: u64 = 64 << 20;
const MATRIX_DEVICE_BYTES: u64 = 128 << 20;
const MATRIX_BLOCK_SIZES: [u64; 5] = [4096, 8192, 16384, 32768, 65536];
const OBJECT_MAP_BLOCKS: u64 = 1;
const PREFIX: &str = "APFS native geometry";

#[test]
fn report_retained_native_geometry_and_mapping_extents() {
	let checkpoints = [
		(0, include_bytes!("fixtures/native-block-0.bin")),
		(2, include_bytes!("fixtures/native-block-2.bin")),
		(4, include_bytes!("fixtures/native-block-4.bin")),
	];
	println!();
	for (address, bytes) in checkpoints {
		report_superblock(address, bytes, DEVICE_BYTES, false);
	}

	let maps = [
		(
			1,
			include_bytes!("fixtures/native-block-1.bin"),
			checkpoints[1].1,
		),
		(
			3,
			include_bytes!("fixtures/native-block-3.bin"),
			checkpoints[2].1,
		),
	];
	for (address, bytes, checkpoint) in maps {
		let geometry = Superblock::decode(checkpoint, DEVICE_BYTES)
			.unwrap()
			.geometry;
		let map = Map::decode(bytes, geometry).unwrap();
		report_header(address, map.header());
		println!(
			"{PREFIX} map {address} {} {} {}",
			map.header().transaction.0,
			u8::from(map.is_last()),
			map.mappings().len()
		);
		for (index, mapping) in map.mappings().enumerate() {
			let blocks = mapping.size_bytes / geometry.block_bytes();
			let bytes = geometry
				.byte_range(mapping.physical, u64::from(blocks))
				.unwrap();
			println!(
				"{PREFIX} mapping {address} {index} {} {} {} {} {} {} {} {}",
				mapping.object_type,
				mapping.subtype,
				mapping.size_bytes,
				mapping.volume.map_or(0, |volume| volume.0),
				mapping.id.0,
				mapping.physical.0,
				bytes.start,
				bytes.end,
			);
		}
	}
}

// The runner supplies fixture paths in the workspace. Published format tests
// do not depend on another package's fixture data.
#[test]
#[ignore = "run with check-native-geometry.sh --size-matrix"]
fn report_retained_native_block_size_matrix() {
	let fixtures = PathBuf::from(env::var_os("APFS_NATIVE_GEOMETRY_FIXTURES").unwrap());
	println!();
	for block_bytes in MATRIX_BLOCK_SIZES {
		let bytes =
			fs::read(fixtures.join(format!("native-block-zero-{block_bytes}.bin"))).unwrap();
		report_superblock(block_bytes, &bytes, MATRIX_DEVICE_BYTES, true);
	}
}

fn report_superblock(
	address: u64,
	bytes: &[u8],
	source_bytes: u64,
	report_object_map_extent: bool,
) {
	let superblock = Superblock::decode(bytes, source_bytes).unwrap();
	let (header, profile) = Superblock::verified_profile(bytes).unwrap();
	assert_eq!(header, superblock.object);
	assert_eq!(profile.incompatible, superblock.incompatible);
	report_header(address, header);
	println!(
		"{PREFIX} profile {address} {} {} {} {} {}",
		superblock.features,
		superblock.read_only_compatible,
		profile.incompatible,
		u8::from(profile.has_keylocker),
		u8::from(profile.fragmented_checkpoint_area),
	);
	let geometry = superblock.geometry;
	let blocks = geometry.block_count();
	let extent = geometry.byte_range(BlockAddress(0), blocks).unwrap();
	let locator = if report_object_map_extent {
		let span = geometry
			.byte_range(superblock.object_map, OBJECT_MAP_BLOCKS)
			.unwrap();
		format!(" {} {}", span.start, span.end)
	} else {
		String::new()
	};
	println!(
		"{PREFIX} nxsb {address} {} {} {blocks} {} {} {}{locator}",
		superblock.object.transaction.0,
		geometry.block_bytes(),
		extent.end,
		superblock.object_map.0,
		superblock.incompatible,
	);
	for (name, area) in [
		("descriptor", superblock.descriptors),
		("data", superblock.data),
	] {
		let AreaLocation::Contiguous(base) = area.location else {
			panic!("the retained native fixture uses contiguous rings");
		};
		let bytes = geometry.byte_range(base, u64::from(area.blocks)).unwrap();
		println!(
			"{PREFIX} area {address} {name} {} {} {} {} {} {} {}",
			base.0, area.blocks, area.index, area.length, area.next, bytes.start, bytes.end,
		);
	}
}

fn report_header(address: u64, header: Header) {
	println!(
		"{PREFIX} header {address} {:016x} {} {} {} {}",
		header.checksum, header.id.0, header.transaction.0, header.object_type, header.subtype,
	);
}
