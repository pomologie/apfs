use apfs_format::{
	checkpoint::Map,
	superblock::{AreaLocation, BlockAddress, Superblock},
};

const DEVICE_BYTES: u64 = 64 << 20;
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
		let superblock = Superblock::decode(bytes, DEVICE_BYTES).unwrap();
		let geometry = superblock.geometry;
		let blocks = geometry.block_count();
		let extent = geometry.byte_range(BlockAddress(0), blocks).unwrap();
		println!(
			"{PREFIX} nxsb {address} {} {} {blocks} {} {} {}",
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
