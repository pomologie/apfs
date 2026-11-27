use apfs_format::{
	Error,
	checkpoint::Map,
	object::{HEADER_BYTES, checksum},
	superblock::{BlockAddress, Geometry, Superblock},
};

const BOOTSTRAP: &[u8] = include_bytes!("fixtures/native-block-0.bin");
const NATIVE_MAP: &[u8] = include_bytes!("fixtures/native-block-3.bin");
const CONTAINER_BYTES: u64 = 64 << 20;
const WORD_BYTES: usize = size_of::<u32>();
const CHECKSUM_BYTES: usize = size_of::<u64>();
const SUBTYPE_OFFSET: usize = HEADER_BYTES - WORD_BYTES;
const FLAGS_OFFSET: usize = HEADER_BYTES;
const FIRST_MAPPING: usize = FLAGS_OFFSET + 2 * WORD_BYTES;
const MAPPING_SIZE: usize = FIRST_MAPPING + 2 * WORD_BYTES;
const MAPPING_VOLUME: usize = FIRST_MAPPING + 4 * WORD_BYTES;
const MAPPING_ID: usize = MAPPING_VOLUME + size_of::<u64>();
const MAPPING_ADDRESS: usize = MAPPING_ID + size_of::<u64>();

#[test]
fn verifies_volume_scoped_and_final_block_mappings() {
	let bootstrap = Superblock::decode(BOOTSTRAP, CONTAINER_BYTES).unwrap();
	let geometry = bootstrap.geometry;
	let volume = bootstrap.volume_ids().next().unwrap();
	let control = Map::decode(NATIVE_MAP, geometry).unwrap();
	let original = control.mappings().next().unwrap();
	assert_eq!(original.volume, None);
	let mut bytes = NATIVE_MAP.to_vec();
	let last = geometry.block_count() - 1;
	write(&mut bytes, MAPPING_VOLUME, volume.0.to_le_bytes());
	write(&mut bytes, MAPPING_ADDRESS, last.to_le_bytes());
	write(
		&mut bytes,
		MAPPING_SIZE,
		geometry.block_bytes().to_le_bytes(),
	);
	seal(&mut bytes);

	let map = Map::decode(&bytes, geometry).unwrap();
	assert_eq!(map.mappings().len(), control.mappings().len());
	let mapping = map.mappings().next().unwrap();
	assert_eq!(mapping.id, original.id);
	assert_eq!(mapping.volume, Some(volume));
	assert_eq!(mapping.physical, BlockAddress(last));
	assert_eq!(
		geometry.byte_range(mapping.physical, 1).unwrap().end,
		CONTAINER_BYTES
	);
}

#[test]
fn rejects_inconsistent_checkpoint_map_requests() {
	const UNSUPPORTED_FLAGS: u32 = 1 << 31;
	const UNEXPECTED_SUBTYPE: u32 = 1;
	let geometry = Superblock::decode(BOOTSTRAP, CONTAINER_BYTES)
		.unwrap()
		.geometry;
	assert_rejected(
		geometry,
		SUBTYPE_OFFSET,
		UNEXPECTED_SUBTYPE.to_le_bytes(),
		Error::UnexpectedObjectType(Map::OBJECT_TYPE),
	);
	assert_rejected(
		geometry,
		FLAGS_OFFSET,
		UNSUPPORTED_FLAGS.to_le_bytes(),
		Error::UnsupportedCheckpointFlags(UNSUPPORTED_FLAGS),
	);
	for offset in [MAPPING_ID, MAPPING_ADDRESS] {
		assert_rejected(
			geometry,
			offset,
			0u64.to_le_bytes(),
			Error::InvalidCheckpoint,
		);
	}
	for size in [0, geometry.block_bytes() + 1] {
		assert_rejected(
			geometry,
			MAPPING_SIZE,
			size.to_le_bytes(),
			Error::InvalidCheckpoint,
		);
	}
	assert_rejected(
		geometry,
		MAPPING_ADDRESS,
		geometry.block_count().to_le_bytes(),
		Error::InvalidCheckpoint,
	);
}

fn assert_rejected<const N: usize>(
	geometry: Geometry,
	offset: usize,
	field: [u8; N],
	expected: Error,
) {
	let mut bytes = NATIVE_MAP.to_vec();
	write(&mut bytes, offset, field);
	seal(&mut bytes);
	assert_eq!(Map::decode(&bytes, geometry).unwrap_err(), expected);
}

fn write<const N: usize>(bytes: &mut [u8], offset: usize, field: [u8; N]) {
	bytes[offset..offset + N].copy_from_slice(&field);
}

fn seal(bytes: &mut [u8]) {
	let stored = checksum(bytes).unwrap().to_le_bytes();
	bytes[..CHECKSUM_BYTES].copy_from_slice(&stored);
}
