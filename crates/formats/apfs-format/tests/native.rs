use apfs_format::{
	Error,
	checkpoint::Map,
	object::{HEADER_BYTES, ObjectId, TransactionId, checksum},
	superblock::{AreaLocation, BLOCK_SIZE_PREFIX_BYTES, BlockAddress, Superblock},
};

const DEVICE_SIZE: u64 = 64 * 1024 * 1024;
const BOOTSTRAP: &[u8] = include_bytes!("fixtures/native-block-0.bin");
const FIRST_MAP: &[u8] = include_bytes!("fixtures/native-block-1.bin");
const FIRST_CHECKPOINT: &[u8] = include_bytes!("fixtures/native-block-2.bin");
const SECOND_MAP: &[u8] = include_bytes!("fixtures/native-block-3.bin");
const SECOND_CHECKPOINT: &[u8] = include_bytes!("fixtures/native-block-4.bin");

#[test]
fn native_bootstrap_geometry_and_checksums() {
	assert_eq!(
		Superblock::block_size_hint(&BOOTSTRAP[..BLOCK_SIZE_PREFIX_BYTES]),
		Ok(4096)
	);
	let container = Superblock::decode(BOOTSTRAP, DEVICE_SIZE).unwrap();
	assert_eq!(container.geometry.block_count(), 16_384);
	assert_eq!(container.object.checksum, 0x4665_3a58_ffa4_67b1);
	assert_eq!(container.incompatible, 2);
	assert_eq!(
		container.descriptors.location,
		AreaLocation::Contiguous(BlockAddress(1))
	);
	assert_eq!(container.descriptors.blocks, 8);
	assert_eq!(
		container.data.location,
		AreaLocation::Contiguous(BlockAddress(9))
	);
	assert_eq!(container.volume_ids().collect::<Vec<_>>(), [ObjectId(1026)]);
}

#[test]
fn native_checkpoint_and_mapping_objects_agree() {
	for (xid, descriptor_index, count, candidate, map) in [
		(1, 0, 2, FIRST_CHECKPOINT, FIRST_MAP),
		(2, 2, 4, SECOND_CHECKPOINT, SECOND_MAP),
	] {
		let checkpoint = Superblock::decode(candidate, DEVICE_SIZE).unwrap();
		assert_eq!(checkpoint.object.transaction, TransactionId(xid));
		assert_eq!(checkpoint.descriptors.ring_index(0), Ok(descriptor_index));
		assert_eq!(
			checkpoint.descriptors.ring_index(1),
			Ok(descriptor_index + 1)
		);
		let map = Map::decode(map, checkpoint.geometry).unwrap();
		assert_eq!(map.header().transaction, TransactionId(xid));
		assert!(map.is_last());
		assert_eq!(map.mappings().len(), count);
	}
}

#[test]
fn native_live_rings_stop_at_the_verified_span() {
	for (bytes, descriptor_slots, data_slots) in [
		(FIRST_CHECKPOINT, 0..2, 0..2),
		(SECOND_CHECKPOINT, 2..4, 2..6),
	] {
		let checkpoint = Superblock::decode(bytes, DEVICE_SIZE).unwrap();
		for (area, expected) in [
			(checkpoint.descriptors, descriptor_slots),
			(checkpoint.data, data_slots),
		] {
			assert_eq!(area.length, expected.end - expected.start);
			for (ordinal, slot) in (0..area.length).zip(expected) {
				assert_eq!(area.ring_index(ordinal), Ok(slot));
			}
			assert_eq!(area.ring_index(area.length), Err(Error::InvalidCheckpoint));
		}
	}
}

#[test]
fn typed_ring_ordinals_match_modular_distance_at_full_width() {
	let checkpoint = Superblock::decode(SECOND_CHECKPOINT, DEVICE_SIZE).unwrap();
	// Keep the decoded native layouts and vary only the typed cursor inputs.
	let areas = [checkpoint.descriptors, checkpoint.data];
	for native in areas {
		let mut saw_wide_wrap = false;
		for blocks in [1, native.blocks, i32::MAX as u32, u32::MAX] {
			for index in [0, blocks / 2, blocks - 1, blocks] {
				for next in [0, blocks - 1, blocks] {
					for length in [
						0,
						1,
						blocks / 2,
						blocks.saturating_sub(1),
						blocks,
						blocks.saturating_add(1),
					] {
						let mut area = native;
						area.blocks = blocks;
						area.index = index;
						area.next = next;
						area.length = length;
						let indices_fit = index < blocks && next < blocks;
						let length_fits = length <= blocks;
						let distance = blocks - index;
						for ordinal in [
							0,
							length.saturating_sub(1),
							length,
							u32::MAX,
							distance.saturating_sub(1),
							distance,
							distance.saturating_add(1),
						] {
							let expected = if !indices_fit || !length_fits || ordinal >= length {
								Err(Error::InvalidCheckpoint)
							} else if ordinal < distance {
								Ok(index + ordinal)
							} else {
								Ok(ordinal - distance)
							};
							assert_eq!(
								area.ring_index(ordinal),
								expected,
								"{area:?}, ordinal={ordinal}"
							);
							saw_wide_wrap |= expected.is_ok()
								&& u64::from(index) + u64::from(ordinal) > u64::from(u32::MAX);
						}
					}
				}
			}
		}
		assert!(
			saw_wide_wrap,
			"the typed matrix must exercise wrapping above u32::MAX"
		);
	}
}

#[test]
fn native_objects_require_complete_buffers_and_their_own_decoder() {
	let prefix = &BOOTSTRAP[..BLOCK_SIZE_PREFIX_BYTES];
	assert_eq!(Superblock::block_size_hint(prefix), Ok(4096));
	assert_eq!(
		Superblock::verified_profile(prefix),
		Err(Error::InvalidGeometry)
	);
	let checkpoint = Superblock::decode(BOOTSTRAP, DEVICE_SIZE).unwrap();
	let geometry = checkpoint.geometry;

	let map = Map::decode(SECOND_MAP, geometry).unwrap();
	assert_eq!(map.header().transaction, checkpoint.object.transaction);
	assert_eq!(
		Map::decode(&SECOND_MAP[..HEADER_BYTES], geometry).unwrap_err(),
		Error::InvalidGeometry
	);
	assert_eq!(
		Map::decode(BOOTSTRAP, geometry).unwrap_err(),
		Error::UnexpectedObjectType(Superblock::OBJECT_TYPE)
	);
}

#[test]
fn rejects_corruption_false_block_size_and_excessive_mapping_count() {
	let container = Superblock::decode(BOOTSTRAP, DEVICE_SIZE).unwrap();
	assert_eq!(
		Superblock::decode(BOOTSTRAP, DEVICE_SIZE - 1),
		Err(Error::InvalidGeometry)
	);
	assert_eq!(
		container.geometry.byte_range(BlockAddress(u64::MAX), 2),
		Err(Error::InvalidGeometry)
	);
	let mut broken = BOOTSTRAP.to_vec();
	broken[4095] ^= 1;
	assert_eq!(
		Superblock::decode(&broken, DEVICE_SIZE),
		Err(Error::InvalidChecksum)
	);
	broken[36..40].copy_from_slice(&1024_u32.to_le_bytes());
	assert_eq!(
		Superblock::block_size_hint(&broken),
		Err(Error::InvalidGeometry)
	);
	let mut broken = SECOND_MAP.to_vec();
	broken[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
	let crc = checksum(&broken).unwrap();
	broken[..8].copy_from_slice(&crc.to_le_bytes());
	assert!(matches!(
		Map::decode(&broken, container.geometry),
		Err(Error::InvalidCheckpoint)
	));
}
