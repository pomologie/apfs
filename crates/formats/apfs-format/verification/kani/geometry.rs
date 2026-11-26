use super::{
	Area, AreaLocation, BlockAddress, DATA_AREA_OFFSETS, DESCRIPTOR_AREA_OFFSETS, Geometry,
	admit_block_bytes,
};
use crate::Error;

const MIN_CONTAINER_BYTES: u128 = 1 << 20;
const SMALLEST_BLOCK_SHIFT: u32 = 12;
const LARGEST_BLOCK_SHIFT: u32 = 16;

#[kani::proof]
fn nxsb_block_size_matches_profile() {
	let bytes = kani::any::<u32>();
	let shift = bytes.trailing_zeros();
	let allowed =
		(SMALLEST_BLOCK_SHIFT..=LARGEST_BLOCK_SHIFT).contains(&shift) && bytes == 1_u32 << shift;
	assert!(admit_block_bytes(bytes).is_ok() == allowed);
	kani::cover!(allowed, "an allowed block size is accepted");
	kani::cover!(!allowed, "a disallowed block size is rejected");
}

#[kani::proof]
fn nxsb_geometry_matches_widened_model() {
	match kani::any::<u8>() {
		0 => check_geometry::<12>(),
		1 => check_geometry::<13>(),
		2 => check_geometry::<14>(),
		3 => check_geometry::<15>(),
		_ => check_geometry::<16>(),
	}
}

fn check_geometry<const SHIFT: u32>() {
	let block_count = kani::any::<u64>();
	let device_bytes = kani::any::<u64>();
	let start = kani::any::<u64>();
	let blocks = kani::any::<u64>();

	// The model uses wider arithmetic, so invalid on-disk values cannot wrap.
	let container_bytes = u128::from(block_count) << SHIFT;
	let admitted = (MIN_CONTAINER_BYTES..=u128::from(device_bytes)).contains(&container_bytes);
	let geometry = Geometry::new(1_u32 << SHIFT, block_count, device_bytes);
	assert!(geometry.is_ok() == admitted);
	kani::cover!(admitted, "container geometry is admitted");
	kani::cover!(
		container_bytes > u128::from(u64::MAX),
		"container size overflows u64"
	);
	kani::cover!(
		container_bytes < MIN_CONTAINER_BYTES,
		"container size is below the minimum"
	);
	let Ok(geometry) = geometry else {
		return;
	};

	let end = u128::from(start) + u128::from(blocks);
	let range = geometry.byte_range(BlockAddress(start), blocks);
	assert!(range.is_ok() == (end <= u128::from(block_count)));
	if let Ok(range) = range {
		assert!(u128::from(range.start) == u128::from(start) << SHIFT);
		assert!(u128::from(range.end) == end << SHIFT);
		assert!(range.end <= device_bytes);
	}
	kani::cover!(
		end == u128::from(block_count) && blocks > 0,
		"range reaches the end of the container"
	);
	kani::cover!(
		start == block_count && blocks == 0,
		"empty range at the end of the container"
	);
	kani::cover!(end > u128::from(u64::MAX), "block endpoint overflows u64");
}

#[kani::proof]
fn nxsb_checkpoint_area_matches_wire_bounds() {
	const BLOCK_BYTES: u32 = 4096;
	const LAST_AREA_FIELD_END: usize = 152;
	const TREE_FLAG: u32 = 1 << 31;
	let container_blocks = kani::any::<u64>();
	let Ok(geometry) = Geometry::new(BLOCK_BYTES, container_blocks, u64::MAX) else {
		return;
	};
	let stored_count = kani::any::<u32>();
	let base = kani::any::<u64>();
	let next = kani::any::<u32>();
	let index = kani::any::<u32>();
	let length = kani::any::<u32>();
	let descriptor = kani::any::<bool>();

	// The oracle encodes the fields at the wire positions in nx_superblock_t.
	let (count_offset, base_offset, next_offset, index_offset, length_offset, offsets) =
		if descriptor {
			(104, 112, 128, 136, 140, DESCRIPTOR_AREA_OFFSETS)
		} else {
			(108, 120, 132, 144, 148, DATA_AREA_OFFSETS)
		};
	let mut bytes = [0_u8; LAST_AREA_FIELD_END];
	bytes[count_offset..][..4].copy_from_slice(&stored_count.to_le_bytes());
	bytes[base_offset..][..8].copy_from_slice(&base.to_le_bytes());
	bytes[next_offset..][..4].copy_from_slice(&next.to_le_bytes());
	bytes[index_offset..][..4].copy_from_slice(&index.to_le_bytes());
	bytes[length_offset..][..4].copy_from_slice(&length.to_le_bytes());

	let tree = stored_count >= TREE_FLAG;
	let blocks = stored_count % TREE_FLAG;
	let physical_blocks = if tree { 1 } else { blocks };
	let end = u128::from(base) + u128::from(physical_blocks);
	let expected = if blocks != 0 && base != 0 && end <= u128::from(container_blocks) {
		let address = BlockAddress(base);
		let location = if tree {
			AreaLocation::FragmentTree(address)
		} else {
			AreaLocation::Contiguous(address)
		};
		Ok(Area {
			location,
			blocks,
			index,
			length,
			next,
		})
	} else {
		Err(Error::InvalidCheckpoint)
	};
	assert!(Area::decode(&bytes, geometry, offsets) == expected);
	kani::cover!(
		descriptor && expected.is_ok(),
		"descriptor area is admitted"
	);
	kani::cover!(!descriptor && expected.is_ok(), "data area is admitted");
	kani::cover!(
		tree && expected.is_ok(),
		"bounded fragment locator is decoded"
	);
	kani::cover!(
		!tree && expected.is_ok() && end == u128::from(container_blocks),
		"contiguous area reaches the container boundary"
	);
	kani::cover!(base == 0, "missing base is rejected");
	kani::cover!(blocks == 0, "zero block count is rejected");
	kani::cover!(
		blocks != 0 && base != 0 && end > u128::from(u64::MAX),
		"overflowing physical range is rejected"
	);
}
