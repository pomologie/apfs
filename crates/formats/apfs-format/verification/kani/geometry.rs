use super::{BlockAddress, Geometry, admit_block_bytes};

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
