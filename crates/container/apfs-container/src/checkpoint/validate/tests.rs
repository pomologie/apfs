use super::{
	AreaLocation, BlockAddress, Corruption, Map, Mapping, Rings, Superblock, Vec, same_layout,
	valid_live_ring, validate_mappings,
};

const DEVICE_BYTES: u64 = 64 << 20;
const BOOTSTRAP: &[u8] = include_bytes!("../../../tests/fixtures/native-block-0.bin");
const EARLY: &[u8] = include_bytes!("../../../tests/fixtures/native-block-2.bin");
const LATEST: &[u8] = include_bytes!("../../../tests/fixtures/native-block-4.bin");
const LATEST_MAP: &[u8] = include_bytes!("../../../tests/fixtures/native-block-3.bin");

#[test]
fn layout_identity_accepts_cursor_changes_and_rejects_different_ring_identity() {
	let bootstrap = Superblock::decode(BOOTSTRAP, DEVICE_BYTES).unwrap();
	let early = Superblock::decode(EARLY, DEVICE_BYTES).unwrap();
	let latest = Superblock::decode(LATEST, DEVICE_BYTES).unwrap();
	assert_ne!(early.descriptors.index, latest.descriptors.index);
	assert_ne!(early.data.index, latest.data.index);
	assert!(same_layout(&bootstrap, &early));
	assert!(same_layout(&bootstrap, &latest));

	let mut foreign = latest.clone();
	foreign.uuid[0] ^= 1;
	let mut descriptor_location = latest.clone();
	descriptor_location.descriptors.location = AreaLocation::Contiguous(BlockAddress(2));
	let mut descriptor_capacity = latest.clone();
	descriptor_capacity.descriptors.blocks -= 1;
	let mut data_location = latest.clone();
	data_location.data.location = AreaLocation::Contiguous(BlockAddress(10));
	let mut data_capacity = latest;
	data_capacity.data.blocks -= 1;
	for checkpoint in [
		foreign,
		descriptor_location,
		descriptor_capacity,
		data_location,
		data_capacity,
	] {
		assert!(!same_layout(&bootstrap, &checkpoint), "{checkpoint:?}");
	}
}

#[test]
fn live_descriptor_ring_matches_a_slot_by_slot_walk() {
	let native = Superblock::decode(LATEST, DEVICE_BYTES)
		.unwrap()
		.descriptors;
	assert!(valid_live_ring(native));
	let slots = native.blocks;
	for index in 0..=slots {
		for length in 0..=slots + 1 {
			for next in 0..=slots {
				let mut area = native;
				area.index = index;
				area.length = length;
				area.next = next;
				let after_live_span = (index < slots && (1..=slots).contains(&length))
					.then(|| (0..slots).cycle().nth((index + length) as usize).unwrap());
				assert_eq!(
					valid_live_ring(area),
					after_live_span == Some(next),
					"{area:?}"
				);
			}
		}
	}
}

#[test]
fn mappings_cover_native_and_wrapped_live_spans_with_reversed_input_order() {
	let (mut checkpoint, rings, native) = native_mappings();
	let mut mappings = native;
	mappings.reverse();
	assert_eq!(
		validate_mappings(&mut mappings, &checkpoint, &rings),
		Ok(())
	);
	assert!(mappings.windows(2).all(|pair| pair[0].id < pair[1].id));
	let sorted_ids: Vec<_> = mappings.iter().map(|mapping| mapping.id).collect();

	let unwrapped_start = rings.data.0 + u64::from(checkpoint.data.index);
	checkpoint.data.index = checkpoint.data.blocks - 1;
	checkpoint.data.next = checkpoint.data.length - 1;
	assert!(valid_live_ring(checkpoint.data));
	for mapping in &mut mappings {
		let relative = mapping.physical.0 - unwrapped_start;
		mapping.physical = BlockAddress(if relative == 0 {
			rings.data.0 + u64::from(checkpoint.data.blocks) - 1
		} else {
			rings.data.0 + relative - 1
		});
	}
	mappings.reverse();
	assert_eq!(
		validate_mappings(&mut mappings, &checkpoint, &rings),
		Ok(())
	);
	assert!(mappings.iter().map(|mapping| mapping.id).eq(sorted_ids));
}

#[test]
fn mappings_reject_ranges_outside_the_ring_or_noncontiguous_live_coverage() {
	let (checkpoint, rings, native) = native_mappings();
	let last = native.len() - 1;
	let mut before_ring = native.clone();
	before_ring[0].physical = BlockAddress(rings.data.0 - 1);
	let mut after_ring = native.clone();
	after_ring[0].physical = BlockAddress(rings.data.0 + u64::from(checkpoint.data.blocks));
	let mut gap = native.clone();
	gap.remove(1);
	let mut overlap = native.clone();
	overlap[1].physical = overlap[0].physical;
	let mut past_live = native.clone();
	past_live[last].size_bytes += checkpoint.geometry.block_bytes();
	let mut short = native;
	short.pop();
	for mut mappings in [before_ring, after_ring, gap, overlap, past_live, short] {
		assert_eq!(
			validate_mappings(&mut mappings, &checkpoint, &rings),
			Err(Corruption::Ring)
		);
	}
}

#[test]
fn complete_ranges_require_unique_ids_and_global_space_manager_and_reaper_mappings() {
	let (checkpoint, rings, native) = native_mappings();
	let mut duplicate = native.clone();
	duplicate[1].id = duplicate[0].id;
	assert_eq!(
		validate_mappings(&mut duplicate, &checkpoint, &rings),
		Err(Corruption::Object)
	);
	let volume = checkpoint.volume_ids().next().unwrap();
	for (root, other) in [
		(checkpoint.spaceman, checkpoint.reaper),
		(checkpoint.reaper, checkpoint.spaceman),
	] {
		let position = native
			.iter()
			.position(|mapping| mapping.id == root)
			.unwrap();
		let other_type = native
			.iter()
			.find(|mapping| mapping.id == other)
			.unwrap()
			.object_type;
		let mut missing = native.clone();
		missing[position].id = checkpoint.next_object;
		let mut type_mismatch = native.clone();
		type_mismatch[position].object_type = other_type;
		let mut subtype_mismatch = native.clone();
		subtype_mismatch[position].subtype = 1;
		let mut scoped = native.clone();
		scoped[position].volume = Some(volume);
		for mut mappings in [missing, type_mismatch, subtype_mismatch, scoped] {
			assert_eq!(
				validate_mappings(&mut mappings, &checkpoint, &rings),
				Err(Corruption::Object)
			);
		}
	}
}

fn native_mappings() -> (Superblock, Rings, Vec<Mapping>) {
	let checkpoint = Superblock::decode(LATEST, DEVICE_BYTES).unwrap();
	let rings = Rings::from_bootstrap(&checkpoint).unwrap();
	let mut mappings: Vec<_> = Map::decode(LATEST_MAP, checkpoint.geometry)
		.unwrap()
		.mappings()
		.collect();
	mappings.sort_unstable_by_key(|mapping| mapping.physical);
	(checkpoint, rings, mappings)
}
