use core::{cell::RefCell, cmp::Ordering};

use apfs_core::{ByteOffset, ReadAt};

use super::{
	AreaLocation, BlockAddress, Candidate, Corruption, Discovery, Error, Header, Map, Mapping,
	Rings, Superblock, Vec, same_layout, valid_live_ring, validate_mappings,
};
use crate::probe::Probe;

mod payload_validation;

const DEVICE_BYTES: u64 = 64 << 20;
const LARGER_DEVICE_BYTES: u64 = 128 << 20;
const BLOCK_BYTES: usize = 4096;
const BOOTSTRAP: &[u8] = include_bytes!("../../../tests/fixtures/native-block-0.bin");
const LARGER_BOOTSTRAP: &[u8] = include_bytes!("../../../tests/fixtures/sonoma-128m-bootstrap.bin");
const EARLY: &[u8] = include_bytes!("../../../tests/fixtures/native-block-2.bin");
const LATEST: &[u8] = include_bytes!("../../../tests/fixtures/native-block-4.bin");
const LATEST_MAP: &[u8] = include_bytes!("../../../tests/fixtures/native-block-3.bin");
const EARLY_MAP: &[u8] = include_bytes!("../../../tests/fixtures/native-block-1.bin");
const EARLY_DESCRIPTOR: BlockAddress = BlockAddress(2);
const LATEST_DESCRIPTOR: BlockAddress = BlockAddress(4);
const EARLY_OBJECT_MAP: BlockAddress = BlockAddress(191);
const LATEST_OBJECT_MAP: BlockAddress = BlockAddress(199);

macro_rules! native_block {
	($address:literal) => {
		(
			BlockAddress($address),
			include_bytes!(concat!(
				"../../../tests/fixtures/native-block-",
				stringify!($address),
				".bin"
			)),
		)
	};
}

const NATIVE_BLOCKS: &[(BlockAddress, &[u8; BLOCK_BYTES])] = &[
	native_block!(4),
	native_block!(9),
	native_block!(10),
	native_block!(11),
	native_block!(12),
	native_block!(13),
	native_block!(14),
	native_block!(191),
	native_block!(199),
];

#[test]
fn candidate_with_different_geometry_stops_after_its_descriptor() {
	let mut bootstrap = Superblock::decode(BOOTSTRAP, DEVICE_BYTES).unwrap();
	bootstrap.geometry = Superblock::decode(LARGER_BOOTSTRAP, LARGER_DEVICE_BYTES)
		.unwrap()
		.geometry;
	let checkpoint = Superblock::decode(LATEST, LARGER_DEVICE_BYTES).unwrap();
	assert_eq!(
		checkpoint.geometry.block_bytes(),
		bootstrap.geometry.block_bytes()
	);
	assert_ne!(
		checkpoint.geometry.block_count(),
		bootstrap.geometry.block_count()
	);
	let source = NativeBlocks::new(LARGER_DEVICE_BYTES);
	let rings = Rings::from_bootstrap(&bootstrap).unwrap();
	let candidate = Candidate {
		address: LATEST_DESCRIPTOR,
		xid: checkpoint.object.transaction,
	};

	let result = source
		.discovery(1)
		.read_candidate(&bootstrap, &rings, candidate, &mut Vec::new());
	assert!(matches!(
		result,
		Err(Error::CandidateCorruption(damage))
			if damage.descriptor == candidate.address
				&& damage.transaction == Some(candidate.xid)
				&& damage.reason == Corruption::Identity
	));
	assert_eq!(*source.reads.borrow(), [LATEST_DESCRIPTOR]);
}

#[test]
fn physical_checkpoint_object_map_can_be_reused_but_must_not_be_newer() {
	let early = Superblock::decode(EARLY, DEVICE_BYTES).unwrap();
	let mut early_mappings: Vec<_> = Map::decode(EARLY_MAP, early.geometry)
		.unwrap()
		.mappings()
		.collect();
	early_mappings.sort_unstable_by_key(|mapping| mapping.physical);
	let (latest, _, latest_mappings) = native_mappings();
	let cases = [
		(
			&latest,
			LATEST_DESCRIPTOR,
			latest_mappings.as_slice(),
			EARLY_OBJECT_MAP,
			Ordering::Less,
		),
		(
			&latest,
			LATEST_DESCRIPTOR,
			latest_mappings.as_slice(),
			LATEST_OBJECT_MAP,
			Ordering::Equal,
		),
		(
			&early,
			EARLY_DESCRIPTOR,
			early_mappings.as_slice(),
			LATEST_OBJECT_MAP,
			Ordering::Greater,
		),
	];

	for (descriptor, address, mappings, object_map, age) in cases {
		let mut checkpoint = descriptor.clone();
		checkpoint.object_map = object_map;
		let candidate = Candidate {
			address,
			xid: checkpoint.object.transaction,
		};
		assert_eq!(
			Header::decode(NativeBlocks::block(object_map).unwrap())
				.unwrap()
				.transaction
				.cmp(&candidate.xid),
			age
		);
		let source = NativeBlocks::new(DEVICE_BYTES);
		let rings = Rings::from_bootstrap(&checkpoint).unwrap();
		let result = source.discovery(mappings.len() + 1).validate_payloads(
			mappings,
			&checkpoint,
			&rings,
			candidate,
			&mut Vec::new(),
		);
		if age == Ordering::Greater {
			assert!(matches!(
				result,
				Err(Error::CandidateCorruption(damage))
					if damage.descriptor == candidate.address
						&& damage.transaction == Some(candidate.xid)
						&& damage.reason == Corruption::Object
			));
		} else {
			result.unwrap();
		}
		let expected_reads = mappings
			.iter()
			.map(|mapping| mapping.physical)
			.chain([object_map]);
		assert!(source.reads.borrow().iter().copied().eq(expected_reads));
	}
}

struct NativeBlocks {
	len: u64,
	reads: RefCell<Vec<BlockAddress>>,
}

impl NativeBlocks {
	fn new(len: u64) -> Self {
		Self {
			len,
			reads: RefCell::new(Vec::new()),
		}
	}

	fn block(address: BlockAddress) -> Option<&'static [u8; BLOCK_BYTES]> {
		NATIVE_BLOCKS
			.iter()
			.find_map(|&(block, bytes)| (block == address).then_some(bytes))
	}

	fn discovery(&self, block_budget: usize) -> Discovery<'_, Self> {
		Discovery {
			probe: Probe::new(self, BLOCK_BYTES, (block_budget * BLOCK_BYTES) as u64),
			max_mappings: NATIVE_BLOCKS.len(),
		}
	}
}

impl ReadAt for NativeBlocks {
	type Error = ByteOffset;

	fn len(&self) -> u64 {
		self.len
	}

	fn read_exact_at(&self, offset: ByteOffset, out: &mut [u8]) -> Result<(), Self::Error> {
		if !offset.0.is_multiple_of(BLOCK_BYTES as u64) || out.len() != BLOCK_BYTES {
			return Err(offset);
		}
		let address = BlockAddress(offset.0 / BLOCK_BYTES as u64);
		self.reads.borrow_mut().push(address);
		let bytes = Self::block(address).ok_or(offset)?;
		out.copy_from_slice(bytes);
		Ok(())
	}
}

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
fn contiguous_ring_ownership_matches_an_independent_slot_inventory() {
	let native = Superblock::decode(BOOTSTRAP, DEVICE_BYTES).unwrap();
	assert!(Rings::from_bootstrap(&native).is_ok());

	const FIRST_ADDRESS: u64 = 1;
	const LAST_ADDRESS: u64 = 5;
	const CAPACITIES: [u32; 3] = [1, 2, 3];
	for descriptor in FIRST_ADDRESS..=LAST_ADDRESS {
		for data in FIRST_ADDRESS..=LAST_ADDRESS {
			for descriptor_blocks in CAPACITIES {
				for data_blocks in CAPACITIES {
					let mut candidate = native.clone();
					candidate.descriptors.location =
						AreaLocation::Contiguous(BlockAddress(descriptor));
					candidate.descriptors.blocks = descriptor_blocks;
					candidate.data.location = AreaLocation::Contiguous(BlockAddress(data));
					candidate.data.blocks = data_blocks;
					let descriptor_inventory =
						descriptor..descriptor + u64::from(descriptor_blocks);
					let data_inventory = data..data + u64::from(data_blocks);
					let overlaps = descriptor_inventory
						.clone()
						.any(|slot| data_inventory.contains(&slot));
					let actual = Rings::from_bootstrap(&candidate);
					if overlaps {
						assert!(
							matches!(actual, Err(Corruption::Ring)),
							"{descriptor_inventory:?}, {data_inventory:?}"
						);
					} else {
						let rings = actual.unwrap();
						assert_eq!((rings.descriptor.0, rings.data.0), (descriptor, data));
					}
				}
			}
		}
	}
}

#[test]
fn multi_block_mapping_admission_matches_exact_slot_ownership() {
	const SLOTS: usize = 5;
	const MAX_MAPPING_BLOCKS: usize = 3;
	let mut checkpoint = Superblock::decode(EARLY, DEVICE_BYTES).unwrap();
	let rings = Rings::from_bootstrap(&checkpoint).unwrap();
	let native: [Mapping; 2] = Map::decode(EARLY_MAP, checkpoint.geometry)
		.unwrap()
		.mappings()
		.collect::<Vec<_>>()
		.try_into()
		.unwrap();
	let block_bytes = checkpoint.geometry.block_bytes();
	checkpoint.data.blocks = SLOTS as u32;
	let spans = || {
		(0..SLOTS)
			.flat_map(|start| (1..=MAX_MAPPING_BLOCKS).map(move |length| start..start + length))
	};
	for start in 0..SLOTS {
		checkpoint.data.index = start as u32;
		for length in 1..=SLOTS {
			checkpoint.data.length = length as u32;
			checkpoint.data.next = ((start + length) % SLOTS) as u32;
			let mut live = [0; SLOTS];
			for slot in (0..SLOTS).cycle().skip(start).take(length) {
				live[slot] = 1;
			}
			for first in spans() {
				for second in spans() {
					let spans = [first.clone(), second];
					let mut mappings = native;
					for (mapping, span) in mappings.iter_mut().zip(&spans) {
						mapping.physical = BlockAddress(rings.data.0 + span.start as u64);
						mapping.size_bytes = span.len() as u32 * block_bytes;
					}
					let mut owners = [0; SLOTS];
					let in_bounds = spans.iter().all(|span| {
						let Some(window) = owners.get_mut(span.clone()) else {
							return false;
						};
						for owners in window {
							*owners += 1;
						}
						true
					});
					// A full ring can have exact physical ownership while a mapping
					// still crosses the boundary between the first and last live slots.
					let crosses_live_boundary = spans
						.iter()
						.any(|span| span.start < start && span.contains(&start));
					let expected = if in_bounds && owners == live && !crosses_live_boundary {
						Ok(())
					} else {
						Err(Corruption::Ring)
					};
					assert_eq!(
						validate_mappings(&mut mappings, &checkpoint, &rings),
						expected,
						"live start={start} length={length}, physical spans={spans:?}",
					);
				}
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
