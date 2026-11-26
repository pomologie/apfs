use apfs_container::{Container, OpenOptions};
use apfs_format::{object::TransactionId, superblock::BlockAddress};

use super::fixture::{
	BLOCK_BYTES, BOOTSTRAP, DATA_INDEX_OFFSET, DATA_NEXT_OFFSET, DESCRIPTOR_INDEX_OFFSET,
	DESCRIPTOR_NEXT_OFFSET, FIRST_MAPPING_OFFSET, Fixture, LATEST_FIRST_DATA, LATEST_MAP,
	LATEST_MAPPING_COUNT, LATEST_NXSB, MAPPING_BYTES, MAPPING_PHYSICAL_OFFSET, OBJECT_ID_OFFSET,
	XID_OFFSET,
};

const RING_SIZES: [u32; 3] = [8, 16, 32];
const CANDIDATE_COUNTS: [u32; 3] = [1, 3, 4];
const DESCRIPTOR_BASE: u64 = 512;
const DATA_BASE: u64 = 1024;
const BASE_XID: u64 = 16;
const DESCRIPTORS_PER_CANDIDATE: u32 = 2;
const PAYLOAD_BLOCKS: u32 = LATEST_MAPPING_COUNT as u32;
const DESCRIPTOR_COUNT_OFFSET: usize = 104;
const DATA_COUNT_OFFSET: usize = 108;
const DESCRIPTOR_BASE_OFFSET: usize = 112;
const DATA_BASE_OFFSET: usize = 120;

#[derive(Clone, Copy, Debug)]
enum Placement {
	Start,
	Middle,
	Wrap,
}

impl Placement {
	fn origin(self, slots: u32) -> u32 {
		match self {
			Self::Start => 0,
			Self::Middle => slots / 2,
			Self::Wrap => slots - 1,
		}
	}
}

#[derive(Clone, Copy, Debug)]
enum Order {
	Ascending,
	Descending,
}

#[derive(Clone, Copy, Debug)]
struct Layout {
	slots: u32,
	candidates: u32,
	placement: Placement,
	order: Order,
}

#[derive(Clone, Copy, Debug)]
struct PlannedCheckpoint {
	xid: TransactionId,
	map_slot: u32,
	descriptor_slot: u32,
	payload_slot: u32,
}

impl Layout {
	fn data_slots(self) -> u32 {
		self.slots * 2
	}

	fn plan(self) -> Vec<PlannedCheckpoint> {
		(0..self.candidates)
			.map(|position| {
				let xid_offset = match self.order {
					Order::Ascending => position,
					Order::Descending => self.candidates - 1 - position,
				};
				let map_slot = (self.placement.origin(self.slots)
					+ position * DESCRIPTORS_PER_CANDIDATE)
					% self.slots;
				let payload_slot = (self.placement.origin(self.data_slots())
					+ position * PAYLOAD_BLOCKS)
					% self.data_slots();
				PlannedCheckpoint {
					xid: TransactionId(BASE_XID + u64::from(xid_offset)),
					map_slot,
					descriptor_slot: (map_slot + 1) % self.slots,
					payload_slot,
				}
			})
			.collect()
	}
}

#[test]
fn opens_every_complete_checkpoint_across_valid_ring_layouts() {
	println!();
	for slots in RING_SIZES {
		for candidates in CANDIDATE_COUNTS {
			let orders: &[_] = if candidates == 1 {
				&[Order::Ascending]
			} else {
				&[Order::Ascending, Order::Descending]
			};
			for placement in [Placement::Start, Placement::Middle, Placement::Wrap] {
				for &order in orders {
					check_layout(Layout {
						slots,
						candidates,
						placement,
						order,
					});
				}
			}
		}
	}
}

fn check_layout(layout: Layout) {
	let plan = layout.plan();
	let fixture = with_layout(layout, &plan);
	let options = OpenOptions::default();
	let newest = plan.iter().max_by_key(|candidate| candidate.xid).unwrap();
	let automatic = Container::open(&fixture, options).unwrap();
	check_view(&automatic, layout, *newest);
	print_case(layout, "automatic");
	for candidate in plan {
		let view = Container::open_at(&fixture, options, candidate.xid).unwrap();
		check_view(&view, layout, candidate);
		print_case(layout, candidate.xid.0);
	}
}

fn print_case(layout: Layout, request: impl std::fmt::Display) {
	println!(
		"APFS checkpoint layout {} {} {:?} {:?} {request}",
		layout.slots, layout.candidates, layout.placement, layout.order
	);
}

fn check_view(view: &Container<&Fixture>, layout: Layout, candidate: PlannedCheckpoint) {
	assert_eq!(view.superblock().object.transaction, candidate.xid);
	assert_eq!(
		view.descriptor(),
		BlockAddress(DESCRIPTOR_BASE + u64::from(candidate.descriptor_slot))
	);
	assert_eq!(view.superblock().descriptors.blocks, layout.slots);
	assert_eq!(view.superblock().data.blocks, layout.data_slots());
	assert!(view.diagnostics().is_empty());
	let mut mapped: Vec<_> = view
		.mappings()
		.iter()
		.map(|mapping| mapping.physical.0)
		.collect();
	mapped.sort_unstable();
	let mut expected: Vec<_> = (0..PAYLOAD_BLOCKS)
		.map(|offset| {
			DATA_BASE + u64::from((candidate.payload_slot + offset) % layout.data_slots())
		})
		.collect();
	expected.sort_unstable();
	assert_eq!(mapped, expected);
}

fn with_layout(layout: Layout, plan: &[PlannedCheckpoint]) -> Fixture {
	let mut fixture = Fixture::native();
	let original_nxsb = fixture.0[&LATEST_NXSB];
	let original_map = fixture.0[&LATEST_MAP];
	for slot in 0..u64::from(layout.slots) {
		fixture.0.insert(DESCRIPTOR_BASE + slot, [0; BLOCK_BYTES]);
	}
	configure_rings(&mut fixture, BOOTSTRAP, layout);
	fixture.set_u64(BOOTSTRAP, XID_OFFSET, BASE_XID);
	for candidate in plan {
		let map = DESCRIPTOR_BASE + u64::from(candidate.map_slot);
		let descriptor = DESCRIPTOR_BASE + u64::from(candidate.descriptor_slot);
		fixture.0.insert(map, original_map);
		fixture.0.insert(descriptor, original_nxsb);
		configure_rings(&mut fixture, descriptor, layout);
		fixture.set_u64(descriptor, XID_OFFSET, candidate.xid.0);
		fixture.set_u32(descriptor, DESCRIPTOR_INDEX_OFFSET, candidate.map_slot);
		fixture.set_u32(
			descriptor,
			DESCRIPTOR_NEXT_OFFSET,
			(candidate.descriptor_slot + 1) % layout.slots,
		);
		fixture.set_u32(descriptor, DATA_INDEX_OFFSET, candidate.payload_slot);
		fixture.set_u32(
			descriptor,
			DATA_NEXT_OFFSET,
			(candidate.payload_slot + PAYLOAD_BLOCKS) % layout.data_slots(),
		);
		fixture.set_u64(map, OBJECT_ID_OFFSET, map);
		fixture.set_u64(map, XID_OFFSET, candidate.xid.0);
		for offset in 0..PAYLOAD_BLOCKS {
			let address =
				DATA_BASE + u64::from((candidate.payload_slot + offset) % layout.data_slots());
			fixture
				.0
				.insert(address, fixture.0[&(LATEST_FIRST_DATA + u64::from(offset))]);
			fixture.set_u64(address, XID_OFFSET, candidate.xid.0);
			fixture.set_u64(
				map,
				FIRST_MAPPING_OFFSET + offset as usize * MAPPING_BYTES + MAPPING_PHYSICAL_OFFSET,
				address,
			);
		}
	}
	fixture
}

fn configure_rings(fixture: &mut Fixture, address: u64, layout: Layout) {
	fixture.set_u32(address, DESCRIPTOR_COUNT_OFFSET, layout.slots);
	fixture.set_u32(address, DATA_COUNT_OFFSET, layout.data_slots());
	fixture.set_u64(address, DESCRIPTOR_BASE_OFFSET, DESCRIPTOR_BASE);
	fixture.set_u64(address, DATA_BASE_OFFSET, DATA_BASE);
}
