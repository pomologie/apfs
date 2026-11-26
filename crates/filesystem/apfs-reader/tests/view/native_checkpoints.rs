use std::cell::RefCell;

use apfs_container::{Container, Error, Limit, OpenOptions};
use apfs_core::{ByteOffset, ReadAt};
use apfs_format::{
	object::{Header, ObjectId, TransactionId},
	superblock::{AreaLocation, BLOCK_SIZE_PREFIX_BYTES, BlockAddress},
};

use super::{BLOCK_BYTES, Fixture};

const RING_START: BlockAddress = BlockAddress(1);
const RING_BLOCKS: u32 = 8;
const DESCRIPTOR_BLOCKS: [u64; 4] = [2, 4, 6, 8];
const MAPPED_OBJECTS: [u64; 4] = [1024, 1025, 1027, 1029];

struct Snapshot {
	name: &'static str,
	bytes: &'static [u8],
	selected_xid: TransactionId,
	descriptor: BlockAddress,
	descriptor_xids: [u64; 4],
	live_slots: [u32; 2],
	next_slot: u32,
	first_data_block: u64,
	object_map: BlockAddress,
}

// The fixture ledgers record Apple's checker selecting XID 4 in the base
// image and XID 6 after a native read-write attach and file creation.
const SNAPSHOTS: [Snapshot; 2] = [
	Snapshot {
		name: "sonoma-payload-blocks",
		bytes: include_bytes!("../fixtures/sonoma-payload-blocks.bin"),
		selected_xid: TransactionId(4),
		descriptor: BlockAddress(8),
		descriptor_xids: [1, 2, 3, 4],
		live_slots: [6, 7],
		next_slot: 0,
		first_data_block: 19,
		object_map: BlockAddress(414),
	},
	Snapshot {
		name: "sonoma-fragmented-blocks",
		bytes: include_bytes!("../fixtures/sonoma-fragmented-blocks.bin"),
		selected_xid: TransactionId(6),
		descriptor: BlockAddress(4),
		descriptor_xids: [5, 6, 3, 4],
		live_slots: [2, 3],
		next_slot: 4,
		first_data_block: 27,
		object_map: BlockAddress(689),
	},
];

#[test]
fn native_selection_agrees_with_apples_checker_across_descriptor_slot_reuse() {
	println!();
	for sample in SNAPSHOTS {
		let fixture = Fixture::from_packed_blocks(sample.bytes);
		let descriptor_xids = DESCRIPTOR_BLOCKS
			.map(|address| Header::decode(&fixture.0[&address]).unwrap().transaction.0);
		assert_eq!(descriptor_xids, sample.descriptor_xids);

		let options = OpenOptions::default();
		let automatic = Container::open(&fixture, options).unwrap();
		let exact = Container::open_at(&fixture, options, sample.selected_xid).unwrap();
		assert_eq!(
			automatic.superblock().object.transaction,
			sample.selected_xid
		);
		assert_eq!(automatic.descriptor(), sample.descriptor);
		assert_eq!(automatic.descriptor(), exact.descriptor());
		assert_eq!(automatic.superblock(), exact.superblock());
		assert_eq!(automatic.mappings(), exact.mappings());
		assert!(automatic.diagnostics().is_empty());
		assert!(exact.diagnostics().is_empty());

		let ring = automatic.superblock().descriptors;
		assert_eq!(ring.location, AreaLocation::Contiguous(RING_START));
		assert_eq!(ring.blocks, RING_BLOCKS);
		assert_eq!(ring.length, sample.live_slots.len() as u32);
		assert_eq!(ring.next, sample.next_slot);
		let live_slots = [ring.ring_index(0).unwrap(), ring.ring_index(1).unwrap()];
		assert_eq!(live_slots, sample.live_slots);

		let mappings = automatic.mappings();
		assert_eq!(mappings.len(), MAPPED_OBJECTS.len());
		for (index, (mapping, id)) in mappings.iter().zip(MAPPED_OBJECTS).enumerate() {
			assert_eq!(mapping.id, ObjectId(id));
			assert_eq!(
				mapping.physical,
				BlockAddress(sample.first_data_block + index as u64)
			);
			assert_eq!(mapping.size_bytes, BLOCK_BYTES as u32);
		}
		let payload_blocks: Vec<_> = mappings.iter().map(|mapping| mapping.physical.0).collect();
		println!(
			"APFS native checkpoints replay {} {} {} {} {} {live_slots:?} {descriptor_xids:?} {payload_blocks:?}",
			sample.name,
			automatic.superblock().object.transaction.0,
			automatic.descriptor().0,
			ring.blocks,
			ring.next,
		);
	}
}

#[test]
fn native_selection_admits_the_exact_budget_and_stops_before_each_unfunded_read() {
	for sample in SNAPSHOTS {
		let fixture = Fixture::from_packed_blocks(sample.bytes);
		let source = RecordingFixture {
			fixture: &fixture,
			reads: RefCell::new(Vec::new()),
		};
		let block_read = |block| (ByteOffset(block * BLOCK_BYTES as u64), BLOCK_BYTES);
		let ring_start = RING_START.0;
		let map = ring_start + u64::from(sample.live_slots[0]);
		let data = sample.first_data_block..sample.first_data_block + MAPPED_OBJECTS.len() as u64;
		let expected: Vec<_> = std::iter::once((ByteOffset(0), BLOCK_SIZE_PREFIX_BYTES))
			.chain(
				std::iter::once(0)
					.chain(ring_start..ring_start + u64::from(RING_BLOCKS))
					.chain([sample.descriptor.0, map])
					.chain(data)
					.chain([sample.object_map.0])
					.map(block_read),
			)
			.collect();
		for transaction in [None, Some(sample.selected_xid)] {
			let open = |max_read_bytes| {
				let options = OpenOptions {
					max_read_bytes,
					..OpenOptions::default()
				};
				match transaction {
					Some(xid) => Container::open_at(&source, options, xid),
					None => Container::open(&source, options),
				}
			};
			let mut required = 0;
			for (index, &(_, bytes)) in expected.iter().enumerate() {
				required += bytes as u64;
				assert!(matches!(
					open(required - 1),
					Err(Error::Limit(Limit::ReadBytes))
				));
				assert_eq!(
					*source.reads.borrow(),
					expected[..index],
					"{} {transaction:?}",
					sample.name
				);
				source.reads.borrow_mut().clear();
			}
			let selected = open(required).unwrap();
			assert_eq!(
				selected.superblock().object.transaction,
				sample.selected_xid
			);
			assert_eq!(*source.reads.borrow(), expected);
			source.reads.borrow_mut().clear();
		}
	}
}

struct RecordingFixture<'fixture> {
	fixture: &'fixture Fixture,
	reads: RefCell<Vec<(ByteOffset, usize)>>,
}

impl ReadAt for RecordingFixture<'_> {
	type Error = u64;

	fn len(&self) -> u64 {
		self.fixture.len()
	}

	fn read_exact_at(&self, offset: ByteOffset, output: &mut [u8]) -> Result<(), Self::Error> {
		self.reads.borrow_mut().push((offset, output.len()));
		self.fixture.read_exact_at(offset, output)
	}
}
