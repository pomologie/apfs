use apfs_container::{Container, OpenOptions};
use apfs_format::{
	object::{Header, ObjectId, TransactionId},
	superblock::{AreaLocation, BlockAddress},
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
}

#[test]
fn native_selection_agrees_with_apples_checker_across_descriptor_slot_reuse() {
	// The fixture ledgers record Apple's checker selecting XID 4 in the base
	// image and XID 6 after a native read-write attach and file creation.
	let snapshots = [
		Snapshot {
			name: "sonoma-payload-blocks",
			bytes: include_bytes!("../fixtures/sonoma-payload-blocks.bin"),
			selected_xid: TransactionId(4),
			descriptor: BlockAddress(8),
			descriptor_xids: [1, 2, 3, 4],
			live_slots: [6, 7],
			next_slot: 0,
			first_data_block: 19,
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
		},
	];

	println!();
	for sample in snapshots {
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
