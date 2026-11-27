use std::collections::BTreeMap;

use apfs_container::{Container, LookupOptions, OpenOptions};
use apfs_core::{BoundsError, ByteOffset, ReadAt};
use apfs_format::{
	object::{ObjectId, TransactionId},
	superblock::{Area, AreaLocation, BlockAddress},
};

const RAW_BYTES: u64 = 1 << 30;
const BLOCK_BYTES: usize = 4096;
const ADDRESS_BYTES: usize = size_of::<u64>();
const RECORD_BYTES: usize = ADDRESS_BYTES + BLOCK_BYTES;
const DESCRIPTOR_BASE: u64 = 1;
const DESCRIPTOR_BLOCKS: u32 = 16;
const DATA_BASE: u64 = 17;
const DATA_BLOCKS: u32 = 992;
const MAPPING_IDS: [u64; 4] = [1024, 1025, 1027, 1029];

const PRIMARY: (ObjectId, &str, u128) = (
	ObjectId(1026),
	"Pomologie Primary",
	0x001c9ace_25e0_404c_b490_b3c5ee36035d,
);
const SECONDARY: (ObjectId, &str, u128) = (
	ObjectId(1030),
	"Pomologie Secondary",
	0x6a02d1cd_ddc2_4d08_b347_ad5043851dce,
);

struct ObservedStage {
	pack: &'static [u8],
	xid: u64,
	descriptor: u64,
	descriptor_slots: [u32; 2],
	data_slots: [u32; 4],
	object_map: u64,
	volumes: &'static [(ObjectId, &'static str, u128)],
}

const STAGES: [ObservedStage; 2] = [
	ObservedStage {
		pack: include_bytes!("fixtures/native-volume-growth/sonoma-1g-baseline-blocks.bin"),
		xid: 2,
		descriptor: 4,
		descriptor_slots: [2, 3],
		data_slots: [2, 3, 4, 5],
		object_map: 1060,
		volumes: &[PRIMARY],
	},
	ObservedStage {
		pack: include_bytes!("fixtures/native-volume-growth/sonoma-1g-two-volume-blocks.bin"),
		xid: 3,
		descriptor: 6,
		descriptor_slots: [4, 5],
		data_slots: [6, 7, 8, 9],
		object_map: 1068,
		volumes: &[PRIMARY, SECONDARY],
	},
];

struct Pack<'bytes>(BTreeMap<u64, &'bytes [u8]>);

impl<'bytes> Pack<'bytes> {
	fn decode(bytes: &'bytes [u8]) -> Self {
		let (records, trailing) = bytes.as_chunks::<RECORD_BYTES>();
		assert!(trailing.is_empty());
		let mut blocks = BTreeMap::new();
		for record in records {
			let (address, block) = record.split_at(ADDRESS_BYTES);
			let address = u64::from_le_bytes(address.try_into().unwrap());
			assert!(address < RAW_BYTES / BLOCK_BYTES as u64);
			assert!(
				blocks
					.last_key_value()
					.is_none_or(|(&last, _)| last < address)
			);
			blocks.insert(address, block);
		}
		Self(blocks)
	}
}

impl ReadAt for Pack<'_> {
	type Error = BoundsError;

	fn len(&self) -> u64 {
		RAW_BYTES
	}

	fn read_exact_at(&self, offset: ByteOffset, output: &mut [u8]) -> Result<(), Self::Error> {
		let end = offset
			.0
			.checked_add(output.len() as u64)
			.ok_or(BoundsError)?;
		if end > RAW_BYTES {
			return Err(BoundsError);
		}
		let mut start = offset.0;
		let mut rest = output;
		while !rest.is_empty() {
			let size = BLOCK_BYTES as u64;
			let block = self.0.get(&(start / size)).ok_or(BoundsError)?;
			let in_block = (start % size) as usize;
			let requested = rest.len().min(BLOCK_BYTES - in_block);
			rest[..requested].copy_from_slice(&block[in_block..in_block + requested]);
			rest = &mut rest[requested..];
			start += requested as u64;
		}
		Ok(())
	}
}

#[test]
fn native_checkpoint_and_volume_selection_agree_with_apple_after_volume_growth() {
	for stage in STAGES {
		let source = Pack::decode(stage.pack);
		let xid = TransactionId(stage.xid);
		let latest = Container::open(&source, OpenOptions::default()).unwrap();
		let exact = Container::open_at(&source, OpenOptions::default(), xid).unwrap();
		let selected = latest.superblock();

		assert_eq!(selected.object.transaction, xid);
		assert_eq!(latest.descriptor(), BlockAddress(stage.descriptor));
		assert_eq!(latest.descriptor(), exact.descriptor());
		assert_eq!(selected, exact.superblock());
		assert_eq!(selected.geometry.block_bytes(), BLOCK_BYTES as u32);
		assert_eq!(
			selected.geometry.block_count(),
			RAW_BYTES / BLOCK_BYTES as u64
		);
		assert_eq!(selected.object_map, BlockAddress(stage.object_map));
		assert!(latest.diagnostics().is_empty());
		assert!(exact.diagnostics().is_empty());

		assert_ring(
			selected.descriptors,
			DESCRIPTOR_BASE,
			DESCRIPTOR_BLOCKS,
			stage.descriptor_slots,
		);
		assert_ring(selected.data, DATA_BASE, DATA_BLOCKS, stage.data_slots);

		assert_eq!(latest.mappings(), exact.mappings());
		assert_eq!(latest.mappings().len(), MAPPING_IDS.len());
		for (mapping, (id, slot)) in latest
			.mappings()
			.iter()
			.zip(MAPPING_IDS.into_iter().zip(stage.data_slots))
		{
			assert_eq!(mapping.id, ObjectId(id));
			assert_eq!(mapping.physical, BlockAddress(DATA_BASE + u64::from(slot)));
			assert_eq!(mapping.size_bytes, BLOCK_BYTES as u32);
		}

		let volumes = latest.volumes(LookupOptions::default()).unwrap();
		assert_eq!(volumes, exact.volumes(LookupOptions::default()).unwrap());
		let observed: Vec<_> = volumes
			.iter()
			.map(|volume| {
				assert_eq!(volume.checkpoint, xid);
				(
					volume.superblock.object.id,
					volume.superblock.name.as_str(),
					u128::from_be_bytes(volume.superblock.uuid),
				)
			})
			.collect();
		assert_eq!(observed, stage.volumes);
	}
}

fn assert_ring<const SLOTS: usize>(ring: Area, base: u64, blocks: u32, slots: [u32; SLOTS]) {
	assert_eq!(ring.location, AreaLocation::Contiguous(BlockAddress(base)));
	assert_eq!(ring.blocks, blocks);
	assert_eq!(ring.index, slots[0]);
	assert_eq!(ring.length, SLOTS as u32);
	assert_eq!(ring.next, slots[SLOTS - 1] + 1);
	assert_eq!(
		core::array::from_fn(|offset| ring.ring_index(offset as u32).unwrap()),
		slots
	);
}
