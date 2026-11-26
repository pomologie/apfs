//! Retained native blocks shared by checkpoint verification targets.

use std::collections::BTreeMap;

use apfs_core::{ByteOffset, ReadAt};
use apfs_format::object::{TransactionId, checksum};

pub(super) const BLOCK_BYTES: usize = 4096;
pub(super) const DEVICE_BYTES: u64 = 64 << 20;
pub(super) const BOOTSTRAP: u64 = 0;
pub(super) const EARLY_MAP: u64 = 1;
pub(super) const EARLY_NXSB: u64 = 2;
pub(super) const LATEST_MAP: u64 = 3;
pub(super) const LATEST_NXSB: u64 = 4;
pub(super) const LAST_DESCRIPTOR_BLOCK: u64 = 8;
pub(super) const WRAPPED_NXSB: u64 = EARLY_MAP;
pub(super) const MOVED_EARLY_MAP: u64 = EARLY_NXSB;
pub(super) const MOVED_EARLY_NXSB: u64 = LATEST_MAP;
pub(super) const MOVED_EARLY_DESCRIPTOR_INDEX: u32 = 1;
pub(super) const MOVED_EARLY_DESCRIPTOR_NEXT: u32 = 3;
pub(super) const WRAPPED_DESCRIPTOR_INDEX: u32 = 7;
pub(super) const WRAPPED_DESCRIPTOR_NEXT: u32 = 1;
pub(super) const DATA_RING_START: u64 = 9;
pub(super) const LATEST_FIRST_DATA: u64 = 11;
pub(super) const DATA_RING_BLOCKS: u64 = 160;
pub(super) const EARLY_OMAP: u64 = 191;
pub(super) const EARLY_OMAP_ROOT: u64 = 192;
pub(super) const VOLUME_OMAP: u64 = 193;
pub(super) const VOLUME_OMAP_ROOT: u64 = 194;
pub(super) const VOLUME_FSROOT: u64 = 197;
pub(super) const VOLUME_SUPERBLOCK: u64 = 198;
pub(super) const LATEST_OMAP: u64 = 199;
pub(super) const LATEST_OMAP_ROOT: u64 = 200;
pub(super) const CHECKSUM_BYTES: usize = 8;
pub(super) const OBJECT_ID_OFFSET: usize = 8;
pub(super) const XID_OFFSET: usize = 16;
pub(super) const INCOMPATIBLE_OFFSET: usize = 64;
pub(super) const DESCRIPTOR_NEXT_OFFSET: usize = 128;
pub(super) const DATA_NEXT_OFFSET: usize = 132;
pub(super) const DESCRIPTOR_INDEX_OFFSET: usize = 136;
pub(super) const DATA_INDEX_OFFSET: usize = 144;
pub(super) const MAP_FLAGS_OFFSET: usize = 32;
pub(super) const FIRST_MAPPING_OFFSET: usize = 40;
pub(super) const MAPPING_BYTES: usize = 40;
pub(super) const MAPPING_ID_OFFSET: usize = 24;
pub(super) const MAPPING_PHYSICAL_OFFSET: usize = 32;
pub(super) const LATEST_MAPPING_COUNT: usize = 4;
pub(super) const EARLY_XID: TransactionId = TransactionId(1);
pub(super) const LATEST_XID: TransactionId = TransactionId(2);

macro_rules! native_block {
	($address:literal) => {
		*include_bytes!(concat!(
			"../tests/fixtures/native-block-",
			stringify!($address),
			".bin"
		))
	};
}

#[derive(Debug)]
pub(super) struct Fixture(pub(super) BTreeMap<u64, [u8; BLOCK_BYTES]>);

impl Fixture {
	pub(super) fn native() -> Self {
		Self(BTreeMap::from([
			(BOOTSTRAP, native_block!(0)),
			(EARLY_MAP, native_block!(1)),
			(EARLY_NXSB, native_block!(2)),
			(LATEST_MAP, native_block!(3)),
			(LATEST_NXSB, native_block!(4)),
			// The provenance ledger records these verified blank native slots.
			(5, [0; BLOCK_BYTES]),
			(6, [0; BLOCK_BYTES]),
			(7, [0; BLOCK_BYTES]),
			(LAST_DESCRIPTOR_BLOCK, [0; BLOCK_BYTES]),
			(DATA_RING_START, native_block!(9)),
			(10, native_block!(10)),
			(LATEST_FIRST_DATA, native_block!(11)),
			(12, native_block!(12)),
			(13, native_block!(13)),
			(14, native_block!(14)),
			(EARLY_OMAP, native_block!(191)),
			(EARLY_OMAP_ROOT, native_block!(192)),
			(VOLUME_OMAP, native_block!(193)),
			(VOLUME_OMAP_ROOT, native_block!(194)),
			(VOLUME_FSROOT, native_block!(197)),
			(VOLUME_SUPERBLOCK, native_block!(198)),
			(LATEST_OMAP, native_block!(199)),
			(LATEST_OMAP_ROOT, native_block!(200)),
		]))
	}

	/// Keep the earlier native checkpoint complete while the newer descriptor
	/// wraps to the first ring slot and refers to a map in the last slot.
	pub(super) fn wrapped_descriptors() -> Self {
		let mut fixture = Self::native();
		let latest_map = fixture.0[&LATEST_MAP];
		fixture.0.insert(MOVED_EARLY_NXSB, fixture.0[&EARLY_NXSB]);
		fixture.0.insert(MOVED_EARLY_MAP, fixture.0[&EARLY_MAP]);
		fixture.0.insert(WRAPPED_NXSB, fixture.0[&LATEST_NXSB]);
		fixture.0.insert(LAST_DESCRIPTOR_BLOCK, latest_map);
		fixture.0.insert(LATEST_NXSB, [0; BLOCK_BYTES]);
		fixture.set_u64(MOVED_EARLY_MAP, OBJECT_ID_OFFSET, MOVED_EARLY_MAP);
		fixture.set_u32(
			MOVED_EARLY_NXSB,
			DESCRIPTOR_INDEX_OFFSET,
			MOVED_EARLY_DESCRIPTOR_INDEX,
		);
		fixture.set_u32(
			MOVED_EARLY_NXSB,
			DESCRIPTOR_NEXT_OFFSET,
			MOVED_EARLY_DESCRIPTOR_NEXT,
		);
		fixture.set_u64(
			LAST_DESCRIPTOR_BLOCK,
			OBJECT_ID_OFFSET,
			LAST_DESCRIPTOR_BLOCK,
		);
		fixture.set_u32(
			WRAPPED_NXSB,
			DESCRIPTOR_INDEX_OFFSET,
			WRAPPED_DESCRIPTOR_INDEX,
		);
		fixture.set_u32(
			WRAPPED_NXSB,
			DESCRIPTOR_NEXT_OFFSET,
			WRAPPED_DESCRIPTOR_NEXT,
		);
		fixture
	}

	pub(super) fn set_u32(&mut self, block: u64, offset: usize, value: u32) {
		let bytes = self.0.get_mut(&block).unwrap();
		bytes[offset..offset + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
		update_checksum(bytes);
	}

	pub(super) fn set_u64(&mut self, block: u64, offset: usize, value: u64) {
		let bytes = self.0.get_mut(&block).unwrap();
		bytes[offset..offset + size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
		update_checksum(bytes);
	}
}

pub(super) fn update_checksum(bytes: &mut [u8]) {
	let sum = checksum(bytes).unwrap();
	bytes[..CHECKSUM_BYTES].copy_from_slice(&sum.to_le_bytes());
}

impl ReadAt for Fixture {
	type Error = u64;

	fn len(&self) -> u64 {
		DEVICE_BYTES
	}

	fn read_exact_at(&self, offset: ByteOffset, out: &mut [u8]) -> Result<(), Self::Error> {
		let mut start = offset.0;
		let mut destination = out;
		while !destination.is_empty() {
			let block = start / BLOCK_BYTES as u64;
			let within = (start % BLOCK_BYTES as u64) as usize;
			let bytes = self.0.get(&block).ok_or(block)?;
			let take = destination.len().min(BLOCK_BYTES - within);
			let (head, tail) = destination.split_at_mut(take);
			head.copy_from_slice(&bytes[within..within + take]);
			destination = tail;
			start += take as u64;
		}
		Ok(())
	}
}
