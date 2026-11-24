use alloc::vec::Vec;
use core::fmt;

use apfs_core::{ByteOffset, ReadAt};
use apfs_format::{
	object::ObjectId,
	object_map::{Key, ObjectMap},
	superblock::BlockAddress,
};

use crate::{Container, Error, Volume};

use super::{
	Lookup, LookupOptions, VirtualMapping, VirtualObject, VirtualType, address_contains,
	format_error, verify_physical_header,
};

/// Budgeted access to virtual objects in one volume of the selected checkpoint.
///
/// Lookup uses this volume's object map and the checkpoint transaction. The
/// read budget includes opening the volume and every subsequent lookup.
pub struct VolumeObjects<'source, S> {
	volume: Volume,
	lookup: Lookup<'source, S>,
}

impl<S> fmt::Debug for VolumeObjects<'_, S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("VolumeObjects")
			.field("volume", &self.volume)
			.finish_non_exhaustive()
	}
}

impl<S: ReadAt> VolumeObjects<'_, S> {
	/// Verified metadata for this volume in the selected checkpoint.
	#[must_use]
	pub const fn volume(&self) -> &Volume {
		&self.volume
	}

	/// Reads exact bytes inside the selected container and charges the shared
	/// read budget. Filesystem callers validate the ownership and interpretation
	/// of each physical range before reading it.
	///
	/// # Errors
	/// Rejects container bounds, exhausted read budgets, and source failures.
	pub fn read_physical_at(
		&mut self,
		offset: ByteOffset,
		destination: &mut [u8],
	) -> Result<(), Error<S::Error>> {
		let geometry = self.lookup.container.superblock().geometry;
		// Geometry admission bounds this multiplication by the source length.
		let container_bytes = geometry.block_count() * u64::from(geometry.block_bytes());
		let bytes = destination.len() as u64;
		if offset
			.0
			.checked_add(bytes)
			.is_none_or(|end| end > container_bytes)
		{
			return Err(Error::ReadBounds { offset, bytes });
		}
		self.lookup.probe.read_exact(offset, destination)
	}

	/// Finds a visible mapping using the volume namespace and checkpoint XID.
	/// Absence includes a visible tombstone.
	///
	/// # Errors
	/// Rejects corrupt or unsupported tree nodes, unsafe ranges, exhausted
	/// limits and positional read failures.
	pub fn lookup_virtual_mapping(
		&mut self,
		id: ObjectId,
	) -> Result<Option<VirtualMapping>, Error<S::Error>> {
		self.lookup.mapping(
			Key {
				id,
				transaction: self.volume.checkpoint,
			},
			&mut Vec::new(),
		)
	}

	/// Reads the object visible in this volume at the selected checkpoint.
	/// Returns `None` for absent or deleted objects. A successful read verifies
	/// the complete checksum and checks the header against the mapping and type.
	///
	/// # Errors
	/// Returns mapping errors and any checksum, OID, XID, type or source error.
	pub fn read_virtual_object(
		&mut self,
		id: ObjectId,
		expected: VirtualType,
	) -> Result<Option<VirtualObject>, Error<S::Error>> {
		self.lookup.read_virtual_object(id, expected)
	}
}

impl<S: ReadAt> Container<S> {
	/// Opens one explicitly named volume's object map in the selected checkpoint.
	/// An unlisted volume returns `None`. Its filesystem nodes are read lazily.
	///
	/// # Errors
	/// Rejects an invalid volume table, unreadable or unsupported volume state,
	/// an invalid physical object map, exhausted limits and source failures.
	pub fn open_volume_objects(
		&self,
		id: ObjectId,
		options: LookupOptions,
	) -> Result<Option<VolumeObjects<'_, S>>, Error<S::Error>> {
		self.validate_volume_table()?;
		let checkpoint = self.superblock();
		let Some(slot) = checkpoint.volume_slots().find(|slot| slot.id == id) else {
			return Ok(None);
		};
		let mut lookup = Lookup::new(self, options);
		let volume = self.resolve_volume(slot, &mut lookup)?;
		let trees = volume.superblock.trees;
		let address = trees.object_map;
		let mut bytes = Vec::new();
		lookup.read(address, 1, &mut bytes)?;
		let map = ObjectMap::decode_volume(&bytes, checkpoint.geometry)
			.map_err(|error| format_error(address, error))?;
		verify_physical_header(address, map.header, volume.superblock.object.transaction)?;
		lookup.volume_map = Some(VolumeMap {
			address,
			map,
			protected: [
				address,
				checkpoint.object_map,
				volume.mapping.address,
				trees.extent_references,
				trees.snapshot_metadata,
			],
		});
		lookup.validate_range(map.root, 1)?;
		Ok(Some(VolumeObjects { volume, lookup }))
	}
}

#[derive(Clone, Copy)]
pub(super) struct VolumeMap {
	pub(super) address: BlockAddress,
	pub(super) map: ObjectMap,
	protected: [BlockAddress; 5],
}

impl VolumeMap {
	pub(super) fn overlaps_protected(self, address: BlockAddress, blocks: u64) -> bool {
		self.protected
			.into_iter()
			.any(|target| address_contains(address, blocks, target))
	}
}
