use alloc::vec::Vec;

use apfs_core::ReadAt;
use apfs_format::{
	object::{ObjectId, TransactionId},
	superblock::VolumeSlot,
	volume::VolumeSuperblock,
};

use crate::{
	Container, Error, LookupOptions, VirtualMapping, VirtualType, VolumeError, object_map::Lookup,
};

const FIRST_DYNAMIC_OBJECT_ID: ObjectId = ObjectId(1024);
const APSB_TYPE: VirtualType = VirtualType {
	kind: VolumeSuperblock::OBJECT_KIND,
	subtype: VolumeSuperblock::OBJECT_SUBTYPE,
};

/// Checked volume metadata in a selected container checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Volume {
	/// Selected container transaction used for mapping lookup.
	pub checkpoint: TransactionId,
	/// Visible mapping, whose object may have been written by an older transaction.
	pub mapping: VirtualMapping,
	/// Checked volume superblock, including its declared tree references.
	pub superblock: VolumeSuperblock,
}

impl<S: ReadAt> Container<S> {
	/// Enumerates the selected checkpoint's volumes in original NXSB slot order.
	/// All entries must pass volume metadata admission. One aggregate read budget
	/// covers the operation. This operation does not open filesystem trees.
	///
	/// # Errors
	/// Rejects an inconsistent volume table, any missing or unsupported volume,
	/// duplicate UUIDs, source errors, and exhausted read or allocation limits.
	pub fn volumes(&self, options: LookupOptions) -> Result<Vec<Volume>, Error<S::Error>> {
		self.validate_volume_table()?;
		let mut volumes: Vec<Volume> = Vec::new();
		volumes
			.try_reserve_exact(self.superblock().volume_slots().count())
			.map_err(|_| Error::Allocation)?;
		let mut lookup = Lookup::new(self, options);
		for slot in self.superblock().volume_slots() {
			let volume = self.resolve_volume(slot, &mut lookup)?;
			if volumes
				.iter()
				.any(|other| volume.superblock.uuid == other.superblock.uuid)
			{
				return Err(volume_error(slot.id, VolumeError::DuplicateUuid));
			}
			if volumes
				.iter()
				.any(|other| volume.superblock.trees.root == other.superblock.trees.root)
			{
				return Err(volume_error(slot.id, VolumeError::AliasedTree));
			}
			volumes.push(volume);
		}
		Ok(volumes)
	}

	/// Reads metadata for an explicitly named volume OID in the selected checkpoint.
	/// An unlisted OID returns `None`; a listed OID must resolve at this checkpoint.
	///
	/// # Errors
	/// Rejects an inconsistent volume table, a missing or unsupported selected
	/// volume, source errors and exhausted read or allocation limits.
	pub fn volume(
		&self,
		id: ObjectId,
		options: LookupOptions,
	) -> Result<Option<Volume>, Error<S::Error>> {
		self.validate_volume_table()?;
		self.superblock()
			.volume_slots()
			.find(|slot| slot.id == id)
			.map(|slot| self.resolve_volume(slot, &mut Lookup::new(self, options)))
			.transpose()
	}

	pub(super) fn validate_volume_table(&self) -> Result<(), Error<S::Error>> {
		let checkpoint = self.superblock();
		for slot in checkpoint.volume_slots() {
			if slot.index >= checkpoint.max_volumes {
				return Err(volume_error(slot.id, VolumeError::SlotBounds(slot.index)));
			}
			if slot.id < FIRST_DYNAMIC_OBJECT_ID || slot.id >= checkpoint.next_object {
				return Err(volume_error(slot.id, VolumeError::InvalidId));
			}
			if checkpoint
				.volume_slots()
				.take_while(|other| other.index < slot.index)
				.any(|other| other.id == slot.id)
			{
				return Err(volume_error(slot.id, VolumeError::DuplicateId));
			}
		}
		Ok(())
	}

	pub(super) fn resolve_volume(
		&self,
		slot: VolumeSlot,
		lookup: &mut Lookup<'_, S>,
	) -> Result<Volume, Error<S::Error>> {
		let checkpoint = self.superblock();
		let object = lookup
			.read_virtual_object(slot.id, APSB_TYPE)?
			.ok_or_else(|| volume_error(slot.id, VolumeError::MissingObject))?;
		let superblock = VolumeSuperblock::decode(object.as_bytes(), checkpoint.geometry)
			.map_err(|error| volume_error(slot.id, VolumeError::Format(error)))?;
		if superblock.index != slot.index {
			return Err(volume_error(
				slot.id,
				VolumeError::SlotMismatch {
					expected: slot.index,
					actual: superblock.index,
				},
			));
		}
		let trees = superblock.trees;
		if trees.root < FIRST_DYNAMIC_OBJECT_ID || trees.root >= checkpoint.next_object {
			return Err(volume_error(slot.id, VolumeError::InvalidRootId));
		}
		if checkpoint.volume_ids().any(|id| id == trees.root) {
			return Err(volume_error(slot.id, VolumeError::AliasedTree));
		}
		for address in [
			trees.object_map,
			trees.extent_references,
			trees.snapshot_metadata,
		] {
			if address == object.mapping.address || address == checkpoint.object_map {
				return Err(volume_error(slot.id, VolumeError::AliasedTree));
			}
			lookup.validate_range(address, 1)?;
		}
		Ok(Volume {
			checkpoint: checkpoint.object.transaction,
			mapping: object.mapping,
			superblock,
		})
	}
}

fn volume_error<E>(id: ObjectId, reason: VolumeError) -> Error<E> {
	Error::Volume { id, reason }
}
