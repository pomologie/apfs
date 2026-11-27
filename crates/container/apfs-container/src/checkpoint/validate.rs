use apfs_core::ReadAt;
use apfs_format::{
	Error as FormatError,
	checkpoint::{Map, Mapping},
	object::{Header, KIND_MASK, ObjectId, TransactionId},
	object_map::ObjectMap,
	superblock::{Area, AreaLocation, BlockAddress, Superblock},
};

use super::{Candidate, Discovery, check_profile};
use crate::{Corruption, Error, Limit, Unsupported, alloc::vec::Vec};

#[cfg(test)]
mod tests;

const FIRST_CHECKPOINT_XID: TransactionId = TransactionId(1);
const MIN_DESCRIPTOR_LENGTH: u32 = 2; // At least one map and the final NXSB.
const EPHEMERAL: u32 = 0x8000_0000;
const SPACE_MANAGER_TYPE: u32 = EPHEMERAL | 0x0005;
const REAPER_TYPE: u32 = EPHEMERAL | 0x0011;
const NO_SUBTYPE: u32 = 0;

pub(super) struct Rings {
	pub(super) descriptor: BlockAddress,
	data: BlockAddress,
}

impl Rings {
	pub(super) fn from_bootstrap(bootstrap: &Superblock) -> Result<Self, Corruption> {
		let (AreaLocation::Contiguous(descriptor), AreaLocation::Contiguous(data)) =
			(bootstrap.descriptors.location, bootstrap.data.location)
		else {
			return Err(Corruption::Ring);
		};
		// Geometry admission already established these endpoints in the device.
		let descriptor_end = descriptor.0 + u64::from(bootstrap.descriptors.blocks);
		let data_end = data.0 + u64::from(bootstrap.data.blocks);
		if descriptor.0 < data_end && data.0 < descriptor_end {
			return Err(Corruption::Ring);
		}
		Ok(Self { descriptor, data })
	}
}

impl<S: ReadAt> Discovery<'_, S> {
	pub(super) fn read_candidate(
		&mut self,
		bootstrap: &Superblock,
		rings: &Rings,
		candidate: Candidate,
		scratch: &mut Vec<u8>,
	) -> Result<(Superblock, Vec<Mapping>), Error<S::Error>> {
		let reject = |reason| candidate.reject(reason);
		self.probe
			.read_blocks(bootstrap.geometry, candidate.address, 1, scratch)?;
		let (header, profile) = Superblock::verified_profile(scratch)
			.map_err(|error| classify_superblock_error(candidate, error))?;
		if header.transaction != candidate.xid || candidate.xid < FIRST_CHECKPOINT_XID {
			return Err(reject(Corruption::Identity));
		}
		check_profile(profile).map_err(|reason| candidate.unsupported(reason))?;
		let checkpoint = Superblock::decode(scratch, self.probe.source_len())
			.map_err(|error| reject(Corruption::Format(error)))?;
		if !same_layout(bootstrap, &checkpoint) {
			return Err(reject(Corruption::Identity));
		}
		validate_candidate_rings(&checkpoint, rings, candidate.address).map_err(reject)?;
		let mut mappings = self.read_maps(&checkpoint, rings, candidate, scratch)?;
		validate_mappings(&mut mappings, &checkpoint, rings).map_err(reject)?;
		self.validate_payloads(&mappings, &checkpoint, rings, candidate, scratch)?;
		Ok((checkpoint, mappings))
	}

	fn read_maps(
		&mut self,
		checkpoint: &Superblock,
		rings: &Rings,
		candidate: Candidate,
		scratch: &mut Vec<u8>,
	) -> Result<Vec<Mapping>, Error<S::Error>> {
		let mut mappings = Vec::new();
		let map_count = checkpoint.descriptors.length - 1;
		for ordinal in 0..map_count {
			let address = descriptor_address(checkpoint.descriptors, rings, ordinal)
				.map_err(|reason| candidate.reject(reason))?;
			self.probe
				.read_blocks(checkpoint.geometry, address, 1, scratch)?;
			let header = Header::decode(scratch)
				.map_err(|error| candidate.reject(Corruption::Format(error)))?;
			if header.transaction != candidate.xid || header.id != ObjectId(address.0) {
				return Err(candidate.reject(Corruption::Object));
			}
			let map = Map::decode(scratch, checkpoint.geometry)
				.map_err(|error| classify_map_error(candidate, error))?;
			if map.is_last() != (ordinal + 1 == map_count) {
				return Err(candidate.reject(Corruption::Object));
			}
			let entries = map.mappings();
			let count = entries.len();
			if mappings
				.len()
				.checked_add(count)
				.is_none_or(|total| total > self.max_mappings)
			{
				return Err(Error::Limit(Limit::Mappings));
			}
			mappings.try_reserve(count).map_err(|_| Error::Allocation)?;
			for mapping in entries {
				if mapping.object_type & !KIND_MASK != EPHEMERAL {
					return Err(
						candidate.unsupported(Unsupported::MappedObjectType(mapping.object_type))
					);
				}
				mappings.push(mapping);
			}
		}
		Ok(mappings)
	}

	fn validate_payloads(
		&mut self,
		mappings: &[Mapping],
		checkpoint: &Superblock,
		rings: &Rings,
		candidate: Candidate,
		scratch: &mut Vec<u8>,
	) -> Result<(), Error<S::Error>> {
		let reject = |reason| candidate.reject(reason);
		for mapping in mappings {
			self.probe.read_blocks(
				checkpoint.geometry,
				mapping.physical,
				mapping_blocks(mapping, checkpoint),
				scratch,
			)?;
			let object =
				Header::decode(scratch).map_err(|error| reject(Corruption::Format(error)))?;
			if object.transaction != candidate.xid
				|| object.id != mapping.id
				|| object.object_type != mapping.object_type
				|| object.subtype != mapping.subtype
			{
				return Err(reject(Corruption::Object));
			}
		}
		let omap = checkpoint.object_map;
		if omap.0 == 0
			|| inside(omap, rings.descriptor, checkpoint.descriptors.blocks)
			|| inside(omap, rings.data, checkpoint.data.blocks)
		{
			return Err(reject(Corruption::Ring));
		}
		self.probe
			.read_blocks(checkpoint.geometry, omap, 1, scratch)?;
		let header = Header::decode(scratch).map_err(|error| reject(Corruption::Format(error)))?;
		// A physical copy-on-write object may have been created by an older transaction.
		if header.id != ObjectId(omap.0)
			|| header.object_type != ObjectMap::OBJECT_TYPE
			|| header.subtype != NO_SUBTYPE
			|| header.transaction < FIRST_CHECKPOINT_XID
			|| header.transaction > candidate.xid
		{
			return Err(reject(Corruption::Object));
		}
		Ok(())
	}
}

fn classify_superblock_error<E>(candidate: Candidate, error: FormatError) -> Error<E> {
	match error {
		FormatError::UnexpectedObjectType(kind)
			if kind != Superblock::OBJECT_TYPE
				&& kind & KIND_MASK == Superblock::OBJECT_TYPE & KIND_MASK =>
		{
			candidate.unsupported(Unsupported::SuperblockObjectType(kind))
		}
		_ => candidate.reject(Corruption::Format(error)),
	}
}

fn classify_map_error<E>(candidate: Candidate, error: FormatError) -> Error<E> {
	match error {
		FormatError::UnsupportedCheckpointFlags(flags) => {
			candidate.unsupported(Unsupported::CheckpointMapFlags(flags))
		}
		FormatError::UnexpectedObjectType(kind)
			if kind != Map::OBJECT_TYPE && kind & KIND_MASK == Map::OBJECT_TYPE & KIND_MASK =>
		{
			candidate.unsupported(Unsupported::CheckpointMapType(kind))
		}
		_ => candidate.reject(Corruption::Format(error)),
	}
}

fn same_layout(bootstrap: &Superblock, candidate: &Superblock) -> bool {
	candidate.uuid == bootstrap.uuid
		&& candidate.geometry == bootstrap.geometry
		&& candidate.descriptors.location == bootstrap.descriptors.location
		&& candidate.descriptors.blocks == bootstrap.descriptors.blocks
		&& candidate.data.location == bootstrap.data.location
		&& candidate.data.blocks == bootstrap.data.blocks
}

fn inside(address: BlockAddress, base: BlockAddress, blocks: u32) -> bool {
	address
		.0
		.checked_sub(base.0)
		.is_some_and(|index| index < u64::from(blocks))
}

fn valid_live_ring(area: Area) -> bool {
	area.ring_index(0).is_ok()
		&& (u64::from(area.index) + u64::from(area.length)) % u64::from(area.blocks)
			== u64::from(area.next)
}

fn validate_candidate_rings(
	checkpoint: &Superblock,
	rings: &Rings,
	address: BlockAddress,
) -> Result<(), Corruption> {
	let descriptors = checkpoint.descriptors;
	if descriptors.length < MIN_DESCRIPTOR_LENGTH
		|| !valid_live_ring(descriptors)
		|| !valid_live_ring(checkpoint.data)
		|| descriptor_address(descriptors, rings, descriptors.length - 1)? != address
	{
		return Err(Corruption::Ring);
	}
	Ok(())
}

fn descriptor_address(area: Area, rings: &Rings, ordinal: u32) -> Result<BlockAddress, Corruption> {
	let index = area.ring_index(ordinal).map_err(|_| Corruption::Ring)?;
	Ok(BlockAddress(rings.descriptor.0 + u64::from(index)))
}

fn mapping_blocks(mapping: &Mapping, checkpoint: &Superblock) -> u64 {
	// The mapping codec requires a nonempty, whole-block size.
	u64::from(mapping.size_bytes / checkpoint.geometry.block_bytes())
}

fn validate_mappings(
	mappings: &mut [Mapping],
	checkpoint: &Superblock,
	rings: &Rings,
) -> Result<(), Corruption> {
	let area = checkpoint.data;
	let ring_blocks = u64::from(area.blocks);
	let span = |mapping: &Mapping| -> Result<(u64, u64), Corruption> {
		let index = mapping
			.physical
			.0
			.checked_sub(rings.data.0)
			.ok_or(Corruption::Ring)?;
		let blocks = mapping_blocks(mapping, checkpoint);
		if index
			.checked_add(blocks)
			.is_none_or(|end| end > ring_blocks)
		{
			return Err(Corruption::Ring);
		}
		let relative = (index + ring_blocks - u64::from(area.index)) % ring_blocks;
		Ok((relative, relative + blocks))
	};
	// All starts are nonnegative within the same admitted ring after these checks.
	for mapping in mappings.iter() {
		span(mapping)?;
	}
	mappings.sort_unstable_by_key(|mapping| {
		let index = mapping.physical.0 - rings.data.0;
		(index + ring_blocks - u64::from(area.index)) % ring_blocks
	});
	let mut cursor = 0;
	for mapping in mappings.iter() {
		let (start, end) = span(mapping)?;
		if start != cursor || end > u64::from(area.length) {
			return Err(Corruption::Ring);
		}
		cursor = end;
	}
	if cursor != u64::from(area.length) {
		return Err(Corruption::Ring);
	}
	mappings.sort_unstable_by_key(|mapping| mapping.id);
	if mappings.windows(2).any(|pair| pair[0].id == pair[1].id)
		|| !has_root(mappings, checkpoint.spaceman, SPACE_MANAGER_TYPE)
		|| !has_root(mappings, checkpoint.reaper, REAPER_TYPE)
	{
		return Err(Corruption::Object);
	}
	Ok(())
}

fn has_root(mappings: &[Mapping], id: ObjectId, object_type: u32) -> bool {
	mappings
		.binary_search_by_key(&id, |mapping| mapping.id)
		.is_ok_and(|index| {
			let mapping = &mappings[index];
			mapping.volume.is_none()
				&& mapping.object_type == object_type
				&& mapping.subtype == NO_SUBTYPE
		})
}
