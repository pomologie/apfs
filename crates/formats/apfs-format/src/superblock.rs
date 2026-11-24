//! NXSB container geometry and checkpoint area declarations.

use core::ops::Range;

use crate::{
	Error,
	binary::{field, u32_at, u64_at},
	object::{HEADER_BYTES, Header, ObjectId, TransactionId},
};

const NX_SUPERBLOCK_MAGIC: [u8; 4] = *b"NXSB";
const NX_SUPERBLOCK_OBJECT_TYPE: u32 = 0x8000_0001;
const NX_SUPERBLOCK_OBJECT_SUBTYPE: u32 = 0;
const NX_SUPERBLOCK_OBJECT_ID: ObjectId = ObjectId(1);
const MIN_BLOCK_BYTES: u32 = 4096;
const MAX_BLOCK_BYTES: u32 = 65_536;
const MIN_CONTAINER_BYTES: u64 = 1 << 20;
const MAX_FILESYSTEM_IDS: usize = 100;
const EMPTY_FILESYSTEM_ID: ObjectId = ObjectId(0);
const OBJECT_ID_BYTES: usize = size_of::<u64>();
const UUID_BYTES: usize = 16;
const FRAGMENTED_AREA_FLAG: u32 = 1 << 31;
const MISSING_AREA_ADDRESS: BlockAddress = BlockAddress(0);

const MAGIC_OFFSET: usize = HEADER_BYTES;
const BLOCK_SIZE_OFFSET: usize = 36;
const BLOCK_COUNT_OFFSET: usize = 40;
const FEATURES_OFFSET: usize = 48;
const READ_ONLY_COMPATIBLE_FEATURES_OFFSET: usize = 56;
const INCOMPATIBLE_FEATURES_OFFSET: usize = 64;
const UUID_OFFSET: usize = 72;
const NEXT_OBJECT_ID_OFFSET: usize = 88;
const NEXT_TRANSACTION_ID_OFFSET: usize = 96;
const SPACEMAN_ID_OFFSET: usize = 152;
const OBJECT_MAP_ADDRESS_OFFSET: usize = 160;
const REAPER_ID_OFFSET: usize = 168;
const MAX_VOLUMES_OFFSET: usize = 180;
const FILESYSTEM_IDS_OFFSET: usize = 184;

struct AreaOffsets {
	block_count: usize,
	base: usize,
	next: usize,
	index: usize,
	length: usize,
}

const DESCRIPTOR_AREA_OFFSETS: AreaOffsets = AreaOffsets {
	block_count: 104,
	base: 112,
	next: 128,
	index: 136,
	length: 140,
};

const DATA_AREA_OFFSETS: AreaOffsets = AreaOffsets {
	block_count: 108,
	base: 120,
	next: 132,
	index: 144,
	length: 148,
};

/// Physical block address within the current bounded container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockAddress(pub u64);

/// Container geometry bounded by the length of the admitted device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
	block_bytes: u32,
	block_count: u64,
}

impl Geometry {
	fn new(block_bytes: u32, block_count: u64, device_bytes: u64) -> Result<Self, Error> {
		admit_block_bytes(block_bytes)?;
		let byte_len = block_count
			.checked_mul(u64::from(block_bytes))
			.ok_or(Error::InvalidGeometry)?;
		if !(MIN_CONTAINER_BYTES..=device_bytes).contains(&byte_len) {
			return Err(Error::InvalidGeometry);
		}
		Ok(Self {
			block_bytes,
			block_count,
		})
	}

	/// Container block size in bytes.
	#[must_use]
	pub fn block_bytes(self) -> u32 {
		self.block_bytes
	}

	/// Number of logical blocks in the container.
	#[must_use]
	pub fn block_count(self) -> u64 {
		self.block_count
	}

	/// Translate an admitted physical block span to bytes within the container.
	///
	/// # Errors
	/// Returns [`Error::InvalidGeometry`] if either bound escapes the container.
	pub fn byte_range(self, start: BlockAddress, blocks: u64) -> Result<Range<u64>, Error> {
		let end = start
			.0
			.checked_add(blocks)
			.filter(|&end| end <= self.block_count)
			.ok_or(Error::InvalidGeometry)?;
		let block_bytes = u64::from(self.block_bytes);
		Ok(start.0 * block_bytes..end * block_bytes)
	}
}

/// Checkpoint descriptors and payloads can live in contiguous rings or use a fragment tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AreaLocation {
	/// Address of the first block in an ordinary contiguous area.
	Contiguous(BlockAddress),
	/// Physical object identifier of the tree describing the area fragments.
	FragmentTree(BlockAddress),
}

/// One checkpoint descriptor or data area declared in a container superblock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Area {
	/// Physical placement or tree locator.
	pub location: AreaLocation,
	/// Total blocks in the ring.
	pub blocks: u32,
	/// First live index in this checkpoint. Meaningful for checkpoint copies only.
	pub index: u32,
	/// Live blocks in this checkpoint. Meaningful for checkpoint copies only.
	pub length: u32,
	/// Next write index. Meaningful for checkpoint copies only.
	pub next: u32,
}

impl Area {
	fn decode(bytes: &[u8], geometry: Geometry, offsets: AreaOffsets) -> Result<Self, Error> {
		let stored = u32_at(bytes, offsets.block_count)?;
		let blocks = stored & !FRAGMENTED_AREA_FLAG;
		let base = BlockAddress(u64_at(bytes, offsets.base)?);
		if blocks == 0 || base == MISSING_AREA_ADDRESS {
			return Err(Error::InvalidCheckpoint);
		}
		let location = if stored & FRAGMENTED_AREA_FLAG == 0 {
			geometry
				.byte_range(base, u64::from(blocks))
				.map_err(|_| Error::InvalidCheckpoint)?;
			AreaLocation::Contiguous(base)
		} else {
			geometry
				.byte_range(base, 1)
				.map_err(|_| Error::InvalidCheckpoint)?;
			AreaLocation::FragmentTree(base)
		};
		Ok(Self {
			location,
			blocks,
			index: u32_at(bytes, offsets.index)?,
			length: u32_at(bytes, offsets.length)?,
			next: u32_at(bytes, offsets.next)?,
		})
	}

	/// Map an index within this checkpoint's live span into the ring, allowing wrap.
	/// Only call on the descriptor-area checkpoint copy, not the block-zero hint.
	///
	/// # Errors
	/// Returns [`Error::InvalidCheckpoint`] for inconsistent ring geometry or an out-of-range ordinal.
	pub fn ring_index(self, ordinal: u32) -> Result<u32, Error> {
		if self.index >= self.blocks
			|| self.next >= self.blocks
			|| self.length > self.blocks
			|| ordinal >= self.length
		{
			return Err(Error::InvalidCheckpoint);
		}
		Ok(((u64::from(self.index) + u64::from(ordinal)) % u64::from(self.blocks)) as u32)
	}
}

/// Verified container superblock fields, including raw feature masks.
/// The block-zero header is a bootstrap hint and does not select a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Superblock {
	/// Verified on-disk object header.
	pub object: Header,
	/// Bounded logical geometry.
	pub geometry: Geometry,
	/// Volume-independent container UUID bytes.
	pub uuid: [u8; UUID_BYTES],
	/// Optional feature mask.
	pub features: u64,
	/// Read-only-compatible feature mask.
	pub read_only_compatible: u64,
	/// Incompatible feature mask. Consumers must check the bits before opening a view.
	pub incompatible: u64,
	/// First unassigned virtual or ephemeral OID.
	pub next_object: ObjectId,
	/// Next transaction identifier.
	pub next_transaction: TransactionId,
	/// Area containing checkpoint mapping blocks and superblock copies.
	pub descriptors: Area,
	/// Area containing ephemeral checkpoint objects.
	pub data: Area,
	/// Space manager ephemeral object ID.
	pub spaceman: ObjectId,
	/// Physical object map address.
	pub object_map: BlockAddress,
	/// Reaper ephemeral object ID.
	pub reaper: ObjectId,
	/// Declared capacity of the volume identifier table.
	pub max_volumes: u32,
	volume_ids: [ObjectId; MAX_FILESYSTEM_IDS],
}

impl Superblock {
	/// Read the candidate block length from the 40-byte NXSB prefix to size a
	/// subsequent bounded full read. The prefix is not checksum-verified here.
	///
	/// # Errors
	/// Returns an error for incomplete input, absent magic or invalid block size.
	pub fn block_size_hint(prefix: &[u8]) -> Result<u32, Error> {
		if field(prefix, MAGIC_OFFSET)? != NX_SUPERBLOCK_MAGIC {
			return Err(Error::InvalidMagic);
		}
		let block_bytes = u32_at(prefix, BLOCK_SIZE_OFFSET)?;
		admit_block_bytes(block_bytes)?;
		Ok(block_bytes)
	}

	/// Decode one complete NXSB object bounded by the admitted device length.
	///
	/// # Errors
	/// Returns an error for invalid type, geometry, checksum or fields that exceed container limits.
	pub fn decode(bytes: &[u8], device_bytes: u64) -> Result<Self, Error> {
		let geometry = Geometry::new(
			Self::block_size_hint(bytes)?,
			u64_at(bytes, BLOCK_COUNT_OFFSET)?,
			device_bytes,
		)?;
		if bytes.len() != geometry.block_bytes as usize {
			return Err(Error::InvalidGeometry);
		}
		let object = Header::decode(bytes)?;
		if object.object_type != NX_SUPERBLOCK_OBJECT_TYPE
			|| object.subtype != NX_SUPERBLOCK_OBJECT_SUBTYPE
			|| object.id != NX_SUPERBLOCK_OBJECT_ID
		{
			return Err(Error::UnexpectedObjectType(object.object_type));
		}
		let max_volumes = u32_at(bytes, MAX_VOLUMES_OFFSET)?;
		if max_volumes > MAX_FILESYSTEM_IDS as u32 {
			return Err(Error::InvalidGeometry);
		}
		let object_map = BlockAddress(u64_at(bytes, OBJECT_MAP_ADDRESS_OFFSET)?);
		geometry.byte_range(object_map, 1)?;
		let mut volume_ids = [EMPTY_FILESYSTEM_ID; MAX_FILESYSTEM_IDS];
		for (index, id) in volume_ids.iter_mut().enumerate() {
			*id = ObjectId(u64_at(
				bytes,
				FILESYSTEM_IDS_OFFSET + OBJECT_ID_BYTES * index,
			)?);
		}
		Ok(Self {
			object,
			geometry,
			uuid: field(bytes, UUID_OFFSET)?,
			features: u64_at(bytes, FEATURES_OFFSET)?,
			read_only_compatible: u64_at(bytes, READ_ONLY_COMPATIBLE_FEATURES_OFFSET)?,
			incompatible: u64_at(bytes, INCOMPATIBLE_FEATURES_OFFSET)?,
			next_object: ObjectId(u64_at(bytes, NEXT_OBJECT_ID_OFFSET)?),
			next_transaction: TransactionId(u64_at(bytes, NEXT_TRANSACTION_ID_OFFSET)?),
			descriptors: Area::decode(bytes, geometry, DESCRIPTOR_AREA_OFFSETS)?,
			data: Area::decode(bytes, geometry, DATA_AREA_OFFSETS)?,
			spaceman: ObjectId(u64_at(bytes, SPACEMAN_ID_OFFSET)?),
			object_map,
			reaper: ObjectId(u64_at(bytes, REAPER_ID_OFFSET)?),
			max_volumes,
			volume_ids,
		})
	}

	/// Nonempty virtual OIDs declared by the superblock, in their original order.
	/// Resolving these requires a container object map for the selected checkpoint.
	pub fn volume_ids(&self) -> impl Iterator<Item = ObjectId> + '_ {
		self.volume_ids
			.iter()
			.copied()
			.filter(|&id| id != EMPTY_FILESYSTEM_ID)
	}
}

fn admit_block_bytes(bytes: u32) -> Result<(), Error> {
	if !(MIN_BLOCK_BYTES..=MAX_BLOCK_BYTES).contains(&bytes) || !bytes.is_power_of_two() {
		return Err(Error::InvalidGeometry);
	}
	Ok(())
}
