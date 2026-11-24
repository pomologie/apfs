//! Checked, borrowed checkpoint mapping blocks.

use crate::{
	Error,
	binary::u32_at,
	object::{HEADER_BYTES, Header, ObjectId},
	superblock::{BlockAddress, Geometry},
};

const PHYSICAL_CHECKPOINT_MAP: u32 = 0x4000_000c;
const NO_OBJECT_SUBTYPE: u32 = 0;
const CHECKPOINT_MAP_LAST: u32 = 1;
const MAP_FLAGS_OFFSET: usize = HEADER_BYTES;
const MAP_COUNT_OFFSET: usize = MAP_FLAGS_OFFSET + size_of::<u32>();
const MAPPINGS_OFFSET: usize = MAP_COUNT_OFFSET + size_of::<u32>();
const MAPPING_BYTES: usize = 40;
const NULL_OBJECT_ID: ObjectId = ObjectId(0);
const BOOTSTRAP_ADDRESS: BlockAddress = BlockAddress(0);

// Word indexes within the fixed-width mapping record. The reserved word follows size.
const MAPPING_TYPE_WORD: usize = 0;
const MAPPING_SUBTYPE_WORD: usize = 1;
const MAPPING_SIZE_WORD: usize = 2;
const MAPPING_VOLUME_WORD: usize = 4;
const MAPPING_ID_WORD: usize = 6;
const MAPPING_ADDRESS_WORD: usize = 8;

/// An ephemeral object mapping from a checkpoint descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Mapping {
	/// Full type of the mapped object, including flags.
	pub object_type: u32,
	/// Subtype of the mapped object.
	pub subtype: u32,
	/// Mapped object size in bytes.
	pub size_bytes: u32,
	/// Volume OID associated with this mapping, when present.
	pub volume: Option<ObjectId>,
	/// Ephemeral ID of the mapped object.
	pub id: ObjectId,
	/// Physical location of the mapped object.
	pub physical: BlockAddress,
}

/// One verified, bounded APFS checkpoint mapping block.
#[derive(Debug)]
pub struct Map<'bytes> {
	header: Header,
	last: bool,
	entries: &'bytes [[u8; MAPPING_BYTES]],
}

impl<'bytes> Map<'bytes> {
	/// Parse a complete checkpoint mapping block and validate each physical span
	/// against container geometry. Data-ring membership and XID matching are
	/// contextual checks for the checkpoint selector.
	///
	/// # Errors
	/// Returns an error for invalid type, flags, checksum, count or mapped geometry.
	pub fn decode(bytes: &'bytes [u8], geometry: Geometry) -> Result<Self, Error> {
		if bytes.len() != geometry.block_bytes() as usize {
			return Err(Error::InvalidGeometry);
		}
		let header = Header::decode(bytes)?;
		if header.object_type != PHYSICAL_CHECKPOINT_MAP || header.subtype != NO_OBJECT_SUBTYPE {
			return Err(Error::UnexpectedObjectType(header.object_type));
		}
		let flags = u32_at(bytes, MAP_FLAGS_OFFSET)?;
		if flags & !CHECKPOINT_MAP_LAST != 0 {
			return Err(Error::UnsupportedCheckpointFlags(flags));
		}
		let count = usize::try_from(u32_at(bytes, MAP_COUNT_OFFSET)?)
			.map_err(|_| Error::InvalidCheckpoint)?;
		let block_records = bytes[MAPPINGS_OFFSET..].as_chunks::<MAPPING_BYTES>().0;
		let entries = block_records.get(..count).ok_or(Error::InvalidCheckpoint)?;
		for bytes in entries {
			let mapping = decode_record(bytes);
			if mapping.id == NULL_OBJECT_ID
				|| mapping.physical == BOOTSTRAP_ADDRESS
				|| mapping.size_bytes == 0
				|| !mapping.size_bytes.is_multiple_of(geometry.block_bytes())
			{
				return Err(Error::InvalidCheckpoint);
			}
			let blocks = u64::from(mapping.size_bytes / geometry.block_bytes());
			geometry
				.byte_range(mapping.physical, blocks)
				.map_err(|_| Error::InvalidCheckpoint)?;
		}
		Ok(Self {
			header,
			last: flags & CHECKPOINT_MAP_LAST != 0,
			entries,
		})
	}

	/// Verified APFS object header for this mapping block.
	#[must_use]
	pub fn header(&self) -> Header {
		self.header
	}

	/// Whether this block is marked as the checkpoint's final mapping block.
	#[must_use]
	pub fn is_last(&self) -> bool {
		self.last
	}

	/// Mappings in on-disk block order.
	pub fn mappings(&self) -> impl ExactSizeIterator<Item = Mapping> + '_ {
		self.entries.iter().map(decode_record)
	}
}

fn decode_record(bytes: &[u8; MAPPING_BYTES]) -> Mapping {
	let words = bytes.as_chunks::<{ size_of::<u32>() }>().0;
	let word = |index| u32::from_le_bytes(words[index]);
	let wide = |index| u64::from(word(index)) | (u64::from(word(index + 1)) << u32::BITS);
	let volume = ObjectId(wide(MAPPING_VOLUME_WORD));
	Mapping {
		object_type: word(MAPPING_TYPE_WORD),
		subtype: word(MAPPING_SUBTYPE_WORD),
		size_bytes: word(MAPPING_SIZE_WORD),
		volume: (volume != NULL_OBJECT_ID).then_some(volume),
		id: ObjectId(wide(MAPPING_ID_WORD)),
		physical: BlockAddress(wide(MAPPING_ADDRESS_WORD)),
	}
}
