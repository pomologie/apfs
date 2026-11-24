//! Checksummed, fixed-size codecs for physical object maps and their B-trees.

use core::ops::Range;

use crate::{
	Error,
	binary::{field, u16_at, u32_at, u64_at},
	object::{HEADER_BYTES, Header, ObjectId, TransactionId},
	superblock::{BlockAddress, Geometry, MAX_BLOCK_BYTES},
};

const PHYSICAL_STORAGE: u32 = 1 << 30;
const OBJECT_MAP_KIND: u32 = 0x000b;
const BTREE_ROOT: u32 = PHYSICAL_STORAGE | 0x0002;
const BTREE_NODE: u32 = PHYSICAL_STORAGE | 0x0003;
const NO_SUBTYPE: u32 = 0;
const MANUALLY_MANAGED: u32 = 1;

const MAP_FLAGS: usize = HEADER_BYTES;
const MAP_SNAPSHOT_COUNT: usize = 36;
const MAP_TREE_TYPE: usize = 40;
const MAP_SNAPSHOT_TREE_TYPE: usize = 44;
const MAP_ROOT_ADDRESS: usize = 48;
const MAP_SNAPSHOT_TREE_ADDRESS: usize = 56;
const MAP_RECENT_SNAPSHOT: usize = 64;
const MAP_PENDING_REVERT_MIN: usize = 72;
const MAP_PENDING_REVERT_MAX: usize = 80;

const NODE_FLAGS: usize = HEADER_BYTES;
const NODE_LEVEL: usize = 34;
const NODE_COUNT: usize = 36;
const NODE_TABLE_SPACE: usize = 40;
const NODE_FREE_SPACE: usize = 44;
const NODE_KEY_FREE_LIST: usize = 48;
const NODE_VALUE_FREE_LIST: usize = 52;
const NODE_DATA: usize = 56;
const FOOTER_BYTES: usize = 40;
const ROOT_FLAG: u16 = 1;
const LEAF_FLAG: u16 = 1 << 1;
const FIXED_RECORDS_FLAG: u16 = 1 << 2;
const PHYSICAL_TREE_FLAG: u32 = 1 << 4;
const SEQUENTIAL_INSERT_FLAG: u32 = 1 << 1;
const KNOWN_TREE_FLAGS: u32 = PHYSICAL_TREE_FLAG | SEQUENTIAL_INSERT_FLAG;
const NONE_OFFSET: u16 = u16::MAX;

const KEY_BYTES: usize = 2 * size_of::<u64>();
const VALUE_BYTES: usize = 2 * size_of::<u32>() + size_of::<i64>();
const CHILD_BYTES: usize = size_of::<u64>();
const SLOT_BYTES: usize = 2 * size_of::<u16>();
const RECORD_ALIGNMENT: usize = size_of::<u64>();
const ALIGNMENTS_PER_WORD: usize = u64::BITS as usize;
const OCCUPANCY_WORDS: usize =
	(MAX_BLOCK_BYTES as usize).div_ceil(RECORD_ALIGNMENT * ALIGNMENTS_PER_WORD);
const DELETED: u32 = 1;

/// Physical object map and its B-tree root location.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ObjectMap {
	/// Verified physical object header.
	pub header: Header,
	/// Physical address of the root of the mapping tree.
	pub root: BlockAddress,
}

impl ObjectMap {
	/// Full type word for an ordinary physical object map.
	pub const OBJECT_TYPE: u32 = PHYSICAL_STORAGE | OBJECT_MAP_KIND;

	/// Decodes the ordinary, manually managed container object map.
	///
	/// # Errors
	/// Rejects unsupported flags, snapshots, inconsistent fields, checksums,
	/// and addresses outside the container.
	pub fn decode(bytes: &[u8], geometry: Geometry) -> Result<Self, Error> {
		if bytes.len() != geometry.block_bytes() as usize {
			return Err(Error::InvalidGeometry);
		}
		let header = Header::decode(bytes)?;
		if header.object_type != Self::OBJECT_TYPE || header.subtype != NO_SUBTYPE {
			return Err(Error::UnexpectedObjectType(header.object_type));
		}
		let flags = u32_at(bytes, MAP_FLAGS)?;
		if flags != MANUALLY_MANAGED {
			return Err(Error::UnsupportedObjectMapFlags(flags));
		}
		let tree_type = u32_at(bytes, MAP_TREE_TYPE)?;
		if tree_type != BTREE_ROOT {
			return Err(Error::UnexpectedObjectType(tree_type));
		}
		let snapshot_tree_type = u32_at(bytes, MAP_SNAPSHOT_TREE_TYPE)?;
		if !matches!(snapshot_tree_type, NO_SUBTYPE | BTREE_ROOT)
			|| u32_at(bytes, MAP_SNAPSHOT_COUNT)? != 0
			|| u64_at(bytes, MAP_SNAPSHOT_TREE_ADDRESS)? != 0
			|| u64_at(bytes, MAP_RECENT_SNAPSHOT)? != 0
			|| u64_at(bytes, MAP_PENDING_REVERT_MIN)? != 0
			|| u64_at(bytes, MAP_PENDING_REVERT_MAX)? != 0
		{
			return Err(Error::UnsupportedObjectMapSnapshot);
		}

		let root = physical_address(bytes, MAP_ROOT_ADDRESS)?;
		geometry.byte_range(root, 1)?;
		Ok(Self { header, root })
	}
}

/// Object-map key ordered numerically by object ID and then transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Key {
	/// Virtual object ID.
	pub id: ObjectId,
	/// Transaction which introduced the mapping.
	pub transaction: TransactionId,
}

/// Mapping value stored at a leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Mapping {
	/// The key is a tombstone for this and later views.
	Deleted,
	/// A standard checksummed object at a physical address.
	Object {
		/// First physical block of the object.
		address: BlockAddress,
		/// Logical size of the physical object, in bytes.
		size: u32,
	},
}

/// Value stored alongside a key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Value {
	/// Pointer to the node covering the key's subtree.
	Child(BlockAddress),
	/// Physical mapping or tombstone.
	Mapping(Mapping),
}

/// One admitted object-map record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record {
	/// Virtual ID and transaction.
	pub key: Key,
	/// Subtree or leaf mapping.
	pub value: Value,
}

/// A checked table of contents and disjoint fixed-size key/value regions.
#[derive(Debug)]
pub struct Node<'block> {
	bytes: &'block [u8],
	header: Header,
	level: u16,
	count: usize,
	table_base: usize,
	keys: Range<usize>,
	values: Range<usize>,
}

impl<'block> Node<'block> {
	/// Verifies a physical root or child node and every occupied key/value slot.
	///
	/// # Errors
	/// Rejects wrong types, invalid checksums, invalid ranges and overlapping
	/// slots, invalid record ordering, and node flags outside this profile.
	pub fn decode(bytes: &'block [u8], geometry: Geometry, root: bool) -> Result<Self, Error> {
		if bytes.len() != geometry.block_bytes() as usize {
			return Err(Error::InvalidGeometry);
		}
		let header = Header::decode(bytes)?;
		let object_type = if root { BTREE_ROOT } else { BTREE_NODE };
		if header.object_type != object_type || header.subtype != OBJECT_MAP_KIND {
			return Err(Error::UnexpectedObjectType(header.object_type));
		}
		let level = u16_at(bytes, NODE_LEVEL)?;
		let flags = u16_at(bytes, NODE_FLAGS)?;
		let expected_flags = FIXED_RECORDS_FLAG
			| if root { ROOT_FLAG } else { 0 }
			| if level == 0 { LEAF_FLAG } else { 0 };
		if flags != expected_flags {
			return Err(Error::UnsupportedObjectMapFlags(u32::from(flags)));
		}
		let count = u32_at(bytes, NODE_COUNT)? as usize;
		if count == 0 && (!root || level != 0) {
			return Err(Error::InvalidObjectMap);
		}
		let values_end = if root {
			let footer = bytes.len() - FOOTER_BYTES;
			validate_footer(&bytes[footer..], geometry, level, count)?;
			footer
		} else {
			bytes.len()
		};

		let table = location(bytes, NODE_TABLE_SPACE, NODE_DATA)?;
		let free_space = location(bytes, NODE_FREE_SPACE, table.end)?;
		if count > table.len() / SLOT_BYTES || free_space.end > values_end {
			return Err(Error::InvalidObjectMap);
		}
		for offset in [NODE_KEY_FREE_LIST, NODE_VALUE_FREE_LIST] {
			if u16_at(bytes, offset)? != NONE_OFFSET
				|| u16_at(bytes, offset + size_of::<u16>())? != 0
			{
				return Err(Error::UnsupportedObjectMapFlags(u32::from(flags)));
			}
		}
		let node = Self {
			bytes,
			header,
			level,
			count,
			table_base: table.start,
			keys: table.end..free_space.start,
			values: free_space.end..values_end,
		};
		node.validate_records(geometry)?;
		Ok(node)
	}

	/// Verified standard header.
	#[must_use]
	pub const fn header(&self) -> Header {
		self.header
	}

	/// Levels below this node, with zero denoting a leaf.
	#[must_use]
	pub const fn level(&self) -> u16 {
		self.level
	}

	/// Number of admitted records.
	#[must_use]
	pub const fn len(&self) -> usize {
		self.count
	}

	/// Whether this node has no records.
	#[must_use]
	pub const fn is_empty(&self) -> bool {
		self.count == 0
	}

	/// Reads an admitted record in table order.
	///
	/// # Errors
	/// Returns an error if the index is outside this node.
	pub fn record(&self, index: usize) -> Result<Record, Error> {
		let (key_at, value_at) = self.positions(index)?;
		let key = Key {
			id: ObjectId(u64_at(self.bytes, key_at)?),
			transaction: TransactionId(u64_at(self.bytes, key_at + size_of::<u64>())?),
		};
		let value = if self.level != 0 {
			Value::Child(physical_address(self.bytes, value_at)?)
		} else {
			let flags = u32_at(self.bytes, value_at)?;
			match flags {
				DELETED => Value::Mapping(Mapping::Deleted),
				0 => Value::Mapping(Mapping::Object {
					size: u32_at(self.bytes, value_at + size_of::<u32>())?,
					address: physical_address(self.bytes, value_at + 2 * size_of::<u32>())?,
				}),
				flags => return Err(Error::UnsupportedObjectMapFlags(flags)),
			}
		};
		Ok(Record { key, value })
	}

	fn value_bytes(&self) -> usize {
		if self.level == 0 {
			VALUE_BYTES
		} else {
			CHILD_BYTES
		}
	}

	fn positions(&self, index: usize) -> Result<(usize, usize), Error> {
		if index >= self.count {
			return Err(Error::InvalidObjectMap);
		}
		let slot = self.table_base + index * SLOT_BYTES;
		let key_offset = usize::from(u16_at(self.bytes, slot)?);
		let value_offset = usize::from(u16_at(self.bytes, slot + size_of::<u16>())?);
		let key_at = self.keys.start + key_offset;
		let value_at = self
			.values
			.end
			.checked_sub(value_offset)
			.ok_or(Error::InvalidObjectMap)?;
		if !key_offset.is_multiple_of(RECORD_ALIGNMENT)
			|| !value_offset.is_multiple_of(RECORD_ALIGNMENT)
			|| key_at + KEY_BYTES > self.keys.end
			|| value_at < self.values.start
			|| value_offset < self.value_bytes()
		{
			return Err(Error::InvalidObjectMap);
		}
		Ok((key_at, value_at))
	}

	fn validate_records(&self, geometry: Geometry) -> Result<(), Error> {
		let mut occupied = [0u64; OCCUPANCY_WORDS];
		let mut previous = None;
		for index in 0..self.count {
			let (key_at, value_at) = self.positions(index)?;
			// Alignment is relative to each region. Use one scratch bitset, with
			// disjoint slots derived from the physical byte ranges of the node.
			if !key_at.is_multiple_of(RECORD_ALIGNMENT) {
				return Err(Error::InvalidObjectMap);
			}
			claim(&mut occupied, key_at, KEY_BYTES)?;
			claim(&mut occupied, value_at, self.value_bytes())?;
			let record = self.record(index)?;
			if record.key.id == ObjectId(0)
				|| record.key.transaction == TransactionId(0)
				|| record.key.transaction > self.header.transaction
				|| previous.is_some_and(|prior| prior >= record.key)
			{
				return Err(Error::InvalidObjectMap);
			}
			match record.value {
				Value::Child(address) => {
					geometry.byte_range(address, 1)?;
				}
				Value::Mapping(Mapping::Object { address, size }) => {
					if size == 0 || !size.is_multiple_of(geometry.block_bytes()) {
						return Err(Error::InvalidObjectMap);
					}
					geometry.byte_range(address, u64::from(size / geometry.block_bytes()))?;
				}
				Value::Mapping(Mapping::Deleted) => {}
			}
			previous = Some(record.key);
		}
		Ok(())
	}
}

fn location(bytes: &[u8], offset: usize, base: usize) -> Result<Range<usize>, Error> {
	let start = base + usize::from(u16_at(bytes, offset)?);
	let len = usize::from(u16_at(bytes, offset + size_of::<u16>())?);
	Ok(start..start + len)
}

fn physical_address(bytes: &[u8], offset: usize) -> Result<BlockAddress, Error> {
	let address = i64::from_le_bytes(field(bytes, offset)?);
	u64::try_from(address)
		.ok()
		.filter(|&address| address != 0)
		.map(BlockAddress)
		.ok_or(Error::InvalidObjectMap)
}

fn validate_footer(
	footer: &[u8],
	geometry: Geometry,
	level: u16,
	count: usize,
) -> Result<(), Error> {
	const FLAGS: usize = 0;
	const NODE_SIZE: usize = 4;
	const KEY_SIZE: usize = 8;
	const VALUE_SIZE: usize = 12;
	const LONGEST_KEY: usize = 16;
	const LONGEST_VALUE: usize = 20;
	const TOTAL_KEYS: usize = 24;
	const TOTAL_NODES: usize = 32;

	let flags = u32_at(footer, FLAGS)?;
	if flags & PHYSICAL_TREE_FLAG == 0 || flags & !KNOWN_TREE_FLAGS != 0 {
		return Err(Error::UnsupportedObjectMapFlags(flags));
	}
	let keys = u64_at(footer, TOTAL_KEYS)?;
	let nodes = u64_at(footer, TOTAL_NODES)?;
	let longest_key = u32_at(footer, LONGEST_KEY)? as usize;
	let longest_value = u32_at(footer, LONGEST_VALUE)? as usize;
	if u32_at(footer, NODE_SIZE)? != geometry.block_bytes()
		|| u32_at(footer, KEY_SIZE)? as usize != KEY_BYTES
		|| u32_at(footer, VALUE_SIZE)? as usize != VALUE_BYTES
		|| nodes > geometry.block_count()
		|| (level == 0 && (keys != count as u64 || nodes != 1))
		|| (level != 0 && (keys < count as u64 || nodes <= u64::from(level)))
		|| (keys != 0 && (longest_key != KEY_BYTES || longest_value != VALUE_BYTES))
		|| (keys == 0 && (longest_key > KEY_BYTES || longest_value > VALUE_BYTES))
	{
		return Err(Error::InvalidObjectMap);
	}
	Ok(())
}

fn claim(occupied: &mut [u64; OCCUPANCY_WORDS], start: usize, bytes: usize) -> Result<(), Error> {
	let first = start / RECORD_ALIGNMENT;
	for unit in first..first + bytes / RECORD_ALIGNMENT {
		let word = &mut occupied[unit / ALIGNMENTS_PER_WORD];
		let mask = 1 << (unit % ALIGNMENTS_PER_WORD);
		if *word & mask != 0 {
			return Err(Error::InvalidObjectMap);
		}
		*word |= mask;
	}
	Ok(())
}
