use alloc::vec::Vec;
use core::ops::Range;

use apfs_format::{
	object::{HEADER_BYTES, Header, ObjectId},
	superblock::Geometry,
};

use crate::{
	Corruption, Error, Unsupported,
	record::Prefix,
	wire::{U16_BYTES, U64_BYTES, u16_at, u32_at, u64_at},
};

pub(crate) const BTREE_ROOT_KIND: u16 = 2;
pub(crate) const BTREE_NODE_KIND: u16 = 3;
pub(crate) const FILESYSTEM_SUBTYPE: u32 = 14;
const FLAGS: usize = HEADER_BYTES;
const LEVEL: usize = 34;
const COUNT: usize = 36;
const TABLE: usize = 40;
const FREE: usize = 44;
const KEY_FREE_LIST: usize = 48;
const VALUE_FREE_LIST: usize = 52;
const DATA: usize = 56;
const FOOTER_BYTES: usize = 40;
const TOC_ENTRY_BYTES: usize = 4 * U16_BYTES;
const LOCATION_BYTES: usize = 2 * U16_BYTES;
const ROOT: u16 = 1;
const LEAF: u16 = 1 << 1;
const UINT64_KEYS_HINT: u32 = 1;
const SEQUENTIAL_INSERT_HINT: u32 = 1 << 1;
const NONALIGNED: u32 = 1 << 6;
const SUPPORTED_TREE_FLAGS: u32 = UINT64_KEYS_HINT | SEQUENTIAL_INSERT_HINT | NONALIGNED;
const INVALID_OFFSET: u16 = u16::MAX;
const KEY_ALIGNMENT: usize = U64_BYTES;
const OCCUPANCY_WORD_BITS: usize = u64::BITS as usize;

#[derive(Clone, Copy, Debug)]
pub(crate) struct TreeInfo {
	aligned: bool,
	max_key: usize,
	max_value: usize,
	pub(crate) nodes: u64,
}

impl TreeInfo {
	fn decode(
		footer: &[u8],
		geometry: Geometry,
		level: u16,
		count: usize,
	) -> Result<Self, TreeInfoError> {
		const FOOTER_FLAGS: usize = 0;
		const NODE_BYTES: usize = 4;
		const FIXED_KEY_BYTES: usize = 8;
		const FIXED_VALUE_BYTES: usize = 12;
		const LONGEST_KEY: usize = 16;
		const LONGEST_VALUE: usize = 20;
		const TOTAL_KEYS: usize = 24;
		const TOTAL_NODES: usize = 32;

		let flags = u32_at(footer, FOOTER_FLAGS)?;
		if flags & !SUPPORTED_TREE_FLAGS != 0 {
			return Err(TreeInfoError::Flags(flags));
		}
		let max_key = u32_at(footer, LONGEST_KEY)? as usize;
		let max_value = u32_at(footer, LONGEST_VALUE)? as usize;
		let keys = u64_at(footer, TOTAL_KEYS)?;
		let nodes = u64_at(footer, TOTAL_NODES)?;
		let block_bytes = geometry.block_bytes();
		if u32_at(footer, NODE_BYTES)? != block_bytes
			|| u32_at(footer, FIXED_KEY_BYTES)? != 0
			|| u32_at(footer, FIXED_VALUE_BYTES)? != 0
			|| max_key > block_bytes as usize
			|| max_value > block_bytes as usize
			|| nodes > geometry.block_count()
			|| (level == 0 && (nodes != 1 || keys != count as u64))
			|| (level != 0 && (nodes <= u64::from(level) || keys < count as u64))
		{
			return Err(Corruption::NodeDescriptor.into());
		}
		Ok(Self {
			aligned: flags & NONALIGNED == 0,
			max_key,
			max_value,
			nodes,
		})
	}
}

enum TreeInfoError {
	Corrupt(Corruption),
	Flags(u32),
}

impl From<Corruption> for TreeInfoError {
	fn from(error: Corruption) -> Self {
		Self::Corrupt(error)
	}
}

pub(crate) struct Slot<'block> {
	pub(crate) key: &'block [u8],
	pub(crate) value: &'block [u8],
}

pub(crate) struct Node<'block> {
	bytes: &'block [u8],
	info: TreeInfo,
	table: Range<usize>,
	keys: Range<usize>,
	values: Range<usize>,
	count: usize,
	pub(crate) level: u16,
}

impl<'block> Node<'block> {
	/// Opens one already checksummed and identity-checked virtual tree object.
	pub(crate) fn decode<E>(
		bytes: &'block [u8],
		header: Header,
		geometry: Geometry,
		parent_info: Option<TreeInfo>,
	) -> Result<Self, Error<E>> {
		if bytes.len() != geometry.block_bytes() as usize {
			return Err(Corruption::NodeSize.into());
		}
		let root = parent_info.is_none();
		let kind = if root {
			BTREE_ROOT_KIND
		} else {
			BTREE_NODE_KIND
		};
		if header.object_type != u32::from(kind) || header.subtype != FILESYSTEM_SUBTYPE {
			return Err(Corruption::NodeDescriptor.into());
		}

		let level = u16_at(bytes, LEVEL)?;
		let flags = u16_at(bytes, FLAGS)?;
		let expected_flags = if root { ROOT } else { 0 } | if level == 0 { LEAF } else { 0 };
		if flags != expected_flags {
			return Err(Unsupported::NodeFlags(flags).into());
		}

		let count = u32_at(bytes, COUNT)? as usize;
		if count == 0 {
			return Err(Corruption::NodeDescriptor.into());
		}
		let (values_end, info) = match parent_info {
			Some(info) => (bytes.len(), info),
			None => {
				let (content, footer) = bytes
					.split_at_checked(bytes.len().saturating_sub(FOOTER_BYTES))
					.ok_or(Corruption::Truncated)?;
				let info =
					TreeInfo::decode(footer, geometry, level, count).map_err(
						|error| match error {
							TreeInfoError::Corrupt(reason) => Error::Corrupt(reason),
							TreeInfoError::Flags(flags) => {
								Error::Unsupported(Unsupported::TreeFlags(flags))
							}
						},
					)?;
				(content.len(), info)
			}
		};

		let table = location(bytes, TABLE, DATA)?;
		let free = location(bytes, FREE, table.end)?;
		if count > table.len() / TOC_ENTRY_BYTES || free.end > values_end {
			return Err(Corruption::TableOfContents.into());
		}
		let keys = table.end..free.start;
		let values = free.end..values_end;
		validate_free_list_head(bytes, KEY_FREE_LIST, keys.len(), OffsetOrigin::RegionStart)?;
		validate_free_list_head(
			bytes,
			VALUE_FREE_LIST,
			values.len(),
			OffsetOrigin::RegionEnd,
		)?;
		let node = Self {
			bytes,
			info,
			table,
			keys,
			values,
			count,
			level,
		};
		Ok(node)
	}

	pub(crate) const fn info(&self) -> TreeInfo {
		self.info
	}

	pub(crate) const fn len(&self) -> usize {
		self.count
	}

	pub(crate) fn slot(&self, index: usize) -> Result<Slot<'block>, Corruption> {
		let (key, value) = self.ranges(index)?;
		Ok(Slot {
			key: &self.bytes[key],
			value: &self.bytes[value],
		})
	}

	pub(crate) fn prefix(&self, index: usize) -> Result<Prefix, Corruption> {
		Prefix::decode(self.slot(index)?.key)
	}

	fn ranges(&self, index: usize) -> Result<(Range<usize>, Range<usize>), Corruption> {
		if index >= self.count {
			return Err(Corruption::TableOfContents);
		}
		let slot = self.table.start + index * TOC_ENTRY_BYTES;
		let key_rel = usize::from(u16_at(self.bytes, slot)?);
		let key_len = usize::from(u16_at(self.bytes, slot + U16_BYTES)?);
		let value_rel = usize::from(u16_at(self.bytes, slot + 2 * U16_BYTES)?);
		let value_len = usize::from(u16_at(self.bytes, slot + 3 * U16_BYTES)?);
		let key_at = self.keys.start + key_rel;
		let value_at = self
			.values
			.end
			.checked_sub(value_rel)
			.ok_or(Corruption::TableOfContents)?;
		let key = key_at..key_at + key_len;
		let value = value_at..value_at + value_len;
		if key_len < U64_BYTES
			|| key_len > self.info.max_key
			|| (self.level == 0 && (value_len == 0 || value_len > self.info.max_value))
			|| (self.level != 0 && value_len != U64_BYTES)
			|| key.end > self.keys.end
			|| value.start < self.values.start
			|| value.end > self.values.end
			|| (self.info.aligned
				&& !(key_at.is_multiple_of(KEY_ALIGNMENT)
					&& value_at.is_multiple_of(KEY_ALIGNMENT)))
		{
			return Err(Corruption::TableOfContents);
		}
		Ok((key, value))
	}

	pub(crate) fn validate<E>(&self) -> Result<(), Error<E>> {
		let words = self.bytes.len().div_ceil(OCCUPANCY_WORD_BITS);
		let mut occupied = Vec::new();
		occupied
			.try_reserve_exact(words)
			.map_err(|_| Error::Allocation)?;
		occupied.resize(words, 0);
		let mut previous = None;

		for index in 0..self.count {
			let (key, value) = self.ranges(index)?;
			claim(&mut occupied, key.clone())?;
			claim(&mut occupied, value.clone())?;
			let prefix = Prefix::decode(&self.bytes[key])?;
			if previous.is_some_and(|prior| prior > prefix) {
				return Err(Corruption::KeyOrder.into());
			}
			if self.level != 0 {
				child_id(&self.bytes[value])?;
			}
			previous = Some(prefix);
		}
		Ok(())
	}
}

pub(crate) fn child_id(value: &[u8]) -> Result<ObjectId, Corruption> {
	let id = ObjectId(u64_at(value, 0)?);
	if id.0 == 0 {
		return Err(Corruption::Route);
	}
	Ok(id)
}

fn location(bytes: &[u8], offset: usize, base: usize) -> Result<Range<usize>, Corruption> {
	let start = base + usize::from(u16_at(bytes, offset)?);
	let len = usize::from(u16_at(bytes, offset + U16_BYTES)?);
	Ok(start..start + len)
}

enum OffsetOrigin {
	RegionStart,
	RegionEnd,
}

fn validate_free_list_head(
	bytes: &[u8],
	offset: usize,
	region: usize,
	origin: OffsetOrigin,
) -> Result<(), Corruption> {
	let head = u16_at(bytes, offset)?;
	let total = usize::from(u16_at(bytes, offset + U16_BYTES)?);
	let valid = if head == INVALID_OFFSET {
		total <= region
	} else {
		let head = usize::from(head);
		let valid_head = match origin {
			OffsetOrigin::RegionStart => head + LOCATION_BYTES <= region,
			OffsetOrigin::RegionEnd => head >= LOCATION_BYTES && head <= region,
		};
		total >= LOCATION_BYTES && total <= region && valid_head
	};
	if !valid {
		return Err(Corruption::TableOfContents);
	}
	Ok(())
}

fn claim(occupied: &mut [u64], range: Range<usize>) -> Result<(), Corruption> {
	for byte in range {
		let word = &mut occupied[byte / OCCUPANCY_WORD_BITS];
		let bit = 1 << (byte % OCCUPANCY_WORD_BITS);
		if *word & bit != 0 {
			return Err(Corruption::OverlappingRecords);
		}
		*word |= bit;
	}
	Ok(())
}

#[cfg(test)]
mod tests;
