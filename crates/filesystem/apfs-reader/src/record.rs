extern crate alloc;

use alloc::string::String;

use apfs_format::object::ObjectId;

use crate::{
	Corruption, Error, Unsupported,
	wire::{U16_BYTES, U64_BYTES, bytes, u16_at, u32_at, u64_at},
};

const OBJECT_TYPE_SHIFT: u32 = 60;
const OBJECT_ID_MASK: u64 = (1 << OBJECT_TYPE_SHIFT) - 1;
const SYSTEM_ID_MIN: u64 = 0x0fff_ffff_0000_0000;
const PRIVATE_DIRECTORY_ID: InodeId = InodeId(3);
const INODE_RECORD: u8 = 3;
const XATTR_RECORD: u8 = 4;
const SIBLING_LINK_RECORD: u8 = 5;
const DATA_STREAM_ID_RECORD: u8 = 6;
const FILE_EXTENT_RECORD: u8 = 8;
const DIRECTORY_RECORD: u8 = 9;
const SIBLING_MAP_RECORD: u8 = 12;
const INODE_PARENT: usize = 0;
const INODE_STREAM_ID: usize = 8;
const INODE_CREATED: usize = 16;
const INODE_MODIFIED: usize = 24;
const INODE_CHANGED: usize = 32;
const INODE_ACCESSED: usize = 40;
const INODE_FLAGS: usize = 48;
pub(crate) const INODE_HAS_FINDER_INFO: u64 = 1 << 8;
pub(crate) const INODE_IS_SPARSE: u64 = 1 << 9;
pub(crate) const INODE_HAS_RESOURCE_FORK: u64 = 1 << 14;
pub(crate) const INODE_NO_RESOURCE_FORK: u64 = 1 << 15;
const INODE_DIRECTORY_COUNT_OR_LINKS: usize = 56;
const INODE_BSD_FLAGS: usize = 68;
const INODE_OWNER: usize = 72;
const INODE_GROUP: usize = 76;
const INODE_MODE: usize = 80;
const INODE_BYTES: usize = 92;
const ENTRY_ID: usize = 0;
const ENTRY_ADDED: usize = 8;
const ENTRY_FLAGS: usize = 16;
const ENTRY_BYTES: usize = 18;
const HASHED_NAME_LENGTH_MASK: u32 = (1 << 10) - 1;
const HASHED_NAME_HASH_SHIFT: u32 = 10;
const HASHED_NAME_OFFSET: usize = 12;
const PLAIN_NAME_OFFSET: usize = 10;
const TYPE_MASK: u16 = 0xF;
const MODE_TYPE_SHIFT: u32 = 12;
const TYPE_DIRECTORY: u16 = 4;
const TYPE_REGULAR: u16 = 8;
const TYPE_SYMLINK: u16 = 10;
const XFIELD_HEADER_BYTES: usize = 4;
const XFIELD_DESCRIPTOR_BYTES: usize = 4;
const XFIELD_FLAGS_OFFSET: usize = 1;
const XFIELD_LENGTH_OFFSET: usize = 2;
const XFIELD_NAME: u8 = 4;
const XFIELD_FINDER_INFO: u8 = 7;
const XFIELD_DATA_STREAM: u8 = 8;
const XFIELD_SPARSE_BYTES: u8 = 13;
const DREC_XFIELD_SIBLING_ID: u8 = 1;
const DATA_STREAM_BYTES: usize = 5 * U64_BYTES;
const STREAM_SIZE: usize = 0;
const STREAM_ALLOCATED: usize = 8;
const STREAM_CRYPTO_ID: usize = 16;
pub(crate) const FINDER_INFO_BYTES: usize = 32;

/// An inode number interpreted within one APFS volume.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InodeId(u64);

impl InodeId {
	/// Inode of the user-visible root directory of an ordinary APFS volume.
	pub const ROOT: Self = Self(2);
	pub(crate) const ROOT_PARENT: Self = Self(1);

	/// Admits a raw inode number below the reserved system object range.
	#[must_use]
	pub const fn from_raw(id: u64) -> Option<Self> {
		if id >= Self::ROOT.0 && id < SYSTEM_ID_MIN {
			Some(Self(id))
		} else {
			None
		}
	}

	/// The on-disk inode number.
	#[must_use]
	pub const fn as_raw(self) -> u64 {
		self.0
	}
}

/// Object kind indicated by an inode's mode or directory record's type field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FileKind {
	Directory,
	Regular,
	Symlink,
	Other(u16),
}

impl FileKind {
	fn from_type(file_type: u16) -> Self {
		match file_type {
			TYPE_DIRECTORY => Self::Directory,
			TYPE_REGULAR => Self::Regular,
			TYPE_SYMLINK => Self::Symlink,
			other => Self::Other(other),
		}
	}
}

/// On-disk timestamps in nanoseconds since the Unix epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Times {
	pub created: u64,
	pub modified: u64,
	pub changed: u64,
	pub accessed: u64,
}

/// The interpretation of the APFS inode count field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum InodeCount {
	Children(u32),
	Links(u32),
}

/// Raw data-stream sizes in bytes. Reading the data requires separate extent
/// and compression validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct StreamSizes {
	pub logical_bytes: u64,
	pub allocated_bytes: u64,
	/// On-disk stream encryption-key or tweak identifier.
	pub default_crypto_id: u64,
}

/// Checked inode metadata in the selected view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Inode {
	pub id: InodeId,
	/// The primary parent. The root and private directory use a sentinel.
	pub parent: Option<InodeId>,
	pub data_stream_id: ObjectId,
	pub kind: FileKind,
	pub count: InodeCount,
	pub times: Times,
	pub owner: u32,
	pub group: u32,
	/// Raw POSIX mode including file type.
	pub mode: u16,
	pub bsd_flags: u32,
	pub internal_flags: u64,
	pub stream: Option<StreamSizes>,
	pub(crate) sparse: Option<SparseField>,
	pub(crate) other_data_field: Option<u8>,
	pub(crate) finder_info: Option<[u8; FINDER_INFO_BYTES]>,
}

impl Inode {
	/// The inode's declared sparse byte count, when present.
	#[must_use]
	pub const fn sparse_bytes(&self) -> Option<u64> {
		match self.sparse {
			Some(field) => Some(field.bytes),
			None => None,
		}
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SparseField {
	pub(crate) bytes: u64,
	pub(crate) flags: u8,
}

/// One directory record. Its target is volume-local, and filesystem metadata
/// validation of the target is performed separately by `stat` or lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DirectoryEntry {
	/// Exact UTF-8 name as stored on disk.
	pub name: String,
	pub inode: InodeId,
	pub kind: FileKind,
	/// Stored name hash on volumes with hashed keys.
	pub name_hash: Option<u32>,
	/// Nanoseconds since the Unix epoch.
	pub added: u64,
	/// Sibling identifier when explicitly present in a hard-link directory record.
	pub sibling: Option<ObjectId>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct Prefix {
	id: ObjectId,
	kind: u8,
}

impl Prefix {
	pub(crate) fn decode(key: &[u8]) -> Result<Self, Corruption> {
		let raw = u64_at(key, 0)?;
		let id = ObjectId(raw & OBJECT_ID_MASK);
		if id.0 == 0 {
			return Err(Corruption::RecordKey);
		}
		Ok(Self {
			id,
			kind: (raw >> OBJECT_TYPE_SHIFT) as u8,
		})
	}

	pub(crate) const fn inode(id: InodeId) -> Self {
		Self {
			id: ObjectId(id.0),
			kind: INODE_RECORD,
		}
	}

	pub(crate) const fn directory(id: InodeId) -> Self {
		Self {
			id: ObjectId(id.0),
			kind: DIRECTORY_RECORD,
		}
	}

	pub(crate) const fn xattrs(id: InodeId) -> Self {
		Self {
			id: ObjectId(id.0),
			kind: XATTR_RECORD,
		}
	}

	pub(crate) const fn data_stream(id: ObjectId) -> Self {
		Self {
			id,
			kind: DATA_STREAM_ID_RECORD,
		}
	}

	pub(crate) const fn sibling_links(id: InodeId) -> Self {
		Self {
			id: ObjectId(id.0),
			kind: SIBLING_LINK_RECORD,
		}
	}

	pub(crate) const fn sibling_map(id: ObjectId) -> Self {
		Self {
			id,
			kind: SIBLING_MAP_RECORD,
		}
	}

	pub(crate) const fn file_extents(id: ObjectId) -> Self {
		Self {
			id,
			kind: FILE_EXTENT_RECORD,
		}
	}
}

pub(crate) fn inode(id: InodeId, key: &[u8], value: &[u8]) -> Result<Inode, Corruption> {
	if key.len() != U64_BYTES || value.len() < INODE_BYTES {
		return Err(Corruption::RecordValue);
	}
	let raw_parent = u64_at(value, INODE_PARENT)?;
	let parent = match (id, InodeId(raw_parent)) {
		(InodeId::ROOT | PRIVATE_DIRECTORY_ID, InodeId::ROOT_PARENT) => None,
		(InodeId::ROOT, _) => return Err(Corruption::RootInode),
		(_, _) if raw_parent == id.as_raw() => return Err(Corruption::RecordValue),
		(_, InodeId::ROOT_PARENT) => return Err(Corruption::RecordValue),
		_ => Some(InodeId::from_raw(raw_parent).ok_or(Corruption::RecordValue)?),
	};
	let data_stream_id = ObjectId(u64_at(value, INODE_STREAM_ID)?);
	if data_stream_id.0 == 0 || data_stream_id.0 > OBJECT_ID_MASK {
		return Err(Corruption::RecordValue);
	}

	let mode = u16_at(value, INODE_MODE)?;
	let kind = FileKind::from_type((mode >> MODE_TYPE_SHIFT) & TYPE_MASK);
	let count = u32_at(value, INODE_DIRECTORY_COUNT_OR_LINKS)?;
	if i32::try_from(count).is_err() {
		return Err(Corruption::RecordValue);
	}
	let count = if kind == FileKind::Directory {
		InodeCount::Children(count)
	} else {
		InodeCount::Links(count)
	};
	let mut stream = None;
	let mut sparse = None;
	let mut other_data_field = None;
	let mut finder_info = None;
	xfields(&value[INODE_BYTES..], |tag, flags, data| {
		match tag {
			XFIELD_NAME => {
				decode_name(data)?;
			}
			XFIELD_DATA_STREAM => stream = Some(stream_sizes(data, Corruption::ExtendedFields)?),
			XFIELD_SPARSE_BYTES if data.len() == U64_BYTES => {
				sparse = Some(SparseField {
					bytes: u64_at(data, 0)?,
					flags,
				});
			}
			XFIELD_SPARSE_BYTES => return Err(Corruption::ExtendedFields),
			XFIELD_FINDER_INFO => {
				finder_info = Some(data.try_into().map_err(|_| Corruption::ExtendedFields)?);
			}
			_ => {
				other_data_field.get_or_insert(tag);
			}
		}
		Ok(())
	})?;

	Ok(Inode {
		id,
		parent,
		data_stream_id,
		kind,
		count,
		mode,
		stream,
		sparse,
		other_data_field,
		finder_info,
		times: Times {
			created: u64_at(value, INODE_CREATED)?,
			modified: u64_at(value, INODE_MODIFIED)?,
			changed: u64_at(value, INODE_CHANGED)?,
			accessed: u64_at(value, INODE_ACCESSED)?,
		},
		owner: u32_at(value, INODE_OWNER)?,
		group: u32_at(value, INODE_GROUP)?,
		bsd_flags: u32_at(value, INODE_BSD_FLAGS)?,
		internal_flags: u64_at(value, INODE_FLAGS)?,
	})
}

pub(crate) fn stream_sizes(data: &[u8], invalid: Corruption) -> Result<StreamSizes, Corruption> {
	if data.len() != DATA_STREAM_BYTES {
		return Err(invalid);
	}
	Ok(StreamSizes {
		logical_bytes: u64_at(data, STREAM_SIZE)?,
		allocated_bytes: u64_at(data, STREAM_ALLOCATED)?,
		default_crypto_id: u64_at(data, STREAM_CRYPTO_ID)?,
	})
}

pub(crate) struct DirectoryRecord<'a> {
	pub(crate) name: &'a str,
	pub(crate) inode: InodeId,
	pub(crate) kind: FileKind,
	pub(crate) name_hash: Option<u32>,
	pub(crate) added: u64,
	pub(crate) sibling: Option<ObjectId>,
}

impl DirectoryRecord<'_> {
	pub(crate) fn into_owned<E>(self) -> Result<DirectoryEntry, Error<E>> {
		let mut name = String::new();
		name.try_reserve_exact(self.name.len())
			.map_err(|_| Error::Allocation)?;
		name.push_str(self.name);
		Ok(DirectoryEntry {
			name,
			inode: self.inode,
			kind: self.kind,
			name_hash: self.name_hash,
			added: self.added,
			sibling: self.sibling,
		})
	}
}

pub(crate) fn directory<'a, E>(
	key: &'a [u8],
	value: &[u8],
	hashed: bool,
) -> Result<DirectoryRecord<'a>, Error<E>> {
	let (offset, length, name_hash) = if hashed {
		let fields = u32_at(key, U64_BYTES)?;
		(
			HASHED_NAME_OFFSET,
			(fields & HASHED_NAME_LENGTH_MASK) as usize,
			Some(fields >> HASHED_NAME_HASH_SHIFT),
		)
	} else {
		(
			PLAIN_NAME_OFFSET,
			usize::from(u16_at(key, U64_BYTES)?),
			None,
		)
	};
	if key.len() != offset + length || value.len() < ENTRY_BYTES {
		return Err(Corruption::RecordValue.into());
	}
	let name = decode_name(&key[offset..])?;
	let inode = InodeId::from_raw(u64_at(value, ENTRY_ID)?).ok_or(Corruption::DirectoryTarget)?;
	let flags = u16_at(value, ENTRY_FLAGS)?;
	if flags & !TYPE_MASK != 0 {
		return Err(Unsupported::DirectoryEntryFlags(flags).into());
	}
	let mut sibling = None;
	xfields(&value[ENTRY_BYTES..], |tag, _, data| {
		if tag != DREC_XFIELD_SIBLING_ID {
			return Err(Unsupported::DirectoryExtendedField(tag).into());
		}
		if data.len() != U64_BYTES {
			return Err(Corruption::ExtendedFields.into());
		}
		let id = u64_at(data, 0)?;
		if InodeId::from_raw(id).is_none() {
			return Err(Corruption::ExtendedFields.into());
		}
		sibling = Some(ObjectId(id));
		Ok::<_, Error<E>>(())
	})?;
	Ok(DirectoryRecord {
		name,
		inode,
		kind: FileKind::from_type(flags),
		name_hash,
		added: u64_at(value, ENTRY_ADDED)?,
		sibling,
	})
}

pub(crate) fn valid_name(name: &str) -> bool {
	!name.is_empty()
		&& name.len() < HASHED_NAME_LENGTH_MASK as usize
		&& !matches!(name, "." | "..")
		&& !name.as_bytes().iter().any(|&byte| matches!(byte, 0 | b'/'))
}

pub(crate) fn decode_name(data: &[u8]) -> Result<&str, Corruption> {
	let name = data.strip_suffix(&[0]).ok_or(Corruption::RecordKey)?;
	let name = core::str::from_utf8(name).map_err(|_| Corruption::RecordKey)?;
	if !valid_name(name) {
		return Err(Corruption::RecordKey);
	}
	Ok(name)
}

fn xfields<E: From<Corruption>>(
	data: &[u8],
	mut emit: impl FnMut(u8, u8, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
	if data.is_empty() {
		return Ok(());
	}
	let count = usize::from(u16_at(data, 0)?);
	let padded_value_bytes = usize::from(u16_at(data, U16_BYTES)?);
	let descriptors_end = XFIELD_HEADER_BYTES + count * XFIELD_DESCRIPTOR_BYTES;
	// The macOS 14.7.2 fixtures count padded values in xf_used_data.
	if data.len() != descriptors_end + padded_value_bytes {
		return Err(Corruption::ExtendedFields.into());
	}
	let mut seen = [false; 1 << u8::BITS];
	let mut next_value = descriptors_end;
	for index in 0..count {
		let at = XFIELD_HEADER_BYTES + index * XFIELD_DESCRIPTOR_BYTES;
		let tag = *data.get(at).ok_or(Corruption::ExtendedFields)?;
		if core::mem::replace(&mut seen[usize::from(tag)], true) {
			return Err(Corruption::ExtendedFields.into());
		}
		let flags = *data
			.get(at + XFIELD_FLAGS_OFFSET)
			.ok_or(Corruption::ExtendedFields)?;
		let length = usize::from(u16_at(data, at + XFIELD_LENGTH_OFFSET)?);
		emit(tag, flags, bytes(data, next_value, length)?)?;
		next_value += length.next_multiple_of(U64_BYTES);
	}
	if next_value != data.len() {
		return Err(Corruption::ExtendedFields.into());
	}
	Ok(())
}
