use alloc::{string::String, vec::Vec};
use core::{cmp::Ordering, num::NonZeroU16};

use apfs_core::{ByteOffset, ReadAt};
use apfs_format::object::ObjectId;

use crate::{
	Corruption, Error, FileData, InodeId, Limit, StreamSizes, Unsupported, ViewIdentity,
	VolumeView,
	payload::{StreamKind, checked_read_end},
	record::{Prefix, stream_sizes},
	walk,
	wire::{U16_BYTES, U64_BYTES, u16_at, u64_at},
};

const XATTR_NAME_OFFSET: usize = U64_BYTES + U16_BYTES;
const XATTR_VALUE_OFFSET: usize = 2 * U16_BYTES;
const DATA_STREAM: u16 = 1;
const EMBEDDED: u16 = 1 << 1;
const FILE_SYSTEM_OWNED: u16 = 1 << 2;
const INLINE_FILESYSTEM_FLAGS: u16 = EMBEDDED | FILE_SYSTEM_OWNED;
// Sonoma sets this otherwise undocumented bit on externally stored user xattrs.
const SONOMA_EXTERNAL_USER_FLAG: u16 = 1 << 4;
const SONOMA_EXTERNAL_USER_FLAGS: u16 = DATA_STREAM | SONOMA_EXTERNAL_USER_FLAG;
const MAX_EMBEDDED_BYTES: usize = 3804;
pub(crate) const COMPRESSION_ATTRIBUTE: &str = "com.apple.decmpfs";
pub(crate) const SYMLINK_ATTRIBUTE: &str = "com.apple.fs.symlink";
const RESOURCE_FORK_ATTRIBUTE: &str = "com.apple.ResourceFork";
const FINDER_INFO_ATTRIBUTE: &str = "com.apple.FinderInfo";

/// How an attribute stores its raw payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum XattrStorage {
	Inline,
	DataStream(ObjectId),
}

/// One stored extended-attribute record, including file-system-owned records.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Xattr {
	/// The exact UTF-8 name recorded on disk.
	pub name: String,
	pub storage: XattrStorage,
	/// The logical size of the payload before any interpretation.
	pub length: u64,
	/// The original storage and ownership flags.
	pub flags: u16,
}

/// Continuation for one inode's attributes in the selected volume checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XattrCursor {
	identity: ViewIdentity,
	inode: InodeId,
	offset: u32,
}

/// Extended-attribute metadata in its on-disk order.
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct XattrPage {
	pub entries: Vec<Xattr>,
	pub next: Option<XattrCursor>,
}

/// Exact stored attribute data, including external resource fork streams.
#[derive(Debug)]
pub struct XattrData<'view, 'source, S>(Data<'view, 'source, S>);

#[derive(Debug)]
enum Data<'view, 'source, S> {
	Inline(Vec<u8>),
	DataStream(FileData<'view, 'source, S>),
}

impl<S: ReadAt> XattrData<'_, '_, S> {
	/// The logical attribute length in bytes.
	#[must_use]
	pub fn len(&self) -> u64 {
		match &self.0 {
			Data::Inline(data) => data.len() as u64,
			Data::DataStream(data) => data.len(),
		}
	}

	/// Whether the attribute is present with a zero-length payload.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// Reads raw bytes at the requested attribute offset. Empty reads at EOF
	/// succeed. External data shares the source I/O budget of the volume view.
	///
	/// # Errors
	/// Returns an error for an invalid range, a source failure, or budget
	/// exhaustion. A source failure may leave a partially filled destination.
	pub fn read_exact_at(
		&mut self,
		offset: ByteOffset,
		destination: &mut [u8],
	) -> Result<(), Error<S::Error>> {
		match &mut self.0 {
			Data::Inline(data) => {
				let end = checked_read_end(offset, destination.len(), data.len() as u64)?;
				destination.copy_from_slice(&data[offset.0 as usize..end as usize]);
				Ok(())
			}
			Data::DataStream(data) => data.read_exact_at(offset, destination),
		}
	}
}

impl<'source, S: ReadAt> VolumeView<'source, S> {
	/// Lists a bounded page of stored extended-attribute records. A missing
	/// inode returns `None`, and an existing inode can have an empty page.
	/// The listing contains on-disk xattr records. External payloads are checked
	/// when opened.
	///
	/// # Errors
	/// Returns errors for an invalid cursor, corrupt records, source failures,
	/// or exhausted limits.
	pub fn list_xattrs(
		&mut self,
		id: InodeId,
		cursor: Option<XattrCursor>,
		limit: NonZeroU16,
	) -> Result<Option<XattrPage>, Error<S::Error>> {
		if limit.get() > self.limits.max_entries_per_page {
			return Err(Error::Limit(Limit::Page));
		}
		let identity = self.identity();
		let start = match cursor {
			Some(cursor) if cursor.identity == identity && cursor.inode == id => cursor.offset,
			Some(_) => return Err(Error::InvalidCursor),
			None => 0,
		};
		if self.stat(id)?.is_none() {
			return Ok(None);
		}
		let mut entries = Vec::new();
		let count = self.scan_xattrs(id, |index, name, value| {
			let (flags, payload) = decode_value(value)?;
			if index >= start && entries.len() < usize::from(limit.get()) {
				let (storage, length) = match payload {
					Payload::Inline(data) => (XattrStorage::Inline, data.len() as u64),
					Payload::DataStream(id, sizes) => {
						(XattrStorage::DataStream(id), sizes.logical_bytes)
					}
				};
				let mut owned = String::new();
				owned
					.try_reserve_exact(name.len())
					.map_err(|_| Error::Allocation)?;
				owned.push_str(name);
				entries.try_reserve(1).map_err(|_| Error::Allocation)?;
				entries.push(Xattr {
					name: owned,
					storage,
					length,
					flags,
				});
			}
			Ok(())
		})?;
		if start > count {
			return Err(Error::InvalidCursor);
		}
		let end = start + entries.len() as u32;
		Ok(Some(XattrPage {
			entries,
			next: (end < count).then_some(XattrCursor {
				identity,
				inode: id,
				offset: end,
			}),
		}))
	}

	/// Opens exact stored bytes for the given UTF-8 attribute name. A missing
	/// inode or attribute returns `None`. Names are matched byte for byte.
	///
	/// # Errors
	/// Invalid names, corrupt records, unsupported attribute or extent states,
	/// source errors and exhausted limits return typed errors.
	pub fn open_xattr(
		&mut self,
		id: InodeId,
		name: &str,
	) -> Result<Option<XattrData<'_, 'source, S>>, Error<S::Error>> {
		if !valid_name(name) {
			return Err(Error::InvalidXattrName);
		}
		let Some(inode) = self.stat(id)? else {
			return Ok(None);
		};
		if name == FINDER_INFO_ATTRIBUTE && inode.has_finder_info_field {
			return Err(Unsupported::InodeFinderInfo.into());
		}
		let Some(data) = self.with_xattr(id, name, |value| {
			let (flags, payload) = decode_value(value)?;
			match payload {
				Payload::Inline(data) if matches!(flags, EMBEDDED | INLINE_FILESYSTEM_FLAGS) => {
					copy_bytes(data).map(OpenData::Inline)
				}
				Payload::DataStream(stream_id, sizes) => {
					let owner = match (name == RESOURCE_FORK_ATTRIBUTE, flags) {
						(true, DATA_STREAM) => ObjectId(id.as_raw()),
						(false, SONOMA_EXTERNAL_USER_FLAGS) => stream_id,
						_ => return Err(Unsupported::XattrStorage(flags).into()),
					};
					if stream_id == inode.data_stream_id || stream_id.0 == id.as_raw() {
						return Err(Corruption::XattrRecord.into());
					}
					Ok(OpenData::External(
						StreamKind::Xattr {
							id: stream_id,
							owner,
						},
						sizes,
					))
				}
				_ => Err(Unsupported::XattrStorage(flags).into()),
			}
		})?
		else {
			return Ok(None);
		};
		let data = match data {
			OpenData::Inline(data) => Data::Inline(data),
			OpenData::External(kind, sizes) => Data::DataStream(self.open_stream(kind, sizes)?),
		};
		Ok(Some(XattrData(data)))
	}

	/// Opens the raw bytes stored as the inode's resource fork.
	///
	/// # Errors
	/// Returns the same storage, source, and limit errors as [`Self::open_xattr`].
	pub fn open_resource_fork(
		&mut self,
		id: InodeId,
	) -> Result<Option<XattrData<'_, 'source, S>>, Error<S::Error>> {
		self.open_xattr(id, RESOURCE_FORK_ATTRIBUTE)
	}

	pub(crate) fn with_xattr<T>(
		&mut self,
		id: InodeId,
		name: &str,
		decode: impl Fn(&[u8]) -> Result<T, Error<S::Error>>,
	) -> Result<Option<T>, Error<S::Error>> {
		let mut found = None;
		self.scan_xattrs(id, |_, stored, value| {
			if stored == name {
				found = Some(decode(value)?);
			}
			Ok(())
		})?;
		Ok(found)
	}

	fn scan_xattrs(
		&mut self,
		id: InodeId,
		mut visit: impl FnMut(u32, &str, &[u8]) -> Result<(), Error<S::Error>>,
	) -> Result<u32, Error<S::Error>> {
		let mut count = 0;
		let mut previous = String::new();
		walk::scan(
			&mut self.objects,
			self.geometry,
			Prefix::xattrs(id),
			self.limits,
			|slot| {
				let name = decode_name(slot.key)?;
				match previous.as_str().cmp(name) {
					Ordering::Equal => return Err(Corruption::DuplicateXattr.into()),
					Ordering::Greater => return Err(Corruption::KeyOrder.into()),
					Ordering::Less => {}
				}
				previous.clear();
				previous
					.try_reserve_exact(name.len())
					.map_err(|_| Error::Allocation)?;
				previous.push_str(name);
				visit(count, name, slot.value)?;
				count += 1;
				Ok(())
			},
		)?;
		Ok(count)
	}
}

enum OpenData {
	Inline(Vec<u8>),
	External(StreamKind, StreamSizes),
}

enum Payload<'a> {
	Inline(&'a [u8]),
	DataStream(ObjectId, StreamSizes),
}

fn valid_name(name: &str) -> bool {
	!name.is_empty() && name.len() < usize::from(u16::MAX) && !name.as_bytes().contains(&0)
}

fn decode_name(bytes: &[u8]) -> Result<&str, Corruption> {
	let length = usize::from(u16_at(bytes, U64_BYTES)?);
	if bytes.len() != XATTR_NAME_OFFSET + length {
		return Err(Corruption::RecordKey);
	}
	let name = bytes[XATTR_NAME_OFFSET..]
		.strip_suffix(&[0])
		.ok_or(Corruption::RecordKey)?;
	let name = core::str::from_utf8(name).map_err(|_| Corruption::RecordKey)?;
	if !valid_name(name) {
		return Err(Corruption::RecordKey);
	}
	Ok(name)
}

fn decode_value(bytes: &[u8]) -> Result<(u16, Payload<'_>), Corruption> {
	let flags = u16_at(bytes, 0)?;
	let length = usize::from(u16_at(bytes, U16_BYTES)?);
	if bytes.len() != XATTR_VALUE_OFFSET + length {
		return Err(Corruption::XattrRecord);
	}
	let data = &bytes[XATTR_VALUE_OFFSET..];
	match flags & (EMBEDDED | DATA_STREAM) {
		EMBEDDED if length <= MAX_EMBEDDED_BYTES => Ok((flags, Payload::Inline(data))),
		DATA_STREAM => {
			let raw_id = u64_at(data, 0)?;
			if InodeId::from_raw(raw_id).is_none() {
				return Err(Corruption::XattrRecord);
			}
			let sizes = stream_sizes(&data[U64_BYTES..], Corruption::XattrRecord)?;
			Ok((flags, Payload::DataStream(ObjectId(raw_id), sizes)))
		}
		_ => Err(Corruption::XattrRecord),
	}
}

fn copy_bytes<E>(bytes: &[u8]) -> Result<Vec<u8>, Error<E>> {
	let mut result = Vec::new();
	result
		.try_reserve_exact(bytes.len())
		.map_err(|_| Error::Allocation)?;
	result.extend_from_slice(bytes);
	Ok(result)
}

pub(crate) fn symlink_bytes<E>(bytes: &[u8]) -> Result<Vec<u8>, Error<E>> {
	let flags = u16_at(bytes, 0)?;
	if flags != INLINE_FILESYSTEM_FLAGS {
		return Err(Unsupported::SymlinkStorage(flags).into());
	}
	let (_, Payload::Inline(target)) =
		decode_value(bytes).map_err(|_| Corruption::SymlinkRecord)?
	else {
		return Err(Corruption::SymlinkRecord.into());
	};
	let target = target.strip_suffix(&[0]).ok_or(Corruption::SymlinkRecord)?;
	if target.is_empty() || target.contains(&0) {
		return Err(Corruption::SymlinkRecord.into());
	}
	copy_bytes(target)
}
