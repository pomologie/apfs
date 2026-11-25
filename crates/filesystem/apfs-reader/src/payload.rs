extern crate alloc;

use alloc::vec::Vec;
use core::ops::Range;

use apfs_container::{Volume, VolumeObjects};
use apfs_core::{ByteOffset, ReadAt};
use apfs_format::{
	object::ObjectId,
	superblock::{Area, AreaLocation, BlockAddress, Geometry, Superblock},
};

use crate::{
	Corruption, Error, FileKind, Inode, InodeId, StreamSizes, Unsupported, VolumeView,
	extent_refs::References,
	node::Slot,
	record::{INODE_HAS_RESOURCE_FORK, INODE_IS_SPARSE, INODE_NO_RESOURCE_FORK, Prefix},
	walk,
	wire::{U64_BYTES, u32_at, u64_at},
	xattr::{COMPRESSION_ATTRIBUTE, SYMLINK_ATTRIBUTE, symlink_bytes},
};

const INODE_WAS_CLONED: u64 = 1 << 4;
const INODE_HAS_SECURITY_EA: u64 = 1 << 6;
const INODE_HAS_FINDER_INFO: u64 = 1 << 8;
const INODE_WAS_EVER_CLONED: u64 = 1 << 10;
const INODE_HAS_UNCOMPRESSED_SIZE: u64 = 1 << 18;
const SUPPORTED_INODE_DATA_FLAGS: u64 = INODE_HAS_SECURITY_EA
	| INODE_HAS_FINDER_INFO
	| INODE_IS_SPARSE
	| INODE_HAS_RESOURCE_FORK
	| INODE_NO_RESOURCE_FORK;
const XFIELD_CHILDREN_INHERIT: u8 = 1 << 3;
const XFIELD_SYSTEM_FIELD: u8 = 1 << 5;
const SPARSE_FIELD_FLAGS: u8 = XFIELD_CHILDREN_INHERIT | XFIELD_SYSTEM_FIELD;
const BSD_COMPRESSED: u32 = 1 << 5;
const DATA_STREAM_REFCOUNT_BYTES: usize = size_of::<u32>();
const UNSHARED_REFCOUNT: u32 = 1;
const EXTENT_FLAGS_SHIFT: u32 = 56;
const EXTENT_LENGTH_MASK: u64 = (1 << EXTENT_FLAGS_SHIFT) - 1;
const EXTENT_KEY_BYTES: usize = 2 * U64_BYTES;
const EXTENT_VALUE_BYTES: usize = 3 * U64_BYTES;
const EXTENT_BLOCK_OFFSET: usize = U64_BYTES;
const EXTENT_CRYPTO_OFFSET: usize = 2 * U64_BYTES;
const HOLE_BLOCK: BlockAddress = BlockAddress(0);

#[derive(Clone, Copy, Debug)]
pub(crate) struct ReservedBlocks {
	container_map: BlockAddress,
	checkpoint_descriptors: Area,
	checkpoint_data: Area,
}

impl ReservedBlocks {
	pub(crate) fn from_superblock(checkpoint: &Superblock) -> Self {
		Self {
			container_map: checkpoint.object_map,
			checkpoint_descriptors: checkpoint.descriptors,
			checkpoint_data: checkpoint.data,
		}
	}

	fn contains_metadata(
		self,
		blocks: &Range<u64>,
		volume: &Volume,
		root_mapping: &Range<u64>,
	) -> bool {
		let trees = volume.superblock.trees;
		let protected = [
			BlockAddress(0),
			self.container_map,
			volume.mapping.address,
			trees.object_map,
			trees.extent_references,
			trees.snapshot_metadata,
		];
		protected.iter().any(|address| blocks.contains(&address.0))
			|| (blocks.start < root_mapping.end && root_mapping.start < blocks.end)
			|| overlaps_area(blocks, self.checkpoint_descriptors)
			|| overlaps_area(blocks, self.checkpoint_data)
	}
}

fn overlaps_area(blocks: &Range<u64>, area: Area) -> bool {
	match area.location {
		AreaLocation::Contiguous(address) => {
			// The selected checkpoint already bounds the entire contiguous ring.
			let end = address.0 + u64::from(area.blocks);
			blocks.start < end && address.0 < blocks.end
		}
		AreaLocation::FragmentTree(_) => true,
	}
}

#[derive(Debug)]
struct Extent {
	logical: Range<u64>,
	// An absent physical address represents an admitted explicit hole.
	physical: Option<u64>,
}

/// Exact data for an admitted ordinary APFS file in one immutable volume view.
#[derive(Debug)]
pub struct FileData<'view, 'source, S> {
	objects: &'view mut VolumeObjects<'source, S>,
	extents: Vec<Extent>,
	length: u64,
}

impl<S: ReadAt> FileData<'_, '_, S> {
	/// The logical file length in bytes.
	#[must_use]
	pub const fn len(&self) -> u64 {
		self.length
	}

	/// Whether this is an empty file.
	#[must_use]
	pub const fn is_empty(&self) -> bool {
		self.length == 0
	}

	pub(crate) fn physical_ranges(&self) -> impl Iterator<Item = Range<u64>> + '_ {
		self.extents.iter().filter_map(|extent| {
			let length = extent.logical.end - extent.logical.start;
			let physical = extent.physical?;
			Some(physical..physical + length)
		})
	}

	/// Fills the destination from the specified file byte offset. Empty reads
	/// at EOF succeed. Physical reads share the volume's aggregate I/O budget.
	///
	/// # Errors
	/// Out-of-range or overflowing file offsets, exhausted budgets, and source
	/// errors fail the operation. Read failures may leave a partially filled
	/// destination.
	pub fn read_exact_at(
		&mut self,
		offset: ByteOffset,
		mut destination: &mut [u8],
	) -> Result<(), Error<S::Error>> {
		checked_read_end(offset, destination.len(), self.length)?;
		let mut logical = offset.0;
		let first = self
			.extents
			.partition_point(|extent| extent.logical.end <= logical);
		for extent in &self.extents[first..] {
			if destination.is_empty() {
				break;
			}
			let take = (extent.logical.end - logical).min(destination.len() as u64) as usize;
			let (head, tail) = destination.split_at_mut(take);
			// Admission established complete logical coverage and in-container physical bytes.
			if let Some(physical) = extent.physical {
				let offset = physical + (logical - extent.logical.start);
				self.objects.read_physical_at(ByteOffset(offset), head)?;
			} else {
				head.fill(0);
			}
			logical += take as u64;
			destination = tail;
		}
		if !destination.is_empty() {
			return Err(Corruption::ExtentCoverage.into());
		}
		Ok(())
	}
}

impl<'source, S: ReadAt> VolumeView<'source, S> {
	/// Opens an ordinary regular file for exact byte reads in this view.
	/// The extent records must cover the stream continuously. Mapped extents
	/// must be unshared and owned by the declared data stream. Explicit holes
	/// require matching sparse inode metadata and read as zeroes.
	/// A missing inode returns `None`.
	///
	/// # Errors
	/// Rejects unsupported inode, stream, compression, sparse or extent states,
	/// inconsistent ownership, corrupt layout, source errors, or exhausted budgets.
	pub fn open_file(
		&mut self,
		id: InodeId,
	) -> Result<Option<FileData<'_, 'source, S>>, Error<S::Error>> {
		let Some(inode) = self.stat(id)? else {
			return Ok(None);
		};
		if inode.kind != FileKind::Regular {
			return Err(Error::NotRegularFile);
		}
		validate_inode(inode)?;
		if self
			.with_xattr(id, COMPRESSION_ATTRIBUTE, |_| Ok(()))?
			.is_some()
		{
			return Err(Unsupported::CompressedData.into());
		}
		self.open_stream(
			StreamKind::File {
				id: inode.data_stream_id,
				sparse_bytes: inode.sparse_bytes(),
			},
			inode.stream.unwrap_or(StreamSizes {
				logical_bytes: 0,
				allocated_bytes: 0,
				default_crypto_id: 0,
			}),
		)
		.map(Some)
	}

	pub(crate) fn open_stream(
		&mut self,
		kind: StreamKind,
		stream: StreamSizes,
	) -> Result<FileData<'_, 'source, S>, Error<S::Error>> {
		if stream.default_crypto_id != 0 {
			return Err(Unsupported::EncryptedData.into());
		}
		let StreamSizes {
			logical_bytes: length,
			allocated_bytes: allocated,
			..
		} = stream;
		let (id, owner, sparse_bytes) = match kind {
			StreamKind::File { id, sparse_bytes } => (id, id, sparse_bytes),
			StreamKind::Xattr { id, owner } => (id, owner, None),
		};
		// In the qualified sparse layout, the stream span includes explicit holes and EOF padding.
		let block_bytes = u64::from(self.geometry.block_bytes());
		if length > allocated
			|| !allocated.is_multiple_of(block_bytes)
			|| sparse_bytes
				.is_some_and(|bytes| bytes > allocated || !bytes.is_multiple_of(block_bytes))
		{
			return Err(Corruption::ExtentCoverage.into());
		}
		self.validate_data_stream(id, kind, allocated)?;
		let mut extents = self.file_extents(id, allocated, sparse_bytes)?;
		if extents.iter().any(|extent| extent.physical.is_some()) {
			self.verify_extent_references(owner, &mut extents)?;
		}
		Ok(FileData {
			objects: &mut self.objects,
			extents,
			length,
		})
	}

	/// Reads the exact target bytes stored for an inline symbolic link. A
	/// missing inode returns `None`. The target is returned as stored.
	///
	/// # Errors
	/// A non-link inode, corrupt or missing target record, unsupported
	/// attribute storage, source error, or exhausted budget fails the read.
	pub fn read_link(&mut self, id: InodeId) -> Result<Option<Vec<u8>>, Error<S::Error>> {
		let Some(inode) = self.stat(id)? else {
			return Ok(None);
		};
		if inode.kind != FileKind::Symlink {
			return Err(Error::NotSymlink);
		}
		validate_inode(inode)?;
		let target = self
			.with_xattr(id, SYMLINK_ATTRIBUTE, symlink_bytes)?
			.ok_or(Corruption::SymlinkRecord)?;
		Ok(Some(target))
	}

	fn validate_data_stream(
		&mut self,
		id: ObjectId,
		kind: StreamKind,
		allocated: u64,
	) -> Result<(), Error<S::Error>> {
		let mut seen = false;
		walk::scan(
			&mut self.objects,
			self.geometry,
			Prefix::data_stream(id),
			self.limits,
			|slot| {
				if seen
					|| slot.key.len() != U64_BYTES
					|| slot.value.len() != DATA_STREAM_REFCOUNT_BYTES
				{
					return Err(Corruption::StreamRecord.into());
				}
				let count = u32_at(slot.value, 0)?;
				if count == 0 {
					return Err(Corruption::StreamRecord.into());
				}
				if count > UNSHARED_REFCOUNT {
					return Err(Unsupported::SharedData.into());
				}
				seen = true;
				Ok(())
			},
		)?;
		match kind {
			StreamKind::File { .. } if allocated != 0 && !seen => {
				return Err(Corruption::StreamRecord.into());
			}
			StreamKind::Xattr { .. } if seen => return Err(Unsupported::XattrStreamRecord.into()),
			_ => {}
		}
		Ok(())
	}

	fn file_extents(
		&mut self,
		id: ObjectId,
		allocated: u64,
		sparse_bytes: Option<u64>,
	) -> Result<Vec<Extent>, Error<S::Error>> {
		let mut logical = 0;
		let mut remaining_sparse = sparse_bytes.unwrap_or_default();
		let mut extents = Vec::new();
		let geometry = self.geometry;
		walk::scan(
			&mut self.objects,
			geometry,
			Prefix::file_extents(id),
			self.limits,
			|slot| {
				let extent = file_extent(slot, geometry, sparse_bytes.is_some())?;
				if extent.logical.start != logical || extent.logical.end > allocated {
					return Err(Corruption::ExtentCoverage.into());
				}
				if extent.physical.is_none() {
					remaining_sparse = remaining_sparse
						.checked_sub(extent.logical.end - extent.logical.start)
						.ok_or(Corruption::ExtentCoverage)?;
				}
				logical = extent.logical.end;
				extents.try_reserve(1).map_err(|_| Error::Allocation)?;
				extents.push(extent);
				Ok(())
			},
		)?;
		if logical != allocated || remaining_sparse != 0 {
			return Err(Corruption::ExtentCoverage.into());
		}
		Ok(extents)
	}

	fn verify_extent_references(
		&mut self,
		owner: ObjectId,
		extents: &mut [Extent],
	) -> Result<(), Error<S::Error>> {
		let block_bytes = u64::from(self.geometry.block_bytes());
		let fsroot = self.objects.volume().superblock.trees.root;
		let mapping = self
			.objects
			.lookup_virtual_mapping(fsroot)?
			.ok_or(Corruption::MissingNode(fsroot))?;
		let root = mapping.address.0..mapping.address.0 + u64::from(mapping.size) / block_bytes;
		let mut previous_end = 0;
		extents.sort_unstable_by_key(|extent| extent.physical);
		for blocks in extents
			.iter()
			.filter_map(|extent| extent_blocks(extent, block_bytes))
		{
			if blocks.start < previous_end {
				return Err(Corruption::ExtentCoverage.into());
			}
			if self
				.reserved
				.contains_metadata(&blocks, self.objects.volume(), &root)
			{
				return Err(Corruption::ExtentMetadataAlias.into());
			}
			previous_end = blocks.end;
		}
		let mut references = References::new(&mut self.objects, self.geometry, self.limits);
		for blocks in extents
			.iter()
			.filter_map(|extent| extent_blocks(extent, block_bytes))
		{
			references.verify(blocks, owner)?;
		}
		extents.sort_unstable_by_key(|extent| extent.logical.start);
		Ok(())
	}
}

#[derive(Clone, Copy)]
pub(crate) enum StreamKind {
	File {
		id: ObjectId,
		sparse_bytes: Option<u64>,
	},
	Xattr {
		id: ObjectId,
		owner: ObjectId,
	},
}

pub(crate) fn checked_read_end<E>(
	offset: ByteOffset,
	bytes: usize,
	length: u64,
) -> Result<u64, Error<E>> {
	let bytes = bytes as u64;
	offset
		.0
		.checked_add(bytes)
		.filter(|&end| end <= length)
		.ok_or(Error::FileRange {
			offset: offset.0,
			bytes,
			length,
		})
}

fn validate_inode<E>(inode: Inode) -> Result<(), Error<E>> {
	let flags = inode.internal_flags;
	if flags & (INODE_WAS_CLONED | INODE_WAS_EVER_CLONED) != 0 {
		return Err(Unsupported::SharedData.into());
	}
	let sparse_flag = flags & INODE_IS_SPARSE != 0;
	if sparse_flag != inode.sparse.is_some()
		|| inode.sparse.is_some_and(|field| {
			inode.kind != FileKind::Regular
				|| field.flags != SPARSE_FIELD_FLAGS
				|| inode.stream.is_none()
		}) {
		return Err(Unsupported::SparseData.into());
	}
	if flags & INODE_HAS_UNCOMPRESSED_SIZE != 0 || inode.bsd_flags & BSD_COMPRESSED != 0 {
		return Err(Unsupported::CompressedData.into());
	}
	if inode
		.stream
		.is_some_and(|stream| stream.default_crypto_id != 0)
	{
		return Err(Unsupported::EncryptedData.into());
	}
	if flags & !SUPPORTED_INODE_DATA_FLAGS != 0 {
		return Err(Unsupported::InodeDataFlags(flags).into());
	}
	if let Some(field) = inode.other_data_field {
		return Err(Unsupported::InodeDataField(field).into());
	}
	Ok(())
}

fn file_extent<E>(slot: Slot<'_>, geometry: Geometry, sparse: bool) -> Result<Extent, Error<E>> {
	if slot.key.len() != EXTENT_KEY_BYTES || slot.value.len() != EXTENT_VALUE_BYTES {
		return Err(Corruption::ExtentRecord.into());
	}
	let logical = u64_at(slot.key, U64_BYTES)?;
	let length_flags = u64_at(slot.value, 0)?;
	let flags = (length_flags >> EXTENT_FLAGS_SHIFT) as u8;
	if flags != 0 {
		return Err(Unsupported::ExtentFlags(flags).into());
	}
	let length = length_flags & EXTENT_LENGTH_MASK;
	let block = BlockAddress(u64_at(slot.value, EXTENT_BLOCK_OFFSET)?);
	if block == HOLE_BLOCK && !sparse {
		return Err(Unsupported::SparseData.into());
	}
	if u64_at(slot.value, EXTENT_CRYPTO_OFFSET)? != 0 {
		return Err(Unsupported::EncryptedData.into());
	}
	let block_bytes = u64::from(geometry.block_bytes());
	if length == 0 || !length.is_multiple_of(block_bytes) || !logical.is_multiple_of(block_bytes) {
		return Err(Corruption::ExtentRecord.into());
	}
	let end = logical
		.checked_add(length)
		.ok_or(Corruption::ExtentCoverage)?;
	let physical = if block == HOLE_BLOCK {
		None
	} else {
		Some(
			geometry
				.byte_range(block, length / block_bytes)
				.map_err(Corruption::PhysicalNode)?
				.start,
		)
	};
	Ok(Extent {
		logical: logical..end,
		physical,
	})
}

fn extent_blocks(extent: &Extent, block_bytes: u64) -> Option<Range<u64>> {
	let start = extent.physical? / block_bytes;
	let blocks = (extent.logical.end - extent.logical.start) / block_bytes;
	Some(start..start + blocks)
}
