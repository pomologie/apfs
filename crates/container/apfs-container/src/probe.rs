use core::num::NonZeroU64;

use apfs_core::{ByteOffset, ReadAt};
use apfs_format::{
	Error as FormatError,
	superblock::{BLOCK_SIZE_PREFIX_BYTES, BlockAddress, Geometry, Superblock},
};

use crate::{Error, Limit, alloc::vec::Vec};

pub(super) const BLOCK_ZERO: BlockAddress = BlockAddress(0);
const BOOTSTRAP_OFFSET: ByteOffset = ByteOffset(0);
pub(super) const DEFAULT_MAX_OBJECT_BYTES: usize = 16 << 20;
pub(super) const DEFAULT_MAX_READ_BYTES: u64 = 128 << 20;

/// Returns the extent declared by a checksummed block-zero container superblock.
///
/// A source shorter than the block-size prefix or missing NXSB magic returns
/// `Ok(None)`. Recognition reads only the prefix and at most one complete NXSB
/// block. Checkpoint selection, profile admission and volume access are separate.
///
/// # Errors
/// Returns an error on malformed recognized metadata, failed source reads or
/// failure to allocate the bounded superblock buffer.
pub fn probe_extent<S: ReadAt + ?Sized>(source: &S) -> Result<Option<NonZeroU64>, Error<S::Error>> {
	let mut probe = Probe::new(source, DEFAULT_MAX_OBJECT_BYTES, DEFAULT_MAX_READ_BYTES);
	let source_len = probe.source_len();
	if source_len < BLOCK_SIZE_PREFIX_BYTES as u64 {
		return Ok(None);
	}
	let block_bytes = match probe.bootstrap_block_size() {
		Ok(bytes) => bytes,
		Err(Error::Bootstrap(FormatError::InvalidMagic)) => return Ok(None),
		Err(error) => return Err(error),
	};
	if u64::from(block_bytes) > source_len {
		return Err(Error::Bootstrap(FormatError::InvalidGeometry));
	}
	let block = probe.read_bootstrap_block(block_bytes)?;
	let geometry = Superblock::decode(&block, source_len)
		.map_err(Error::Bootstrap)?
		.geometry;
	let range = geometry
		.byte_range(BLOCK_ZERO, geometry.block_count())
		.map_err(Error::Bootstrap)?;
	let extent =
		NonZeroU64::new(range.end).ok_or(Error::Bootstrap(FormatError::InvalidGeometry))?;
	Ok(Some(extent))
}

pub(super) struct Probe<'source, S: ?Sized> {
	source: &'source S,
	max_object_bytes: usize,
	bytes_left: u64,
}

impl<'source, S: ReadAt + ?Sized> Probe<'source, S> {
	pub(super) fn new(source: &'source S, max_object_bytes: usize, max_read_bytes: u64) -> Self {
		Self {
			source,
			max_object_bytes,
			bytes_left: max_read_bytes,
		}
	}

	pub(super) fn source_len(&self) -> u64 {
		self.source.len()
	}

	pub(super) fn bootstrap_block_size(&mut self) -> Result<u32, Error<S::Error>> {
		let mut prefix = [0; BLOCK_SIZE_PREFIX_BYTES];
		self.read_exact(BOOTSTRAP_OFFSET, &mut prefix)?;
		Superblock::block_size_hint(&prefix).map_err(Error::Bootstrap)
	}

	pub(super) fn read_bootstrap_block(
		&mut self,
		block_bytes: u32,
	) -> Result<Vec<u8>, Error<S::Error>> {
		let mut block = Vec::new();
		self.buffer(block_bytes as usize, &mut block)?;
		self.read_exact(BOOTSTRAP_OFFSET, &mut block)?;
		Ok(block)
	}

	pub(super) fn read_exact(
		&mut self,
		offset: ByteOffset,
		destination: &mut [u8],
	) -> Result<(), Error<S::Error>> {
		let bytes = destination.len() as u64;
		if offset
			.0
			.checked_add(bytes)
			.is_none_or(|end| end > self.source.len())
		{
			return Err(Error::ReadBounds { offset, bytes });
		}
		self.bytes_left = self
			.bytes_left
			.checked_sub(bytes)
			.ok_or(Error::Limit(Limit::ReadBytes))?;
		self.source
			.read_exact_at(offset, destination)
			.map_err(|source| Error::Read { offset, source })
	}

	pub(super) fn buffer(
		&self,
		bytes: usize,
		scratch: &mut Vec<u8>,
	) -> Result<(), Error<S::Error>> {
		if bytes > self.max_object_bytes {
			return Err(Error::Limit(Limit::ObjectBytes));
		}
		if bytes > scratch.len() {
			scratch
				.try_reserve_exact(bytes - scratch.len())
				.map_err(|_| Error::Allocation)?;
		}
		scratch.resize(bytes, 0);
		Ok(())
	}

	pub(super) fn read_blocks(
		&mut self,
		geometry: Geometry,
		address: BlockAddress,
		blocks: u64,
		scratch: &mut Vec<u8>,
	) -> Result<(), Error<S::Error>> {
		let range = geometry
			.byte_range(address, blocks)
			.map_err(Error::Bootstrap)?;
		let len = usize::try_from(range.end - range.start)
			.map_err(|_| Error::Limit(Limit::ObjectBytes))?;
		self.buffer(len, scratch)?;
		self.read_exact(ByteOffset(range.start), scratch)
	}
}
