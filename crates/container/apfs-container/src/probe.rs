use apfs_core::{ByteOffset, ReadAt};
use apfs_format::superblock::{BlockAddress, Geometry};

use crate::{Error, Limit, alloc::vec::Vec};

pub(super) const BLOCK_ZERO: BlockAddress = BlockAddress(0);
pub(super) const DEFAULT_MAX_OBJECT_BYTES: usize = 16 << 20;
pub(super) const DEFAULT_MAX_READ_BYTES: u64 = 128 << 20;

pub(super) struct Probe<'source, S> {
	source: &'source S,
	max_object_bytes: usize,
	bytes_left: u64,
}

impl<'source, S: ReadAt> Probe<'source, S> {
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
