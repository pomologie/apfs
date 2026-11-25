//! Read-only consistency checks for the reachable namespace of one selected volume.

use alloc::vec::Vec;
use core::{num::NonZeroU16, ops::Range};

use apfs_core::{ByteOffset, ReadAt};
use apfs_format::object::{ObjectId, TransactionId};

use crate::{
	Corruption, Error, FileKind, Inode, InodeCount, InodeId, Limit, Unsupported, VolumeView,
	XattrStorage,
	record::{INODE_HAS_RESOURCE_FORK, INODE_NO_RESOURCE_FORK},
	verify_directory_target,
	xattr::RESOURCE_FORK_ATTRIBUTE,
};

const DEFAULT_DIRECTORY_DEPTH: u16 = 128;
const DEFAULT_DIRECTORY_ENTRIES: u32 = 16_384;
const DEFAULT_ATTRIBUTES: u32 = 16_384;
const DEFAULT_EXTENT_RANGES: u32 = 16_384;
const ATTRIBUTE_PAGE_ENTRIES: u16 = 64;
const PAYLOAD_CHUNK_BYTES: usize = 4096;

/// Selects how the reachable checker verifies logical payloads.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum CheckData {
	/// Verify metadata and extent ownership without reading external payload bytes.
	#[default]
	Metadata,
	/// Read every logical regular-file and xattr byte within an explicit budget.
	Read { max_bytes: u64 },
}

/// Aggregate limits for one reachable verification. Tree scans and source reads
/// still use the limits set when opening the volume view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckOptions {
	/// Maximum directory depth, measured in edges from the user-visible root.
	pub max_directory_depth: u16,
	/// Maximum directory entries, counting each hard-link name separately.
	pub max_directory_entries: u32,
	/// Maximum attributes across all reached inodes.
	pub max_attributes: u32,
	/// Maximum physical extent ranges across all reached file and xattr streams.
	pub max_extent_ranges: u32,
	pub data: CheckData,
}

impl Default for CheckOptions {
	fn default() -> Self {
		Self {
			max_directory_depth: DEFAULT_DIRECTORY_DEPTH,
			max_directory_entries: DEFAULT_DIRECTORY_ENTRIES,
			max_attributes: DEFAULT_ATTRIBUTES,
			max_extent_ranges: DEFAULT_EXTENT_RANGES,
			data: CheckData::Metadata,
		}
	}
}

/// Successful checks of reachable records in one selected volume checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CheckReport {
	pub volume: ObjectId,
	pub checkpoint: TransactionId,
	/// Count includes the user-visible root.
	pub directories: u32,
	/// Count of distinct regular inodes, including those with multiple names.
	pub regular_files: u32,
	pub symlinks: u32,
	pub directory_entries: u32,
	pub hard_link_entries: u32,
	pub attributes: u32,
	pub extent_ranges: u32,
	pub payload_bytes_read: u64,
}

impl<S: ReadAt> VolumeView<'_, S> {
	/// Verifies the admitted filesystem records reachable from the user-visible
	/// root. Success covers directory and inode relations, hard-link groups,
	/// inline symlink targets, stored xattrs, and unshared extent ownership.
	/// Allocation accounting, unreachable records, snapshots, name equivalence,
	/// and payload checksums are outside this operation's scope.
	///
	/// `cancelled` is polled between directories, entries, inodes, attribute
	/// operations, and payload reads. Individual metadata scans have their own
	/// tree and source limits. A cancelled or failed check returns no report.
	/// Consumed I/O stays charged to the volume view.
	///
	/// # Errors
	/// Returns errors for corrupt records, unsupported structures, source
	/// failures, exhausted limits, or cancellation.
	pub fn check_reachable(
		&mut self,
		options: CheckOptions,
		cancelled: impl FnMut() -> bool,
	) -> Result<CheckReport, Error<S::Error>> {
		let volume = self.volume();
		let mut check = Check {
			options,
			cancelled,
			report: CheckReport {
				volume: volume.mapping.id,
				checkpoint: volume.checkpoint,
				directories: 1,
				regular_files: 0,
				symlinks: 0,
				directory_entries: 0,
				hard_link_entries: 0,
				attributes: 0,
				extent_ranges: 0,
				payload_bytes_read: 0,
			},
			streams: Vec::new(),
			ranges: Vec::new(),
			scratch: Vec::new(),
		};
		let mut entries = check.collect_entries(self)?;
		entries.sort_unstable_by_key(|entry| (entry.inode, entry.sibling));
		check.check_inode(self, self.root())?;
		for group in entries.chunk_by(|left, right| left.inode == right.inode) {
			check.poll()?;
			let inode = self
				.stat(group[0].inode)?
				.ok_or(Corruption::DirectoryTarget)?;
			for entry in group {
				verify_directory_target(entry.parent, entry.kind, inode)?;
			}
			match inode.count {
				InodeCount::Children(_) => {
					if group.len() != 1 || group[0].sibling.is_some() {
						return Err(Corruption::RepeatedDirectory.into());
					}
				}
				InodeCount::Links(count) => check.check_links(self, inode, group, count)?,
			}
			check.check_inode(self, inode)?;
		}
		check.finish()
	}
}

struct Entry {
	inode: InodeId,
	parent: InodeId,
	kind: FileKind,
	sibling: Option<ObjectId>,
}

struct Directory {
	id: InodeId,
	parent: Option<InodeId>,
	depth: u16,
}

struct Check<C> {
	options: CheckOptions,
	cancelled: C,
	report: CheckReport,
	streams: Vec<ObjectId>,
	ranges: Vec<Range<u64>>,
	scratch: Vec<u8>,
}

impl<C: FnMut() -> bool> Check<C> {
	fn collect_entries<S: ReadAt>(
		&mut self,
		view: &mut VolumeView<'_, S>,
	) -> Result<Vec<Entry>, Error<S::Error>> {
		let mut pending = Vec::new();
		let mut entries = Vec::new();
		push(
			&mut pending,
			Directory {
				id: InodeId::ROOT,
				parent: None,
				depth: 0,
			},
		)?;
		while let Some(directory) = pending.pop() {
			self.poll()?;
			let inode = view
				.stat(directory.id)?
				.ok_or(Corruption::DirectoryTarget)?;
			if inode.kind != FileKind::Directory || inode.parent != directory.parent {
				return Err(Corruption::DirectoryTarget.into());
			}
			let mut children = Vec::new();
			view.scan_directory(directory.id, |_, entry| {
				self.poll()?;
				if self.report.directory_entries == self.options.max_directory_entries {
					return Err(Error::Limit(Limit::CheckDirectoryEntries));
				}
				push(&mut children, entry.into_owned()?)?;
				self.report.directory_entries += 1;
				Ok(())
			})?;
			children.sort_unstable_by(|left, right| left.name.cmp(&right.name));
			if children.windows(2).any(|pair| pair[0].name == pair[1].name) {
				return Err(Corruption::DuplicateEntry.into());
			}
			for child in children {
				if child.kind == FileKind::Directory {
					if directory.depth == self.options.max_directory_depth {
						return Err(Error::Limit(Limit::CheckDirectoryDepth));
					}
					push(
						&mut pending,
						Directory {
							id: child.inode,
							parent: Some(directory.id),
							depth: directory.depth + 1,
						},
					)?;
				}
				push(
					&mut entries,
					Entry {
						inode: child.inode,
						parent: directory.id,
						kind: child.kind,
						sibling: child.sibling,
					},
				)?;
			}
		}
		Ok(entries)
	}

	fn check_links<S: ReadAt>(
		&mut self,
		view: &mut VolumeView<'_, S>,
		inode: Inode,
		entries: &[Entry],
		count: u32,
	) -> Result<(), Error<S::Error>> {
		if entries.len() as u32 != count {
			return Err(Corruption::HardLinkCount.into());
		}
		let has_siblings = count > 1 || entries[0].sibling.is_some();
		if inode.kind != FileKind::Regular {
			return if has_siblings {
				Err(Unsupported::HardLinkKind.into())
			} else {
				Ok(())
			};
		}
		let links = view
			.hard_links(inode.id)?
			.ok_or(Corruption::DirectoryTarget)?;
		if has_siblings {
			if links.len() != entries.len()
				|| links.iter().zip(entries).any(|(link, entry)| {
					entry.sibling != Some(ObjectId(link.sibling.as_raw()))
						|| entry.parent != link.parent
				}) {
				return Err(Corruption::HardLinkDirectory.into());
			}
			self.report.hard_link_entries += count;
		} else if !links.is_empty() {
			return Err(Corruption::HardLinkDirectory.into());
		}
		Ok(())
	}

	fn check_inode<S: ReadAt>(
		&mut self,
		view: &mut VolumeView<'_, S>,
		inode: Inode,
	) -> Result<(), Error<S::Error>> {
		self.poll()?;
		match inode.kind {
			FileKind::Directory => {
				self.report.directories = self
					.report
					.directories
					.checked_add(u32::from(inode.id != InodeId::ROOT))
					.ok_or(Error::Limit(Limit::CheckDirectoryEntries))?;
			}
			FileKind::Regular => {
				let mut data = view
					.open_file(inode.id)?
					.ok_or(Corruption::DirectoryTarget)?;
				push(&mut self.streams, inode.data_stream_id)?;
				self.record_ranges(data.physical_ranges())?;
				self.read_payload(data.len(), |offset, buffer| {
					data.read_exact_at(offset, buffer)
				})?;
				self.report.regular_files += 1;
			}
			FileKind::Symlink => {
				view.read_link(inode.id)?
					.ok_or(Corruption::DirectoryTarget)?;
				self.report.symlinks += 1;
			}
			FileKind::Other(kind) => return Err(Unsupported::CheckFileKind(kind).into()),
		}
		if inode.has_finder_info_field {
			return Err(Unsupported::InodeFinderInfo.into());
		}
		self.check_attributes(view, inode)
	}

	fn check_attributes<S: ReadAt>(
		&mut self,
		view: &mut VolumeView<'_, S>,
		inode: Inode,
	) -> Result<(), Error<S::Error>> {
		let limit = NonZeroU16::new(view.limits.max_entries_per_page.min(ATTRIBUTE_PAGE_ENTRIES))
			.ok_or(Error::Limit(Limit::Page))?;
		let mut cursor = None;
		let mut has_resource_fork = false;
		loop {
			self.poll()?;
			let page = view
				.list_xattrs(inode.id, cursor, limit)?
				.ok_or(Corruption::DirectoryTarget)?;
			for attr in page.entries {
				self.poll()?;
				if self.report.attributes == self.options.max_attributes {
					return Err(Error::Limit(Limit::CheckAttributes));
				}
				has_resource_fork |= attr.name == RESOURCE_FORK_ATTRIBUTE;
				let mut data = view
					.open_xattr(inode.id, &attr.name)?
					.ok_or(Corruption::XattrRecord)?;
				if let XattrStorage::DataStream(id) = attr.storage {
					push(&mut self.streams, id)?;
				}
				self.record_ranges(data.physical_ranges())?;
				self.read_payload(data.len(), |offset, buffer| {
					data.read_exact_at(offset, buffer)
				})?;
				self.report.attributes += 1;
			}
			cursor = page.next;
			if cursor.is_none() {
				break;
			}
		}
		let states_fork_present = inode.internal_flags & INODE_HAS_RESOURCE_FORK != 0;
		let states_fork_absent = inode.internal_flags & INODE_NO_RESOURCE_FORK != 0;
		if states_fork_present != has_resource_fork || (has_resource_fork && states_fork_absent) {
			return Err(Corruption::ResourceForkFlags.into());
		}
		Ok(())
	}

	fn record_ranges<E>(
		&mut self,
		ranges: impl Iterator<Item = Range<u64>>,
	) -> Result<(), Error<E>> {
		for range in ranges {
			if self.report.extent_ranges == self.options.max_extent_ranges {
				return Err(Error::Limit(Limit::CheckExtentRanges));
			}
			push(&mut self.ranges, range)?;
			self.report.extent_ranges += 1;
		}
		Ok(())
	}

	fn read_payload<E>(
		&mut self,
		length: u64,
		mut read_exact: impl FnMut(ByteOffset, &mut [u8]) -> Result<(), Error<E>>,
	) -> Result<(), Error<E>> {
		let CheckData::Read { max_bytes } = self.options.data else {
			return Ok(());
		};
		let end = self
			.report
			.payload_bytes_read
			.checked_add(length)
			.filter(|&end| end <= max_bytes)
			.ok_or(Error::Limit(Limit::CheckPayloadBytes))?;
		if length != 0 && self.scratch.is_empty() {
			self.scratch
				.try_reserve_exact(PAYLOAD_CHUNK_BYTES)
				.map_err(|_| Error::Allocation)?;
			self.scratch.resize(PAYLOAD_CHUNK_BYTES, 0);
		}
		let mut offset = 0;
		while offset < length {
			self.poll()?;
			let take = (length - offset).min(PAYLOAD_CHUNK_BYTES as u64) as usize;
			read_exact(ByteOffset(offset), &mut self.scratch[..take])?;
			offset += take as u64;
		}
		self.report.payload_bytes_read = end;
		Ok(())
	}

	fn finish<E>(mut self) -> Result<CheckReport, Error<E>> {
		self.poll()?;
		self.streams.sort_unstable();
		if self.streams.windows(2).any(|pair| pair[0] == pair[1]) {
			return Err(Corruption::RepeatedDataStream.into());
		}
		self.ranges.sort_unstable_by_key(|range| range.start);
		if self
			.ranges
			.windows(2)
			.any(|pair| pair[0].end > pair[1].start)
		{
			return Err(Corruption::OverlappingPayloadExtents.into());
		}
		Ok(self.report)
	}

	fn poll<E>(&mut self) -> Result<(), Error<E>> {
		if (self.cancelled)() {
			return Err(Error::Cancelled);
		}
		Ok(())
	}
}

fn push<T, E>(values: &mut Vec<T>, value: T) -> Result<(), Error<E>> {
	values.try_reserve(1).map_err(|_| Error::Allocation)?;
	values.push(value);
	Ok(())
}
