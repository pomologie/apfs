//! Checked reverse names for ordinary regular-file hard links.

extern crate alloc;

use alloc::{string::String, vec::Vec};

use apfs_core::ReadAt;
use apfs_format::object::ObjectId;

use crate::{
	Corruption, DirectoryEntry, Error, FileKind, Inode, InodeCount, InodeId, Limit, Unsupported,
	VolumeView,
	node::Slot,
	record::{Prefix, decode_name},
	walk,
	wire::{U16_BYTES, U64_BYTES, u16_at, u64_at},
};

const SIBLING_KEY_BYTES: usize = 2 * U64_BYTES;
const SIBLING_NAME_LENGTH: usize = U64_BYTES;
const SIBLING_NAME: usize = SIBLING_NAME_LENGTH + U16_BYTES;

/// Identifier of one hard link in an APFS volume.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SiblingId(u64);

impl SiblingId {
	/// Raw identifier used to join a directory entry, sibling link and sibling map.
	#[must_use]
	pub const fn as_raw(self) -> u64 {
		self.0
	}
}

/// One checked name and parent for a regular-file hard link.
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct HardLink {
	pub sibling: SiblingId,
	pub inode: InodeId,
	pub parent: InodeId,
	/// Exact stored UTF-8 spelling.
	pub name: String,
}

impl<S: ReadAt> VolumeView<'_, S> {
	/// Lists the checked hard-link names of a regular inode in sibling ID order.
	/// The first recorded sibling is the primary link. A missing inode returns
	/// `None`. A single ordinary name without sibling records returns an empty
	/// list. The group must fit the `max_entries_per_page` limit.
	///
	/// # Errors
	/// Rejects non-regular inodes, inconsistent sibling links, maps, counts,
	/// directory records, and any exhausted tree or source-read budget.
	pub fn hard_links(&mut self, id: InodeId) -> Result<Option<Vec<HardLink>>, Error<S::Error>> {
		let Some(inode) = self.stat(id)? else {
			return Ok(None);
		};
		let count = regular_link_count(inode).ok_or(Error::NotRegularFile)?;
		if count > u32::from(self.limits.max_entries_per_page) {
			return Err(Error::Limit(Limit::Page));
		}

		let mut links = Vec::new();
		self.scan_sibling_links(inode, count, |link| {
			let mut name = String::new();
			name.try_reserve_exact(link.name.len())
				.map_err(|_| Error::Allocation)?;
			name.push_str(link.name);
			links.try_reserve(1).map_err(|_| Error::Allocation)?;
			links.push(HardLink {
				sibling: link.sibling,
				inode: id,
				parent: link.parent,
				name,
			});
			Ok(())
		})?;
		for link in &links {
			self.verify_sibling_map(link.sibling, id)?;
			self.verify_sibling_directory(link)?;
		}
		Ok(Some(links))
	}

	pub(crate) fn verify_hard_link(
		&mut self,
		parent: InodeId,
		entry: &DirectoryEntry,
		inode: Inode,
	) -> Result<(), Error<S::Error>> {
		let count = regular_link_count(inode).ok_or(Unsupported::HardLinkKind)?;
		let sibling = SiblingId(entry.sibling.ok_or(Corruption::HardLinkDirectory)?.0);
		let mut found = false;
		self.scan_sibling_links(inode, count, |link| {
			if link.sibling == sibling {
				if link.parent != parent || link.name != entry.name {
					return Err(Corruption::HardLinkDirectory.into());
				}
				found = true;
			}
			Ok(())
		})?;
		if !found {
			return Err(Corruption::HardLinkDirectory.into());
		}
		self.verify_sibling_map(sibling, inode.id)
	}

	fn scan_sibling_links(
		&mut self,
		inode: Inode,
		expected: u32,
		mut visit: impl FnMut(SiblingLink<'_>) -> Result<(), Error<S::Error>>,
	) -> Result<(), Error<S::Error>> {
		if expected == 0 {
			return Err(Corruption::HardLinkCount.into());
		}
		let mut count = 0;
		let mut previous = None;
		walk::scan(
			&mut self.objects,
			self.geometry,
			Prefix::sibling_links(inode.id),
			self.limits,
			|slot| {
				let link = SiblingLink::decode(slot, inode.id)?;
				if previous.is_some_and(|id| id >= link.sibling) {
					return Err(Corruption::SiblingLink.into());
				}
				if count >= expected {
					return Err(Corruption::HardLinkCount.into());
				}
				if count == 0 && inode.parent != Some(link.parent) {
					return Err(Corruption::HardLinkDirectory.into());
				}
				previous = Some(link.sibling);
				count += 1;
				visit(link)
			},
		)?;
		if count != expected && (expected, count) != (1, 0) {
			return Err(Corruption::HardLinkCount.into());
		}
		Ok(())
	}

	fn verify_sibling_map(
		&mut self,
		sibling: SiblingId,
		inode: InodeId,
	) -> Result<(), Error<S::Error>> {
		let mut found = false;
		walk::scan(
			&mut self.objects,
			self.geometry,
			Prefix::sibling_map(ObjectId(sibling.as_raw())),
			self.limits,
			|slot| {
				if found
					|| slot.key.len() != U64_BYTES
					|| slot.value.len() != U64_BYTES
					|| u64_at(slot.value, 0)? != inode.as_raw()
				{
					return Err(Corruption::SiblingMap.into());
				}
				found = true;
				Ok(())
			},
		)?;
		if !found {
			return Err(Corruption::SiblingMap.into());
		}
		Ok(())
	}

	fn verify_sibling_directory(&mut self, link: &HardLink) -> Result<(), Error<S::Error>> {
		let mut found = false;
		let result = self.scan_directory(link.parent, |_, entry| {
			if entry.name == link.name {
				if found
					|| entry.inode != link.inode
					|| entry.kind != FileKind::Regular
					|| entry.sibling != Some(ObjectId(link.sibling.as_raw()))
				{
					return Err(Corruption::HardLinkDirectory.into());
				}
				found = true;
			}
			Ok(())
		});
		match result {
			Ok(_) if found => Ok(()),
			Ok(_) | Err(Error::NotDirectory) => Err(Corruption::HardLinkDirectory.into()),
			Err(error) => Err(error),
		}
	}
}

struct SiblingLink<'a> {
	sibling: SiblingId,
	parent: InodeId,
	name: &'a str,
}

impl<'a> SiblingLink<'a> {
	fn decode(slot: Slot<'a>, inode: InodeId) -> Result<Self, Corruption> {
		if slot.key.len() != SIBLING_KEY_BYTES || slot.value.len() < SIBLING_NAME {
			return Err(Corruption::SiblingLink);
		}
		let id = u64_at(slot.key, U64_BYTES)?;
		if InodeId::from_raw(id).is_none() || id == inode.as_raw() {
			return Err(Corruption::SiblingLink);
		}
		let parent = InodeId::from_raw(u64_at(slot.value, 0)?).ok_or(Corruption::SiblingLink)?;
		let length = usize::from(u16_at(slot.value, SIBLING_NAME_LENGTH)?);
		if parent == inode || slot.value.len() != SIBLING_NAME + length {
			return Err(Corruption::SiblingLink);
		}
		let name = decode_name(&slot.value[SIBLING_NAME..]).map_err(|_| Corruption::SiblingLink)?;
		Ok(Self {
			sibling: SiblingId(id),
			parent,
			name,
		})
	}
}

fn regular_link_count(inode: Inode) -> Option<u32> {
	match (inode.kind, inode.count) {
		(FileKind::Regular, InodeCount::Links(count)) => Some(count),
		_ => None,
	}
}
