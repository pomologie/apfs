//! Checkpoint-bound volume views, directory enumeration, and inode lookup.

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::num::NonZeroU16;

use apfs_container::{Container, LookupOptions, Volume, VolumeObjects};
use apfs_core::ReadAt;
use apfs_format::{
	object::{ObjectId, TransactionId},
	superblock::Geometry,
};

use crate::{
	Corruption, DirectoryEntry, Error, FileKind, Inode, InodeCount, InodeId, Limit, NameProfile,
	payload::ReservedBlocks,
	record::{self, DirectoryRecord, Prefix},
	walk,
};

const DEFAULT_TREE_DEPTH: u16 = 16;
pub(super) const MAX_TREE_DEPTH: u16 = 32;
const DEFAULT_TREE_NODES: u16 = 256;
const DEFAULT_TREE_RECORDS: u32 = 16_384;
const DEFAULT_PAGE_ENTRIES: u16 = 256;

/// Limits for one filesystem-tree scan, in addition to the open view's
/// aggregate object-read budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TreeLimits {
	/// Maximum depth in nodes, including the root. The reader caps this at 32.
	pub max_depth: u16,
	/// Maximum number of visited filesystem nodes per scan.
	pub max_nodes: u16,
	/// Maximum number of examined key/value slots per scan.
	pub max_records: u32,
	/// Maximum number of entries or attributes per page, or total hard links
	/// per query. Zero also disables full attribute name inventories.
	pub max_entries_per_page: u16,
}

impl Default for TreeLimits {
	fn default() -> Self {
		Self {
			max_depth: DEFAULT_TREE_DEPTH,
			max_nodes: DEFAULT_TREE_NODES,
			max_records: DEFAULT_TREE_RECORDS,
			max_entries_per_page: DEFAULT_PAGE_ENTRIES,
		}
	}
}

/// An opaque continuation cursor for an admitted directory in one volume view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryCursor {
	identity: ViewIdentity,
	directory: InodeId,
	offset: u32,
}

/// Directory records in on-disk order, inside the requested page limit.
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct DirectoryPage {
	pub entries: Vec<DirectoryEntry>,
	pub next: Option<DirectoryCursor>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ViewIdentity {
	container: [u8; 16],
	checkpoint: TransactionId,
	id: ObjectId,
	uuid: [u8; 16],
}

/// Read-only filesystem access to one ordinary APFS volume.
#[derive(Debug)]
pub struct VolumeView<'source, S> {
	pub(super) objects: VolumeObjects<'source, S>,
	pub(super) geometry: Geometry,
	container_uuid: [u8; 16],
	pub(super) reserved: ReservedBlocks,
	pub(super) limits: TreeLimits,
	root: Inode,
}

impl<'source, S: ReadAt> VolumeView<'source, S> {
	/// Opens the explicitly selected volume and its ordinary root inode.
	///
	/// The object-map read budget applies to opening and all subsequent reads
	/// on this view. Each metadata query also has its own tree limits.
	///
	/// # Errors
	/// Returns errors for failed object resolution, corrupt or unsupported
	/// filesystem metadata, and exhausted resource limits.
	pub fn open(
		container: &'source Container<S>,
		id: ObjectId,
		objects: LookupOptions,
		limits: TreeLimits,
	) -> Result<Option<Self>, Error<S::Error>> {
		let Some(mut objects) = container.open_volume_objects(id, objects)? else {
			return Ok(None);
		};

		let geometry = container.superblock().geometry;
		let root =
			stat(&mut objects, geometry, InodeId::ROOT, limits)?.ok_or(Corruption::RootInode)?;
		if root.kind != FileKind::Directory || root.parent.is_some() {
			return Err(Corruption::RootInode.into());
		}
		Ok(Some(Self {
			objects,
			geometry,
			limits,
			root,
			container_uuid: container.superblock().uuid,
			reserved: ReservedBlocks::from_superblock(container.superblock()),
		}))
	}

	/// Checked superblock metadata for this view.
	#[must_use]
	pub fn volume(&self) -> &Volume {
		self.objects.volume()
	}

	/// Qualified on-disk name comparison profile selected by the volume flags.
	#[must_use]
	pub fn name_profile(&self) -> NameProfile {
		let features = self.volume().superblock.features;
		NameProfile::for_flags(
			features.case_insensitive(),
			features.normalization_insensitive(),
		)
	}

	/// The verified user-visible root inode.
	#[must_use]
	pub const fn root(&self) -> Inode {
		self.root
	}

	/// Reads checked inode metadata. The inode number is local to this volume.
	///
	/// # Errors
	/// Returns errors for corrupt or unavailable tree records and exhausted limits.
	pub fn stat(&mut self, id: InodeId) -> Result<Option<Inode>, Error<S::Error>> {
		if id == InodeId::ROOT {
			return Ok(Some(self.root));
		}
		stat(&mut self.objects, self.geometry, id, self.limits)
	}

	/// Finds an exact stored UTF-8 name in one directory and verifies its inode.
	/// Matches the spelling stored in the directory record byte for byte.
	/// Hard links also require a matching sibling link and inverse sibling map.
	///
	/// # Errors
	/// Invalid components, malformed or inconsistent records, non-directories,
	/// source failures and resource limits return typed errors.
	pub fn lookup_stored_name(
		&mut self,
		parent: InodeId,
		name: &str,
	) -> Result<Option<DirectoryEntry>, Error<S::Error>> {
		if !record::valid_name(name) {
			return Err(Error::InvalidName);
		}
		self.find_directory_entry(parent, Corruption::DuplicateEntry, |stored| {
			Ok(stored == name)
		})
	}

	/// Looks up a name using the volume's qualified on-disk comparison profile.
	/// Returns the stored spelling and verifies the target inode and hard links.
	///
	/// Normalized and folded profiles compare complete keys in one bounded
	/// directory scan. A 22-bit directory hash can be shared by distinct keys.
	///
	/// # Errors
	/// Rejects invalid names, components outside the qualified profile in the
	/// query or directory entries, ambiguous matches, non-directories, corrupt
	/// metadata, source failures, and exhausted traversal or read limits.
	pub fn lookup_native_name(
		&mut self,
		parent: InodeId,
		name: &str,
	) -> Result<Option<DirectoryEntry>, Error<S::Error>> {
		let profile = self.name_profile();
		if profile == NameProfile::Binary {
			return self.lookup_stored_name(parent, name);
		}
		let wanted = profile.key(name)?;
		self.find_directory_entry(parent, Corruption::EquivalentDirectoryNames, |stored| {
			Ok(profile.key(stored)? == wanted)
		})
	}

	fn find_directory_entry(
		&mut self,
		parent: InodeId,
		duplicate: Corruption,
		matches_name: impl Fn(&str) -> Result<bool, Error<S::Error>>,
	) -> Result<Option<DirectoryEntry>, Error<S::Error>> {
		let mut found = None;
		self.scan_directory(parent, |_, entry| {
			if matches_name(entry.name)? {
				if found.is_some() {
					return Err(duplicate.into());
				}
				found = Some(entry.into_owned()?);
			}
			Ok(())
		})?;
		if let Some(entry) = &found {
			let inode = self.stat(entry.inode)?.ok_or(Corruption::DirectoryTarget)?;
			verify_directory_target(parent, entry.kind, inode)?;
			if entry.sibling.is_some()
				|| matches!(inode.count, InodeCount::Links(count) if count > 1)
			{
				self.verify_hard_link(parent, entry, inode)?;
			}
		}
		Ok(found)
	}

	/// Returns a bounded page of directory records in their on-disk order.
	/// Each page checks the directory-record count against the inode and
	/// charges all visited records against the query's limits.
	///
	/// # Errors
	/// Rejects an invalid cursor, a non-directory, malformed records, a source
	/// failure, and exhausted page or traversal limits.
	pub fn read_dir(
		&mut self,
		directory: InodeId,
		cursor: Option<DirectoryCursor>,
		limit: NonZeroU16,
	) -> Result<DirectoryPage, Error<S::Error>> {
		if limit.get() > self.limits.max_entries_per_page {
			return Err(Error::Limit(Limit::Page));
		}
		let identity = self.identity();
		let start = match cursor {
			Some(cursor) if cursor.identity == identity && cursor.directory == directory => {
				cursor.offset
			}
			Some(_) => return Err(Error::InvalidCursor),
			None => 0,
		};
		let limit = usize::from(limit.get());
		let mut entries = Vec::new();
		let count = self.scan_directory(directory, |index, entry| {
			if index >= start && entries.len() < limit {
				entries.try_reserve(1).map_err(|_| Error::Allocation)?;
				entries.push(entry.into_owned()?);
			}
			Ok(())
		})?;
		if start > count {
			return Err(Error::InvalidCursor);
		}
		let end = start + entries.len() as u32;
		let next = (end < count).then_some(DirectoryCursor {
			identity,
			directory,
			offset: end,
		});
		Ok(DirectoryPage { entries, next })
	}

	/// Pages directory entries and verifies each returned target and hard link.
	///
	/// This uses the same cursor and ordering as [`Self::read_dir`]. Each
	/// returned entry gets an exact-name admission under the view's read budget.
	///
	/// # Errors
	/// In addition to paging failures, returns errors for duplicate, missing,
	/// or inconsistent records and for failed target or sibling validation.
	pub fn read_checked_dir(
		&mut self,
		directory: InodeId,
		cursor: Option<DirectoryCursor>,
		limit: NonZeroU16,
	) -> Result<DirectoryPage, Error<S::Error>> {
		let page = self.read_dir(directory, cursor, limit)?;
		for entry in &page.entries {
			if self.lookup_stored_name(directory, &entry.name)?.as_ref() != Some(entry) {
				return Err(Corruption::DirectoryTarget.into());
			}
		}
		Ok(page)
	}

	pub(super) fn identity(&self) -> ViewIdentity {
		let volume = self.objects.volume();
		ViewIdentity {
			container: self.container_uuid,
			checkpoint: volume.checkpoint,
			id: volume.mapping.id,
			uuid: volume.superblock.uuid,
		}
	}

	pub(super) fn scan_directory(
		&mut self,
		directory: InodeId,
		mut visit: impl FnMut(u32, DirectoryRecord<'_>) -> Result<(), Error<S::Error>>,
	) -> Result<u32, Error<S::Error>> {
		let Some(Inode {
			count: InodeCount::Children(expected),
			..
		}) = self.stat(directory)?
		else {
			return Err(Error::NotDirectory);
		};
		let features = self.objects.volume().superblock.features;
		let hashed = features.case_insensitive() || features.normalization_insensitive();
		let mut count = 0;
		let mut previous_hash = None;
		let mut previous_name = String::new();
		walk::scan(
			&mut self.objects,
			self.geometry,
			Prefix::directory(directory),
			self.limits,
			|slot| {
				let entry = record::directory(slot.key, slot.value, hashed)?;
				if entry.inode == directory {
					return Err(Corruption::DirectoryTarget.into());
				}
				if count >= expected {
					return Err(Corruption::DirectoryCount.into());
				}
				if count != 0 && previous_name == entry.name {
					return Err(Corruption::DuplicateEntry.into());
				}
				if previous_hash > entry.name_hash
					|| (!hashed && previous_name.as_str() > entry.name)
				{
					return Err(Corruption::KeyOrder.into());
				}
				previous_hash = entry.name_hash;
				previous_name.clear();
				previous_name
					.try_reserve_exact(entry.name.len())
					.map_err(|_| Error::Allocation)?;
				previous_name.push_str(entry.name);
				visit(count, entry)?;
				count += 1;
				Ok(())
			},
		)?;
		if count != expected {
			return Err(Corruption::DirectoryCount.into());
		}
		Ok(count)
	}
}

pub(super) fn verify_directory_target(
	parent: InodeId,
	kind: FileKind,
	inode: Inode,
) -> Result<(), Corruption> {
	let expects_parent = matches!(inode.count, InodeCount::Children(_) | InodeCount::Links(1));
	if inode.kind != kind
		|| inode.count == InodeCount::Links(0)
		|| (expects_parent && inode.parent != Some(parent))
	{
		return Err(Corruption::DirectoryTarget);
	}
	Ok(())
}

fn stat<S: ReadAt>(
	objects: &mut VolumeObjects<'_, S>,
	geometry: Geometry,
	id: InodeId,
	limits: TreeLimits,
) -> Result<Option<Inode>, Error<S::Error>> {
	let mut found = None;
	walk::scan(objects, geometry, Prefix::inode(id), limits, |slot| {
		if found.is_some() {
			return Err(Corruption::DuplicateInode.into());
		}
		found = Some(record::inode(id, slot.key, slot.value)?);
		Ok(())
	})?;
	Ok(found)
}
