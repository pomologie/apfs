use std::{fs::File, os::fd::AsFd};

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};

use crate::{
	Directory, EntryName, EventHandle,
	identity::ObjectIdentity,
	metadata::{
		AccessModificationTimes, MAX_EXTENDED_SECURITY_BYTES, MetadataView, ObjectFlags,
		ObservationError, extended_security,
	},
	stored_name,
};

use super::{BirthTimePolicy, WriterError};

pub(super) const PRIVATE_OPEN: OFlags = OFlags::CLOEXEC
	.union(OFlags::NONBLOCK)
	.union(OFlags::NOFOLLOW);
pub(super) const PRIVATE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);

#[derive(Debug)]
pub(super) struct Location<'dir> {
	directory: &'dir Directory,
	name: &'dir EntryName,
	parent: ObjectIdentity,
	identity: ObjectIdentity,
	owner: u32,
	process: u32,
	extent: u64,
	anchor: EventHandle,
}

impl<'dir> Location<'dir> {
	pub(super) fn capture(
		directory: &'dir Directory,
		name: &'dir EntryName,
		extent: u64,
		parent: ObjectIdentity,
		file: &File,
	) -> Result<Self, WriterError> {
		let identity = ObjectIdentity::held(file)?;
		if parent.mount() != identity.mount() {
			return Err(WriterError::Changed);
		}
		let owner = fs::fstat(directory)?.st_uid;
		let anchor = directory.open_event(name)?;
		Ok(Self {
			directory,
			name,
			parent,
			identity,
			owner,
			process: std::process::id(),
			extent,
			anchor,
		})
	}

	pub(super) const fn extent(&self) -> u64 {
		self.extent
	}

	pub(super) const fn identity(&self) -> &ObjectIdentity {
		&self.identity
	}

	pub(super) const fn event_handle(&self) -> &EventHandle {
		&self.anchor
	}

	pub(super) fn check_process(&self) -> Result<(), WriterError> {
		if self.process == std::process::id() {
			Ok(())
		} else {
			Err(WriterError::WrongProcess)
		}
	}

	pub(super) fn observe(&self, file: &File, extent: u64) -> Result<Snapshot, WriterError> {
		let anchor = self.observe_anchor(extent)?;
		self.identity.revalidate_held(file)?;
		let held = Snapshot::capture(fs::fstat(file)?, self.owner, extent)?;
		if held.same_live(&anchor) {
			Ok(held)
		} else {
			Err(WriterError::Changed)
		}
	}

	fn observe_anchor(&self, extent: u64) -> Result<Snapshot, WriterError> {
		self.check_process()?;
		self.parent.revalidate_held(self.directory)?;
		self.identity.revalidate_held(&self.anchor)?;
		self.identity.revalidate_named(self.directory, self.name)?;
		if stored_name(&self.anchor)? != *self.name {
			return Err(WriterError::Changed);
		}
		if !extended_security(&self.anchor, MAX_EXTENDED_SECURITY_BYTES)?.has_no_acl_entries() {
			return Err(WriterError::NotPrivate);
		}
		let held = Snapshot::capture(fs::fstat(&self.anchor)?, self.owner, extent)?;
		let named = Snapshot::capture(
			fs::statat(
				self.directory,
				self.name.as_c_str(),
				AtFlags::SYMLINK_NOFOLLOW,
			)?,
			self.owner,
			extent,
		)?;
		if named.same_live(&held) {
			Ok(held)
		} else {
			Err(WriterError::Changed)
		}
	}

	pub(super) fn revalidate(&self, file: &File, expected: &Snapshot) -> Result<(), WriterError> {
		let current = self.observe(file, expected.extent)?;
		if current.same_live(expected) {
			Ok(())
		} else {
			Err(WriterError::Changed)
		}
	}

	pub(super) fn with_metadata<T>(
		&self,
		file: &File,
		expected: &Snapshot,
		observe: impl FnOnce(MetadataView<'_>) -> Result<T, ObservationError>,
	) -> Result<T, WriterError> {
		self.revalidate(file, expected)?;
		let result = observe(MetadataView::new(file.as_fd()));
		self.revalidate(file, expected)?;
		Ok(result?)
	}

	pub(super) fn revalidate_anchor(&self, expected: &Snapshot) -> Result<Snapshot, WriterError> {
		let current = self.observe_anchor(expected.extent)?;
		if current.same_live(expected) {
			Ok(current)
		} else {
			Err(WriterError::Changed)
		}
	}

	pub(super) fn confirm_time_update(
		&mut self,
		file: &File,
		expected: &Snapshot,
		times: AccessModificationTimes,
		policy: BirthTimePolicy,
	) -> Result<Snapshot, WriterError> {
		let identity = ObjectIdentity::held(file)?;
		let previous = self.identity;
		// Darwin may lower birth time to an earlier requested mtime. Accept only
		// that exact change on the descriptor held across the timestamp operation.
		let birth = (
			previous.birth().seconds(),
			i64::from(previous.birth().nanoseconds()),
		);
		let current_birth = (
			identity.birth().seconds(),
			i64::from(identity.birth().nanoseconds()),
		);
		let modification = (
			times.modification.seconds(),
			times.modification.nanoseconds(),
		);
		let permitted_birth = match policy {
			BirthTimePolicy::Preserve => birth,
			BirthTimePolicy::AllowDarwinAdjustment => birth.min(modification),
		};
		if identity.mount() != previous.mount()
			|| identity.inode() != previous.inode()
			|| identity.generation() != previous.generation()
			|| (current_birth != birth && current_birth != permitted_birth)
		{
			return Err(WriterError::Changed);
		}
		self.identity = identity;
		let observed = self.observe(file, expected.extent)?;
		if !observed.same_file_fields(expected) || !observed.matches_times(times) {
			return Err(WriterError::TimesMismatch);
		}
		Ok(observed)
	}

	pub(super) fn revalidate_times(
		&self,
		file: &File,
		expected: &Snapshot,
		times: AccessModificationTimes,
	) -> Result<(), WriterError> {
		let current = self.observe(file, expected.extent)?;
		if !current.same_live(expected) {
			return Err(WriterError::Changed);
		}
		let named = Snapshot::capture(
			fs::statat(
				self.directory,
				self.name.as_c_str(),
				AtFlags::SYMLINK_NOFOLLOW,
			)?,
			self.owner,
			expected.extent,
		)?;
		if !named.same_live(&current)
			|| !current.matches_times(times)
			|| !named.matches_times(times)
		{
			return Err(WriterError::TimesMismatch);
		}
		Ok(())
	}

	pub(super) fn observe_sealed_held(
		&self,
		file: &File,
		expected: &Snapshot,
		times: AccessModificationTimes,
	) -> Result<Snapshot, WriterError> {
		self.identity.revalidate_held(file)?;
		self.identity.revalidate_held(&self.anchor)?;
		if !extended_security(file, MAX_EXTENDED_SECURITY_BYTES)?.has_no_acl_entries() {
			return Err(WriterError::NotPrivate);
		}
		let held = Snapshot::capture(fs::fstat(file)?, self.owner, expected.extent)?;
		let anchor = Snapshot::capture(fs::fstat(&self.anchor)?, self.owner, expected.extent)?;
		if !held.same_layout(expected) || !held.same_live(&anchor) {
			return Err(WriterError::Changed);
		}
		if !held.matches_times(times) || !anchor.matches_times(times) {
			return Err(WriterError::TimesMismatch);
		}
		Ok(held)
	}

	pub(super) fn open_read_only(&self, expected: &Snapshot) -> Result<File, WriterError> {
		self.revalidate_anchor(expected)?;
		let file = self.directory.open_file(self.name)?;
		if fs::fcntl_getfl(file.as_fd())?.intersection(OFlags::ACCMODE) != OFlags::RDONLY {
			return Err(WriterError::Changed);
		}
		self.revalidate(&file, expected)?;
		Ok(file)
	}
}

#[derive(Debug)]
pub(super) struct Snapshot {
	stat: Stat,
	extent: u64,
}

impl Snapshot {
	fn capture(stat: Stat, owner: u32, extent: u64) -> Result<Self, WriterError> {
		if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
			|| Mode::from_raw_mode(stat.st_mode) != PRIVATE_MODE
			|| stat.st_nlink != 1
			|| stat.st_uid != owner
		{
			return Err(WriterError::NotPrivate);
		}
		if u64::try_from(stat.st_size).ok() != Some(extent) {
			return Err(WriterError::Changed);
		}
		Ok(Self { stat, extent })
	}

	pub(super) const fn flags(&self) -> ObjectFlags {
		ObjectFlags::from_raw(self.stat.st_flags)
	}

	pub(super) fn same_layout(&self, other: &Self) -> bool {
		self.same_file_fields(other)
			&& self.stat.st_birthtime == other.stat.st_birthtime
			&& self.stat.st_birthtime_nsec == other.stat.st_birthtime_nsec
	}

	fn same_file_fields(&self, other: &Self) -> bool {
		let a = &self.stat;
		let b = &other.stat;
		a.st_dev == b.st_dev
			&& a.st_ino == b.st_ino
			&& a.st_gen == b.st_gen
			&& a.st_mode == b.st_mode
			&& a.st_uid == b.st_uid
			&& a.st_gid == b.st_gid
			&& a.st_nlink == b.st_nlink
			&& a.st_flags == b.st_flags
	}

	// A data read can advance atime. It does not change the pinned live extent.
	pub(super) fn same_live(&self, other: &Self) -> bool {
		self.same_layout(other)
			&& self.extent == other.extent
			&& self.stat.st_ctime == other.stat.st_ctime
			&& self.stat.st_ctime_nsec == other.stat.st_ctime_nsec
			&& self.stat.st_mtime == other.stat.st_mtime
			&& self.stat.st_mtime_nsec == other.stat.st_mtime_nsec
	}

	pub(super) fn matches_times(&self, times: AccessModificationTimes) -> bool {
		self.stat.st_atime == times.access.seconds()
			&& self.stat.st_atime_nsec == times.access.nanoseconds()
			&& self.stat.st_mtime == times.modification.seconds()
			&& self.stat.st_mtime_nsec == times.modification.nanoseconds()
	}
}
