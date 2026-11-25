//! Bounded parent-chain observations in a selected immutable volume.

extern crate alloc;

use alloc::vec::Vec;
use core::num::NonZeroU16;

use apfs_core::ReadAt;

use crate::{Error, FileKind, InodeId, VolumeView};

impl<S: ReadAt> VolumeView<'_, S> {
	/// Checks the starting directory and its parents for an exact xattr name.
	///
	/// Returns `Some(true)` when an attribute is found, `Some(false)` when the
	/// root is reached without a match, or `None` when the chain is incomplete,
	/// cyclic, or exceeds the directory allowance. Checks use the existing
	/// xattr admission and aggregate view read limits.
	///
	/// # Errors
	/// Propagates source, format, attribute and allocation errors.
	pub fn directory_ancestry_has_xattr(
		&mut self,
		mut directory: InodeId,
		name: &str,
		limit: NonZeroU16,
	) -> Result<Option<bool>, Error<S::Error>> {
		let mut visited = Vec::new();
		for _ in 0..limit.get() {
			if visited.contains(&directory) {
				return Ok(None);
			}
			let Some(inode) = self.stat(directory)? else {
				return Ok(None);
			};
			if inode.kind != FileKind::Directory {
				return Ok(None);
			}
			if self.open_xattr(directory, name)?.is_some() {
				return Ok(Some(true));
			}
			if directory == InodeId::ROOT {
				return Ok(Some(false));
			}
			let Some(parent) = inode.parent else {
				return Ok(None);
			};
			visited.try_reserve(1).map_err(|_| Error::Allocation)?;
			visited.push(directory);
			directory = parent;
		}
		Ok(None)
	}
}
