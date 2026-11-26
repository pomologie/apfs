use std::fs::File;

use rustix::{
	fs::{self, FileType, Mode, OFlags},
	io::Errno,
};

use crate::{Directory, EntryName, identity::ObjectIdentity, lease::Lease};

use super::{
	PinnedSource, SourceError, SourceMetadata, content_error, same_stamp, stat_name, under_policy,
};

const READ_FLAGS: OFlags = OFlags::RDONLY
	.union(OFlags::NOFOLLOW)
	.union(OFlags::NONBLOCK)
	.union(OFlags::CLOEXEC);

impl<'root> PinnedSource<'root> {
	/// Open a selected regular file read-only with materialization disabled.
	/// # Errors
	/// Returns an error for an absent, unsupported, rebound, or inaccessible
	/// file, or if the thread's materialization policy cannot be established
	/// or restored.
	pub fn open(root: &'root Directory, name: &'root EntryName) -> Result<Self, SourceError> {
		Self::open_inner(root, name, None, |_, _| Ok(()))
	}

	/// Observe the named file, run caller admission, then open it for data.
	///
	/// The caller selects the appropriate shared or exclusive lease. The
	/// source borrows it throughout its life and revalidates any named lease
	/// binding before and after I/O. Admission receives one no-follow
	/// identity and metadata observation, including pre-open access time.
	/// The callback may inspect owner, mode, link count and native flags
	/// before allowing data access. The selection is checked again before
	/// open and matched to the held file afterward.
	///
	/// The lease coordinates cooperators. The authorized namespace still
	/// must remain controlled through observation and open.
	/// # Errors
	/// Returns the callback's refusal (for example, [`SourceError::AdmissionRefused`])
	/// before any data open. Also returns errors for mismatched leases,
	/// absent, unsupported, or changed sources, I/O or thread policy failures.
	pub fn open_leased(
		root: &'root Directory,
		name: &'root EntryName,
		lease: &'root Lease,
		admit: impl FnOnce(&ObjectIdentity, SourceMetadata) -> Result<(), SourceError>,
	) -> Result<Self, SourceError> {
		Self::open_inner(root, name, Some(lease), admit)
	}

	fn open_inner(
		root: &'root Directory,
		name: &'root EntryName,
		lease: Option<&'root Lease>,
		admit: impl FnOnce(&ObjectIdentity, SourceMetadata) -> Result<(), SourceError>,
	) -> Result<Self, SourceError> {
		under_policy(|| {
			let root_identity = ObjectIdentity::held(root)?;
			validate_lease(lease, root_identity)?;
			let named = stat_name(root, name)?.ok_or(SourceError::Missing)?;
			if FileType::from_raw_mode(named.st_mode) != FileType::RegularFile {
				return Err(SourceError::Unsupported);
			}
			let (identity, observed) =
				ObjectIdentity::named_with_stat(root, name)?.ok_or(SourceError::Changed)?;
			if !same_stamp(&named, &observed) {
				return Err(SourceError::Changed);
			}
			if root_identity.mount() != identity.mount() {
				return Err(SourceError::Unsupported);
			}
			let metadata = SourceMetadata::from_stat(&observed)?;
			admit(&identity, metadata)?;

			validate_lease(lease, root_identity)?;
			root_identity.revalidate_held(root)?;
			let (current, current_stamp) =
				ObjectIdentity::named_with_stat(root, name)?.ok_or(SourceError::Changed)?;
			if current != identity || !same_stamp(&current_stamp, &observed) {
				return Err(SourceError::Changed);
			}
			let fd =
				fs::openat(root, name.as_c_str(), READ_FLAGS, Mode::empty()).map_err(|error| {
					match error {
						Errno::NOENT | Errno::LOOP => SourceError::Changed,
						error => content_error(error.into()),
					}
				})?;
			let file = File::from(fd);
			let initial = fs::fstat(&file)?;
			if !same_stamp(&initial, &observed) {
				return Err(SourceError::Changed);
			}
			let source = Self {
				root,
				name,
				file,
				root_identity,
				identity,
				initial,
				metadata,
				lease,
			};
			source.validate_state()?;
			Ok(source)
		})
	}
}

pub(super) fn validate_lease(
	lease: Option<&Lease>,
	root_identity: ObjectIdentity,
) -> Result<(), SourceError> {
	if let Some(lease) = lease {
		if *lease.identity() != root_identity {
			return Err(SourceError::LeaseMismatch);
		}
		lease.revalidate().map_err(SourceError::Lease)?;
	}
	Ok(())
}
