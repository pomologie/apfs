use std::fs::File;

use rustix::{
	fs::{self, OFlags},
	io::Errno,
};

use crate::{Directory, EntryName, ObjectIdentity};

use super::{
	InitialFlags, LifecycleEffect, PrivateWriter, WriterError, observation, without_materialization,
};

const MAX_FILE_EXTENT: u64 = i64::MAX as u64;

impl<'dir> PrivateWriter<'dir> {
	/// Exclusively create one private file at a relative name.
	/// # Errors
	/// Returns an occupied-name, invalid extent, opening, policy, or observation
	/// error. Once creation succeeds the name is retained even if admission fails.
	pub fn create(
		directory: &'dir Directory,
		name: &'dir EntryName,
		extent: u64,
	) -> Result<Self, WriterError> {
		Self::create_with_initial_flags(directory, name, extent, InitialFlags::AllowStable)
	}

	/// Exclusively create a private file and apply the selected initial flag rule.
	/// # Errors
	/// In addition to the errors from [Self::create], refusal of the initial flags
	/// returns [WriterError::CreatedButUnverified] and retains the entry.
	pub fn create_with_initial_flags(
		directory: &'dir Directory,
		name: &'dir EntryName,
		extent: u64,
		flags: InitialFlags,
	) -> Result<Self, WriterError> {
		Self::create_guarded(directory, name, extent, flags, || Ok(()))
	}

	pub(super) fn create_guarded<G>(
		directory: &'dir Directory,
		name: &'dir EntryName,
		extent: u64,
		flags: InitialFlags,
		authorize: impl FnOnce() -> Result<G, WriterError>,
	) -> Result<Self, WriterError> {
		if extent > MAX_FILE_EXTENT {
			return Err(WriterError::InvalidRange);
		}
		without_materialization(LifecycleEffect::Created, || {
			let parent = ObjectIdentity::held(directory)?;
			let opened = {
				let _guard = authorize()?;
				fs::openat(
					directory,
					name.as_c_str(),
					observation::PRIVATE_OPEN | OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
					observation::PRIVATE_MODE,
				)
			};
			let file = match opened {
				Ok(fd) => File::from(fd),
				Err(Errno::EXIST) => return Err(WriterError::Occupied),
				Err(error) => return Err(WriterError::CreateUncertain(error.into())),
			};
			let admit = || {
				let location =
					observation::Location::capture(directory, name, extent, parent, &file)?;
				let observed = location.observe(&file, 0)?;
				flags.check(observed.flags())?;
				Ok(Self {
					location,
					file: Some(file),
					position: 0,
					observed,
				})
			};
			admit().map_err(|error| WriterError::CreatedButUnverified(Box::new(error)))
		})
	}
}
