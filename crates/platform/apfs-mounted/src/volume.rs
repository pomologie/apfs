//! Live Darwin volume facts obtained from a held directory descriptor.

use std::{
	ffi::{CStr, CString},
	io,
	os::fd::{AsFd, AsRawFd, BorrowedFd},
};

use rustix::fs::{FileType, fstat, fstatfs};

const RETURNED_ATTRIBUTES: u32 = libc::ATTR_CMN_RETURNED_ATTRS;
const VOLUME_CAPABILITIES: u32 = libc::ATTR_VOL_CAPABILITIES;
const VOLUME_ATTRIBUTES: u32 = libc::ATTR_VOL_ATTRIBUTES;
const VOLUME_FIELDS: u32 = VOLUME_CAPABILITIES | VOLUME_ATTRIBUTES;
const OWNERSHIP_ATTRIBUTES: u32 = libc::ATTR_CMN_OWNERID | libc::ATTR_CMN_GRPID;
const WORD_BYTES: usize = size_of::<u32>();
const ATTRIBUTES_WORDS: usize = size_of::<libc::attribute_set_t>() / WORD_BYTES;
const CAPABILITIES_WORDS: usize = size_of::<libc::vol_capabilities_attr_t>() / WORD_BYTES;
const VOLUME_ATTRIBUTES_WORDS: usize = size_of::<libc::vol_attributes_attr_t>() / WORD_BYTES;
const HEADER_WORDS: usize = 1 + ATTRIBUTES_WORDS;
const RESPONSE_WORDS: usize = HEADER_WORDS + CAPABILITIES_WORDS + VOLUME_ATTRIBUTES_WORDS;
const VALID_WORD_OFFSET: usize = CAPABILITIES_WORDS / 2;

#[cfg(test)]
mod tests;

/// Evidence for a volume capability from the current observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Capability {
	/// Darwin reports support.
	Supported,
	/// Darwin reports that the capability is unavailable on this mount.
	Unsupported,
	/// The response did not establish support or absence.
	Unknown,
}

/// Darwin's locality classification for a mounted volume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Locality {
	/// The mount reports `MNT_LOCAL`.
	Local,
	/// The mount lacks `MNT_LOCAL`.
	Remote,
}

/// Whether the mount ignores native file ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OwnershipMode {
	/// The mount uses the filesystem's own ownership semantics.
	Native,
	/// The mount reports `MNT_IGNORE_OWNERSHIP`.
	Ignored,
}

/// Capabilities reported by the mounted volume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct VolumeCapabilities {
	/// The volume format supports setting permissions.
	pub permissions: Capability,
	/// Darwin exposes owner/group attributes and honors mount-level ownership.
	/// This does not establish permission to change ownership.
	pub ownership: Capability,
	/// The interface supports extended security (ACLs).
	pub acls: Capability,
	/// The interface supports advisory `flock` on files.
	pub advisory_locking: Capability,
	/// The interface supports exclusive rename.
	pub exclusive_rename: Capability,
}

/// Live mount facts. They confer no authority and do not describe a snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct MountFacts {
	filesystem_type: CString,
	mount_flags: u32,
	pub locality: Locality,
}

impl MountFacts {
	/// Native filesystem type name as reported by `fstatfs`.
	pub fn filesystem_type(&self) -> &CStr {
		&self.filesystem_type
	}

	pub fn is_apfs(&self) -> bool {
		self.filesystem_type() == c"apfs"
	}

	/// Raw Darwin `f_flags` from `fstatfs`, including flags unknown to this crate.
	pub fn mount_flags(&self) -> u32 {
		self.mount_flags
	}

	pub fn is_read_only(&self) -> bool {
		self.mount_flags & libc::MNT_RDONLY as u32 != 0
	}

	pub fn is_automounted(&self) -> bool {
		self.mount_flags & libc::MNT_AUTOMOUNTED as u32 != 0
	}

	/// Report mount ownership behavior independently of attribute support.
	pub fn ownership_mode(&self) -> OwnershipMode {
		if self.mount_flags & libc::MNT_IGNORE_OWNERSHIP as u32 == 0 {
			OwnershipMode::Native
		} else {
			OwnershipMode::Ignored
		}
	}
}

/// Live mount facts and a separate observation of supported operations.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Volume {
	mount: MountFacts,
	pub locality: Locality,
	pub capabilities: VolumeCapabilities,
}

impl Volume {
	pub fn filesystem_type(&self) -> &CStr {
		self.mount.filesystem_type()
	}

	pub fn is_apfs(&self) -> bool {
		self.mount.is_apfs()
	}

	pub fn mount_flags(&self) -> u32 {
		self.mount.mount_flags()
	}

	pub fn is_read_only(&self) -> bool {
		self.mount.is_read_only()
	}

	pub fn is_automounted(&self) -> bool {
		self.mount.is_automounted()
	}

	pub fn ignores_ownership(&self) -> bool {
		self.mount.ownership_mode() == OwnershipMode::Ignored
	}
}

/// Observe the mount and capabilities for a held directory.
///
/// Capability bits apply only where Darwin marks them valid. An unsupported
/// attribute query yields unknown capabilities, except where mount flags
/// establish that ownership is ignored. The calls sample separate live facts.
/// Inspect the currently authorized directory again after reopening it.
///
/// # Errors
/// Returns an error for a non-directory handle, other native failures, or a
/// malformed response.
pub fn observe(directory: impl AsFd) -> io::Result<Volume> {
	let fd = directory.as_fd();
	let mount = observe_mount(fd)?;
	let (capabilities, attributes) = match query_volume_attributes(fd) {
		Ok(response) => parse_response(&response)?,
		Err(error) if error.kind() == io::ErrorKind::Unsupported => (None, None),
		Err(error) => return Err(error),
	};
	Ok(Volume {
		locality: mount.locality,
		capabilities: volume_capabilities(capabilities, attributes, mount.mount_flags()),
		mount,
	})
}

/// Observe mount classification without querying Darwin capability attributes.
/// # Errors
/// Returns an error for a non-directory, a native failure, or a malformed filesystem name.
pub fn observe_mount(directory: impl AsFd) -> io::Result<MountFacts> {
	let fd = directory.as_fd();
	if FileType::from_raw_mode(fstat(fd)?.st_mode) != FileType::Directory {
		return Err(io::ErrorKind::NotADirectory.into());
	}
	let stat = fstatfs(fd)?;
	let name = stat.f_fstypename.map(|byte| byte as u8);
	let filesystem_type = CStr::from_bytes_until_nul(&name)
		.ok()
		.filter(|name| !name.is_empty())
		.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid filesystem type name"))?
		.to_owned();
	let mount_flags = stat.f_flags;
	let locality = if mount_flags & libc::MNT_LOCAL as u32 != 0 {
		Locality::Local
	} else {
		Locality::Remote
	};
	Ok(MountFacts {
		filesystem_type,
		mount_flags,
		locality,
	})
}

#[allow(unsafe_code, reason = "audited Darwin descriptor attribute query")]
fn query_volume_attributes(fd: BorrowedFd<'_>) -> io::Result<[u32; RESPONSE_WORDS]> {
	let mut request = libc::attrlist {
		bitmapcount: libc::ATTR_BIT_MAP_COUNT,
		reserved: 0,
		commonattr: RETURNED_ATTRIBUTES,
		volattr: libc::ATTR_VOL_INFO | VOLUME_FIELDS,
		dirattr: 0,
		fileattr: 0,
		forkattr: 0,
	};
	let mut response = [0; RESPONSE_WORDS];
	// SAFETY: The borrowed descriptor stays live. The initialized request and
	// aligned response array are disjoint and writable for the supplied sizes.
	// Darwin retains neither pointer. The response length is checked before use.
	let status = unsafe {
		libc::fgetattrlist(
			fd.as_raw_fd(),
			(&raw mut request).cast(),
			response.as_mut_ptr().cast(),
			size_of_val(&response),
			libc::FSOPT_REPORT_FULLSIZE,
		)
	};
	if status != 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(response)
}

// Darwin packs the length, returned attribute bitmap, capabilities, and then
// the volume attributes, in that order. Unreturned fields occupy no payload.
type CapabilitiesResponse = (Option<[u32; CAPABILITIES_WORDS]>, Option<u32>);

fn parse_response(response: &[u32; RESPONSE_WORDS]) -> io::Result<CapabilitiesResponse> {
	let invalid = || {
		io::Error::new(
			io::ErrorKind::InvalidData,
			"invalid Darwin volume attributes",
		)
	};
	let bytes = response[0] as usize;
	let words = bytes / WORD_BYTES;
	if !bytes.is_multiple_of(WORD_BYTES) || !(HEADER_WORDS..=RESPONSE_WORDS).contains(&words) {
		return Err(invalid());
	}
	let [_, common, volume, directory, file, fork, payload @ ..] = &response[..words] else {
		return Err(invalid());
	};
	if *common != RETURNED_ATTRIBUTES
		|| *volume & !VOLUME_FIELDS != 0
		|| *directory | *file | *fork != 0
	{
		return Err(invalid());
	}
	let (capabilities, payload) = if *volume & VOLUME_CAPABILITIES != 0 {
		let (capabilities, rest) = payload.split_first_chunk().ok_or_else(invalid)?;
		(Some(*capabilities), rest)
	} else {
		(None, payload)
	};
	let ownership_attributes = if *volume & VOLUME_ATTRIBUTES != 0 {
		let attributes =
			<&[u32; VOLUME_ATTRIBUTES_WORDS]>::try_from(payload).map_err(|_| invalid())?;
		Some(attributes[0])
	} else if payload.is_empty() {
		None
	} else {
		return Err(invalid());
	};
	Ok((capabilities, ownership_attributes))
}

fn volume_capabilities(
	capabilities: Option<[u32; CAPABILITIES_WORDS]>,
	ownership_attributes: Option<u32>,
	mount_flags: u32,
) -> VolumeCapabilities {
	let ownership = if mount_flags & libc::MNT_IGNORE_OWNERSHIP as u32 != 0 {
		Capability::Unsupported
	} else {
		ownership_attributes.map_or(Capability::Unknown, |attributes| {
			known_support(attributes & OWNERSHIP_ATTRIBUTES == OWNERSHIP_ATTRIBUTES)
		})
	};
	let support = |group: usize, bit: u32, positive: bool| {
		capabilities.map_or(Capability::Unknown, |words| {
			if words[group + VALID_WORD_OFFSET] & bit == 0 {
				Capability::Unknown
			} else {
				known_support((words[group] & bit != 0) == positive)
			}
		})
	};
	let interfaces = libc::VOL_CAPABILITIES_INTERFACES;
	VolumeCapabilities {
		permissions: support(
			libc::VOL_CAPABILITIES_FORMAT,
			libc::VOL_CAP_FMT_NO_PERMISSIONS,
			false,
		),
		ownership,
		acls: support(interfaces, libc::VOL_CAP_INT_EXTENDED_SECURITY, true),
		advisory_locking: support(interfaces, libc::VOL_CAP_INT_FLOCK, true),
		exclusive_rename: support(interfaces, libc::VOL_CAP_INT_RENAME_EXCL, true),
	}
}

fn known_support(supported: bool) -> Capability {
	if supported {
		Capability::Supported
	} else {
		Capability::Unsupported
	}
}
