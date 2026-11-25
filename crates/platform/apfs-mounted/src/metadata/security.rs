//! Extended-security observations and empty ACL provisioning on Darwin.

use std::{io, os::fd::AsFd};

use rustix::fs::{FileType, fstat};

use super::{
	ApplyError, ObservationError,
	attributes::{self, AttributeBuffer, HEADER_BYTES, WORD_BYTES},
};

const SECURITY_MASK: u32 = libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_EXTENDED_SECURITY;
const REFERENCE_BYTES: usize = size_of::<libc::attrreference_t>();
const PAYLOAD_OFFSET: usize = HEADER_BYTES + REFERENCE_BYTES;

// Portable wire layout facts from XNU sys/kauth.h. Decode manually to
// preserve bounds and avoid importing the kernel's private structure ABI.
const FILESEC_MAGIC: u32 = 0x012c_c16d;
const FILESEC_NO_ACL: u32 = u32::MAX;
const GUID_BYTES: usize = 16;
const GUID_MASK: u32 = libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_UUID | libc::ATTR_CMN_GRPUUID;
const GUID_RESPONSE_BYTES: usize = HEADER_BYTES + 2 * GUID_BYTES;
const ENTRY_COUNT_OFFSET: usize = WORD_BYTES + 2 * GUID_BYTES;
const FLAGS_OFFSET: usize = ENTRY_COUNT_OFFSET + WORD_BYTES;
const FILESEC_HEADER_BYTES: usize = FLAGS_OFFSET + WORD_BYTES;
const ACE_BYTES: usize = GUID_BYTES + 2 * WORD_BYTES;
const NATIVE_MAX_ENTRIES: u32 = 128;

/// Maximum bytes admitted for the native descriptor security response.
pub const MAX_EXTENDED_SECURITY_BYTES: usize =
	PAYLOAD_OFFSET + FILESEC_HEADER_BYTES + NATIVE_MAX_ENTRIES as usize * ACE_BYTES;

/// Result of a descriptor-relative Darwin extended-security query.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtendedSecurity {
	/// Darwin omitted the extended-security bit from returned attributes.
	NotReturned {
		/// APFS may return a zero reference for an inode with no ACL.
		/// This field records the exact observed encoding. On an unknown or
		/// unsupported filesystem, an omitted bit may have another cause.
		empty_reference: bool,
	},
	Present(SecurityPayload),
}

impl ExtendedSecurity {
	/// Reports the native APFS no-entry encoding or an admitted empty ACL.
	/// Use this predicate only after admitting a volume with verified support
	/// for the native extended-security observations.
	#[must_use]
	pub fn has_no_acl_entries(&self) -> bool {
		match self {
			Self::NotReturned { empty_reference } => *empty_reference,
			Self::Present(payload) => payload.entry_count.unwrap_or(0) == 0 && payload.flags == 0,
		}
	}
}

/// Admitted Darwin file-security metadata. ACE bytes remain opaque.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SecurityPayload {
	/// Owner GUID bytes packed in the ACL payload. Use [`security_guids`] for
	/// the separate kernel owner GUID observation.
	pub owner_guid: [u8; GUID_BYTES],
	/// Group GUID bytes packed in the ACL payload.
	pub group_guid: [u8; GUID_BYTES],
	/// `None` is Darwin's no-ACL marker. `Some(0)` is an explicit empty ACL.
	pub entry_count: Option<u32>,
	pub flags: u32,
	pub raw_entries: Vec<u8>,
}

/// Read bounded extended-security metadata from an already held descriptor.
///
/// The byte limit includes the returned attribute header, reference, and
/// payload. The native response is also capped by the supported ACL entry limit.
/// # Errors
/// Returns an error on permission denial, unsupported operations, malformed or
/// oversized security metadata, allocation failure, or descriptor I/O failure.
pub fn extended_security(
	fd: impl AsFd,
	max_bytes: usize,
) -> Result<ExtendedSecurity, ObservationError> {
	let mut buffer = AttributeBuffer([0; MAX_EXTENDED_SECURITY_BYTES]);
	let bytes = attributes::read(
		fd.as_fd(),
		attributes::request(SECURITY_MASK),
		&mut buffer,
		max_bytes,
		0,
	)?;
	parse_security(bytes)
}

/// Owner/group security identifiers reported independently of the ACL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SecurityGuids {
	/// `None` means the kernel omitted the owner UUID bit.
	pub owner: Option<[u8; GUID_BYTES]>,
	/// `None` means the kernel omitted the group UUID bit.
	pub group: Option<[u8; GUID_BYTES]>,
}

/// Observe the kernel's owner and group GUID attributes on a held descriptor.
/// Darwin can report them separately from the GUID bytes in the ACL payload.
/// # Errors
/// Returns an error for a malformed response, permission denial, unsupported
/// query or descriptor I/O failure.
pub fn security_guids(fd: impl AsFd) -> Result<SecurityGuids, ObservationError> {
	let mut buffer = AttributeBuffer([0; GUID_RESPONSE_BYTES]);
	let bytes = attributes::read(
		fd.as_fd(),
		attributes::request(GUID_MASK),
		&mut buffer,
		GUID_RESPONSE_BYTES,
		libc::FSOPT_PACK_INVAL_ATTRS,
	)?;
	parse_guids(bytes)
}

fn parse_guids(bytes: &[u8]) -> Result<SecurityGuids, ObservationError> {
	let malformed = || ObservationError::Malformed("security GUIDs");
	let common = attributes::word(bytes, WORD_BYTES).ok_or_else(malformed)?;
	if common & !GUID_MASK != 0
		|| common & libc::ATTR_CMN_RETURNED_ATTRS == 0
		|| !attributes::returned_fields_equal(bytes, common, 0)
	{
		return Err(malformed());
	}
	let payload = bytes.get(HEADER_BYTES..).ok_or_else(malformed)?;
	let (guids, remaining) = payload.as_chunks::<GUID_BYTES>();
	let (&[owner, group], []) = (guids, remaining) else {
		return Err(malformed());
	};
	let owner_returned = common & libc::ATTR_CMN_UUID != 0;
	let group_returned = common & libc::ATTR_CMN_GRPUUID != 0;
	if (!owner_returned && owner != [0; GUID_BYTES])
		|| (!group_returned && group != [0; GUID_BYTES])
	{
		return Err(malformed());
	}
	Ok(SecurityGuids {
		owner: owner_returned.then_some(owner),
		group: group_returned.then_some(group),
	})
}

fn parse_security(bytes: &[u8]) -> Result<ExtendedSecurity, ObservationError> {
	let malformed = || ObservationError::Malformed("extended security");
	if attributes::returned_fields_equal(bytes, libc::ATTR_CMN_RETURNED_ATTRS, 0) {
		return match bytes.get(HEADER_BYTES..) {
			Some([]) => Ok(ExtendedSecurity::NotReturned {
				empty_reference: false,
			}),
			Some(reference) if reference == [0; REFERENCE_BYTES] => {
				Ok(ExtendedSecurity::NotReturned {
					empty_reference: true,
				})
			}
			_ => Err(malformed()),
		};
	}
	if !attributes::returned_fields_equal(bytes, SECURITY_MASK, 0) {
		return Err(malformed());
	}
	let reference = attributes::word(bytes, HEADER_BYTES).ok_or_else(malformed)? as usize;
	let length = attributes::word(bytes, HEADER_BYTES + WORD_BYTES).ok_or_else(malformed)? as usize;
	if reference != REFERENCE_BYTES || PAYLOAD_OFFSET.checked_add(length) != Some(bytes.len()) {
		return Err(malformed());
	}
	let payload = bytes.get(PAYLOAD_OFFSET..).ok_or_else(malformed)?;
	if attributes::word(payload, 0) != Some(FILESEC_MAGIC) {
		return Err(malformed());
	}
	let count = attributes::word(payload, ENTRY_COUNT_OFFSET).ok_or_else(malformed)?;
	let entry_count = (count != FILESEC_NO_ACL).then_some(count);
	let entries = entry_count.unwrap_or(0);
	if entries > NATIVE_MAX_ENTRIES
		|| payload.len() != FILESEC_HEADER_BYTES + entries as usize * ACE_BYTES
	{
		return Err(malformed());
	}
	let mut raw_entries = Vec::new();
	let raw = &payload[FILESEC_HEADER_BYTES..];
	raw_entries
		.try_reserve_exact(raw.len())
		.map_err(ObservationError::Allocation)?;
	raw_entries.extend_from_slice(raw);
	Ok(ExtendedSecurity::Present(SecurityPayload {
		owner_guid: payload[WORD_BYTES..WORD_BYTES + GUID_BYTES]
			.try_into()
			.map_err(|_| malformed())?,
		group_guid: payload[WORD_BYTES + GUID_BYTES..ENTRY_COUNT_OFFSET]
			.try_into()
			.map_err(|_| malformed())?,
		entry_count,
		flags: attributes::word(payload, FLAGS_OFFSET).ok_or_else(malformed)?,
		raw_entries,
	}))
}

/// Provision and confirm an explicit empty ACL on a newly created directory.
///
/// Use only on a private directory whose descriptor is already bound to the
/// caller's exclusive creation. The read-back covers the returned ACL payload.
/// # Errors
/// Returns an error when the descriptor is not a directory, the update fails,
/// or an explicit empty ACL cannot be confirmed. A read-back error can follow
/// an acknowledged update.
pub fn set_empty_acl_on_fresh_directory(fd: impl AsFd) -> Result<ExtendedSecurity, ApplyError> {
	let fd = fd.as_fd();
	let status = fstat(fd).map_err(|error| ApplyError::Update(error.into()))?;
	if FileType::from_raw_mode(status.st_mode) != FileType::Directory {
		return Err(ApplyError::Update(io::Error::new(
			io::ErrorKind::NotADirectory,
			"ACL provisioning requires a directory",
		)));
	}
	const SET_BYTES: usize = REFERENCE_BYTES + FILESEC_HEADER_BYTES;
	let mut buffer = AttributeBuffer([0; SET_BYTES]);
	let reference = (REFERENCE_BYTES as i32).to_ne_bytes();
	let length = (FILESEC_HEADER_BYTES as u32).to_ne_bytes();
	buffer.0[..WORD_BYTES].copy_from_slice(&reference);
	buffer.0[WORD_BYTES..REFERENCE_BYTES].copy_from_slice(&length);
	buffer.0[REFERENCE_BYTES..REFERENCE_BYTES + WORD_BYTES]
		.copy_from_slice(&FILESEC_MAGIC.to_ne_bytes());
	attributes::set(
		fd,
		attributes::request(libc::ATTR_CMN_EXTENDED_SECURITY),
		&mut buffer,
	)
	.map_err(ApplyError::Update)?;
	let observed =
		extended_security(fd, MAX_EXTENDED_SECURITY_BYTES).map_err(ApplyError::ReadBack)?;
	if let ExtendedSecurity::Present(payload) = &observed
		&& payload.entry_count == Some(0)
		&& payload.flags == 0
		&& payload.owner_guid == [0; GUID_BYTES]
		&& payload.group_guid == [0; GUID_BYTES]
	{
		Ok(observed)
	} else {
		Err(ApplyError::UnexpectedSecurity(observed))
	}
}

#[cfg(test)]
mod tests;
