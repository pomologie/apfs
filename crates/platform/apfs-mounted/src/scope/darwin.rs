use std::{
	ffi::CStr,
	io,
	os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
};

use super::{Directory, EntryName, MAX_ENTRY_NAME_BYTES};

const NAME_REQUEST: libc::attrgroup_t = libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_NAME;
const WORD: usize = size_of::<u32>();
const REFERENCE: usize = WORD + size_of::<libc::attribute_set_t>();
const PAYLOAD: usize = REFERENCE + size_of::<libc::attrreference_t>();
const BUFFER_BYTES: usize = (PAYLOAD + MAX_ENTRY_NAME_BYTES + 1).next_multiple_of(WORD);

#[repr(C, align(4))]
struct NameBuffer([u8; BUFFER_BYTES]);

#[allow(
	unsafe_code,
	reason = "Darwin event-only open needs the O_EVTONLY flag"
)]
pub(super) fn open_event(directory: &Directory, name: &EntryName) -> io::Result<OwnedFd> {
	let flags = libc::O_EVTONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
	// SAFETY: The borrowed directory stays open. EntryName owns a NUL-terminated
	// component. No O_CREAT flag is passed, so openat needs no mode argument.
	let fd = unsafe {
		libc::openat(
			directory.as_fd().as_raw_fd(),
			name.as_c_str().as_ptr(),
			flags,
		)
	};
	if fd < 0 {
		return Err(io::Error::last_os_error());
	}
	// SAFETY: A successful openat returns a new descriptor owned by this call.
	Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Reads the kernel's stored name from a held object, including event-only fds.
/// This is a live observation. Check the binding relative to an authorized
/// parent when the result is used to validate a private fixed name.
/// # Errors
/// Fails if the attribute is unavailable or its bounded response is invalid.
#[allow(
	unsafe_code,
	reason = "Darwin fgetattrlist is required for the actual stored spelling"
)]
pub fn stored_name(object: impl AsFd) -> io::Result<EntryName> {
	let mut request = libc::attrlist {
		bitmapcount: libc::ATTR_BIT_MAP_COUNT,
		reserved: 0,
		commonattr: NAME_REQUEST,
		volattr: 0,
		dirattr: 0,
		fileattr: 0,
		forkattr: 0,
	};
	let mut buffer = NameBuffer([0; BUFFER_BYTES]);
	// SAFETY: The descriptor, aligned writable buffer and attribute list remain
	// live through the synchronous call. The buffer length is its exact size.
	let result = unsafe {
		libc::fgetattrlist(
			object.as_fd().as_raw_fd(),
			(&raw mut request).cast(),
			buffer.0.as_mut_ptr().cast(),
			buffer.0.len(),
			libc::FSOPT_REPORT_FULLSIZE,
		)
	};
	if result != 0 {
		return Err(io::Error::last_os_error());
	}
	decode(&buffer.0)
		.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid Darwin name attribute"))
}

fn decode(buffer: &[u8]) -> Option<EntryName> {
	let bytes = buffer.get(..usize::try_from(word(buffer, 0)?).ok()?)?;
	if word(bytes, WORD)? != NAME_REQUEST
		|| bytes.get(2 * WORD..REFERENCE)? != [0; REFERENCE - 2 * WORD]
	{
		return None;
	}
	let offset = usize::try_from(word(bytes, REFERENCE)?).ok()?;
	let length = usize::try_from(word(bytes, REFERENCE + WORD)?).ok()?;
	if offset != size_of::<libc::attrreference_t>()
		|| !(2..=MAX_ENTRY_NAME_BYTES + 1).contains(&length)
	{
		return None;
	}
	let name = CStr::from_bytes_with_nul(bytes.get(PAYLOAD..PAYLOAD.checked_add(length)?)?).ok()?;
	EntryName::new(name.to_bytes()).ok()
}

fn word(bytes: &[u8], offset: usize) -> Option<u32> {
	Some(u32::from_ne_bytes(
		bytes.get(offset..offset + WORD)?.try_into().ok()?,
	))
}
