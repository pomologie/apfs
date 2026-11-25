//! Bounded Darwin attribute-list I/O and header decoding.

use std::{
	io,
	os::fd::{AsRawFd, BorrowedFd},
};

use super::ObservationError;

pub(super) const WORD_BYTES: usize = size_of::<u32>();
pub(super) const HEADER_BYTES: usize = WORD_BYTES + size_of::<libc::attribute_set_t>();

#[repr(align(4))]
pub(super) struct AttributeBuffer<const BYTES: usize>(pub(super) [u8; BYTES]);

pub(super) const fn request(commonattr: u32) -> libc::attrlist {
	libc::attrlist {
		bitmapcount: libc::ATTR_BIT_MAP_COUNT,
		reserved: 0,
		commonattr,
		volattr: 0,
		dirattr: 0,
		fileattr: 0,
		forkattr: 0,
	}
}

#[allow(
	unsafe_code,
	reason = "Darwin descriptor attribute query with a bounded aligned buffer"
)]
pub(super) fn read<'buffer, const BYTES: usize>(
	fd: BorrowedFd<'_>,
	mut request: libc::attrlist,
	buffer: &'buffer mut AttributeBuffer<BYTES>,
	limit: usize,
	options: u32,
) -> Result<&'buffer [u8], ObservationError> {
	// SAFETY: fd remains borrowed. The initialized attribute request and
	// aligned output buffer are writable and disjoint. Darwin writes at most
	// the supplied size and retains neither pointer after this call.
	let status = unsafe {
		libc::fgetattrlist(
			fd.as_raw_fd(),
			(&raw mut request).cast(),
			buffer.0.as_mut_ptr().cast(),
			BYTES,
			libc::FSOPT_REPORT_FULLSIZE | options,
		)
	};
	if status != 0 {
		return Err(io::Error::last_os_error().into());
	}
	let length =
		word(&buffer.0, 0).ok_or(ObservationError::Malformed("attribute header"))? as usize;
	let limit = limit.min(BYTES);
	if length > limit {
		return Err(ObservationError::Limit {
			limit,
			observed: length,
		});
	}
	if length < HEADER_BYTES {
		return Err(ObservationError::Malformed("attribute header"));
	}
	Ok(&buffer.0[..length])
}

#[allow(
	unsafe_code,
	reason = "Darwin descriptor attribute update with a bounded aligned buffer"
)]
pub(super) fn set<const BYTES: usize>(
	fd: BorrowedFd<'_>,
	mut request: libc::attrlist,
	buffer: &mut AttributeBuffer<BYTES>,
) -> io::Result<()> {
	// SAFETY: fd remains borrowed. The initialized request and aligned input
	// buffer are disjoint, valid for the supplied length, and remain live
	// throughout this synchronous call. Darwin retains neither pointer.
	let status = unsafe {
		libc::fsetattrlist(
			fd.as_raw_fd(),
			(&raw mut request).cast(),
			buffer.0.as_mut_ptr().cast(),
			BYTES,
			0,
		)
	};
	if status == 0 {
		Ok(())
	} else {
		Err(io::Error::last_os_error())
	}
}

pub(super) fn word(bytes: &[u8], offset: usize) -> Option<u32> {
	bytes
		.get(offset..)?
		.first_chunk()
		.map(|word| u32::from_ne_bytes(*word))
}

pub(super) fn returned_fields_equal(bytes: &[u8], common: u32, file: u32) -> bool {
	let expected = [common, 0, 0, file, 0];
	bytes.get(WORD_BYTES..HEADER_BYTES).is_some_and(|header| {
		let (words, remaining) = header.as_chunks::<WORD_BYTES>();
		remaining.is_empty() && words == expected.map(u32::to_ne_bytes)
	})
}
