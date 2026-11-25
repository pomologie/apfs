//! Audited Darwin query for a physical FSID and its corresponding inode.

use std::{
	ffi::CStr,
	io,
	num::NonZeroU64,
	os::fd::{AsRawFd, BorrowedFd},
};

use super::IdentityError;

// The response is a length word, returned bitmaps, physical FSID, and FILEID.
// Darwin aligns the fields to word boundaries, including the 64-bit file ID.
const WORD_BYTES: usize = size_of::<u32>();
const FSID_OFFSET: usize = 1 + size_of::<libc::attribute_set_t>() / WORD_BYTES;
const FILEID_OFFSET: usize = FSID_OFFSET + size_of::<libc::fsid_t>() / WORD_BYTES;
const RESPONSE_WORDS: usize = FILEID_OFFSET + size_of::<u64>() / WORD_BYTES;
const RETURNED_MASK: usize = 1;
const COMMON_ATTRIBUTES: u32 =
	libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_FSID | libc::ATTR_CMN_FILEID;
const OPTIONS: u32 = libc::FSOPT_REPORT_FULLSIZE | libc::FSOPT_RETURN_REALDEV;
const REQUEST: libc::attrlist = libc::attrlist {
	bitmapcount: libc::ATTR_BIT_MAP_COUNT,
	reserved: 0,
	commonattr: COMMON_ATTRIBUTES,
	volattr: 0,
	dirattr: 0,
	fileattr: 0,
	forkattr: 0,
};

type Response = [u32; RESPONSE_WORDS];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RealIdentity {
	pub(super) physical_fsid: [u32; 2],
	pub(super) inode: NonZeroU64,
}

#[allow(
	unsafe_code,
	reason = "Darwin physical FSID and FILEID for a held descriptor"
)]
pub(super) fn held(fd: BorrowedFd<'_>) -> Result<RealIdentity, IdentityError> {
	let mut request = REQUEST;
	let mut response = [0; RESPONSE_WORDS];
	// SAFETY: `fd` remains borrowed during the synchronous call. The request
	// and word-aligned response are distinct, initialized stack allocations.
	// The kernel may write at most the advertised response length and retains
	// neither pointer. Every written bit pattern represents valid `u32` data.
	let status = unsafe {
		libc::fgetattrlist(
			fd.as_raw_fd(),
			(&raw mut request).cast(),
			response.as_mut_ptr().cast(),
			size_of_val(&response),
			OPTIONS,
		)
	};
	checked_response(status, &response)
}

#[allow(
	unsafe_code,
	reason = "Darwin physical FSID and FILEID for a relative entry"
)]
pub(super) fn named(fd: BorrowedFd<'_>, name: &CStr) -> Result<RealIdentity, IdentityError> {
	let mut request = REQUEST;
	let mut response = [0; RESPONSE_WORDS];
	// SAFETY: The directory remains borrowed and the NUL-terminated C string
	// remains readable during the synchronous call. The request and output
	// are distinct, initialized allocations of the documented layout and
	// alignment. The kernel can only write within the supplied response length
	// and does not retain any pointer.
	let status = unsafe {
		libc::getattrlistat(
			fd.as_raw_fd(),
			name.as_ptr(),
			(&raw mut request).cast(),
			response.as_mut_ptr().cast(),
			size_of_val(&response),
			u64::from(OPTIONS | libc::FSOPT_NOFOLLOW),
		)
	};
	checked_response(status, &response)
}

fn checked_response(
	status: libc::c_int,
	response: &Response,
) -> Result<RealIdentity, IdentityError> {
	if status != 0 {
		return Err(IdentityError::Io(io::Error::last_os_error()));
	}
	decode(response).ok_or(IdentityError::Unavailable)
}

fn decode(response: &Response) -> Option<RealIdentity> {
	if usize::try_from(response[0]).ok()? != size_of_val(response)
		|| response[RETURNED_MASK] != COMMON_ATTRIBUTES
		|| response[RETURNED_MASK + 1..FSID_OFFSET]
			.iter()
			.any(|&word| word != 0)
	{
		return None;
	}
	let physical_fsid: [u32; 2] = response[FSID_OFFSET..FILEID_OFFSET].try_into().ok()?;
	if physical_fsid == [0; 2] {
		return None;
	}
	let mut file_id = [0; size_of::<u64>()];
	for (bytes, word) in file_id
		.as_chunks_mut::<WORD_BYTES>()
		.0
		.iter_mut()
		.zip(&response[FILEID_OFFSET..])
	{
		*bytes = word.to_ne_bytes();
	}
	Some(RealIdentity {
		physical_fsid,
		inode: NonZeroU64::new(u64::from_ne_bytes(file_id))?,
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn requires_a_complete_returned_mask_and_nonzero_ids() {
		let mut response = [0; RESPONSE_WORDS];
		response[0] = u32::try_from(size_of_val(&response)).unwrap();
		response[RETURNED_MASK] = COMMON_ATTRIBUTES;
		response[FSID_OFFSET..FILEID_OFFSET].copy_from_slice(&[123, 456]);
		let expected = 0x1234_5678_abcd_ef01_u64;
		for (word, bytes) in response[FILEID_OFFSET..]
			.iter_mut()
			.zip(expected.to_ne_bytes().as_chunks::<WORD_BYTES>().0)
		{
			*word = u32::from_ne_bytes(*bytes);
		}
		let identity = decode(&response).unwrap();
		assert_eq!(identity.inode.get(), expected);
		assert_eq!(identity.physical_fsid, [123, 456]);
		for (field, value) in [
			(0, response[0] - WORD_BYTES as u32),
			(0, response[0] + WORD_BYTES as u32),
			(RETURNED_MASK, COMMON_ATTRIBUTES & !libc::ATTR_CMN_FILEID),
			(RETURNED_MASK + 1, 1),
		] {
			let mut invalid = response;
			invalid[field] = value;
			assert_eq!(decode(&invalid), None);
		}
		for area in [FSID_OFFSET..FILEID_OFFSET, FILEID_OFFSET..RESPONSE_WORDS] {
			let mut invalid = response;
			invalid[area].fill(0);
			assert_eq!(decode(&invalid), None);
		}
	}
}
