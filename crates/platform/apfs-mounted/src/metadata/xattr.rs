//! Bounded named attribute and resource-fork observations on Darwin.

use std::{
	ffi::{CStr, CString},
	io,
	os::fd::{AsFd, AsRawFd, BorrowedFd},
	ptr,
};

use super::{
	ObservationError,
	attributes::{self, AttributeBuffer, HEADER_BYTES},
};

const FINDER_INFO: &CStr = c"com.apple.FinderInfo";
const RESOURCE_FORK: &CStr = c"com.apple.ResourceFork";
const RESOURCE_RESPONSE_BYTES: usize = HEADER_BYTES + size_of::<libc::off_t>();

/// Width of the native FinderInfo payload in bytes.
pub const FINDER_INFO_BYTES: usize = 32;

/// Which attributes the descriptor query asks the kernel to report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum XattrVisibility {
	Visible,
	IncludingCompression,
}

impl XattrVisibility {
	const fn options(self) -> libc::c_int {
		match self {
			Self::Visible => 0,
			Self::IncludingCompression => libc::XATTR_SHOWCOMPRESSION,
		}
	}
}

/// Two independent native observations about a held object's resource fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResourceFork {
	/// Size of the compression-visible `com.apple.ResourceFork` attribute.
	/// `Some(0)` denotes an attribute that exists with an empty payload.
	pub attribute_length: Option<u64>,
	/// Length reported by `ATTR_FILE_RSRCLENGTH`, when Darwin returned the bit.
	pub reported_length: Option<u64>,
}

impl ResourceFork {
	/// Returns true when the named attribute was absent and Darwin returned a
	/// zero fork length. An omitted length observation is inconclusive.
	#[must_use]
	pub fn confirmed_absent(self) -> bool {
		self.attribute_length.is_none() && self.reported_length == Some(0)
	}
}

/// List the descriptor's complete xattr inventory visible to this process
/// using the selected kernel query option. Names retain their native bytes.
///
/// The limit covers the kernel list including each terminating NUL. A
/// successful result reflects a live observation for this visibility only.
/// # Errors
/// Returns a byte-limit, malformed list, raced read, unsupported operation,
/// permission, allocation or descriptor I/O error.
pub fn list_xattrs(
	fd: impl AsFd,
	visibility: XattrVisibility,
	max_bytes: usize,
) -> Result<Vec<CString>, ObservationError> {
	let fd = fd.as_fd();
	let read = |output: &mut [u8]| list_native(fd, visibility, output);
	let length = read(&mut [])?;
	let bytes = read_bounded(length, max_bytes, read)?;
	parse_names(&bytes)
}

fn parse_names(mut bytes: &[u8]) -> Result<Vec<CString>, ObservationError> {
	let mut names = Vec::new();
	while !bytes.is_empty() {
		let name = CStr::from_bytes_until_nul(bytes)
			.map_err(|_| ObservationError::Malformed("xattr name list"))?;
		if name.is_empty() {
			return Err(ObservationError::Malformed("xattr name list"));
		}
		let length = name.to_bytes_with_nul().len();
		let mut owned = Vec::new();
		owned
			.try_reserve_exact(length)
			.map_err(ObservationError::Allocation)?;
		owned.extend_from_slice(name.to_bytes_with_nul());
		let owned = CString::from_vec_with_nul(owned)
			.map_err(|_| ObservationError::Malformed("xattr name list"))?;
		names.try_reserve(1).map_err(ObservationError::Allocation)?;
		names.push(owned);
		bytes = &bytes[length..];
	}
	Ok(names)
}

/// Read one named attribute as opaque bytes, under an explicit byte limit.
///
/// Returns `None` for `ENOATTR` on the initial observation, and `Some` with an
/// empty buffer for an existing zero-length attribute.
/// # Errors
/// Returns an oversized value, concurrent removal/growth, unsupported
/// operation, permission, allocation or descriptor I/O error.
pub fn read_xattr(
	fd: impl AsFd,
	name: &CStr,
	visibility: XattrVisibility,
	max_bytes: usize,
) -> Result<Option<Vec<u8>>, ObservationError> {
	let fd = fd.as_fd();
	let read = |output: &mut [u8]| get_native(fd, name, visibility, output);
	match read(&mut []) {
		Ok(length) => read_bounded(length, max_bytes, read).map(Some),
		Err(error) if error.raw_os_error() == Some(libc::ENOATTR) => Ok(None),
		Err(error) => Err(error.into()),
	}
}

/// Read and validate the width of the native FinderInfo attribute.
///
/// Returns `None` when the named attribute is absent in the selected query.
/// # Errors
/// Returns a malformed-length or bounded attribute observation error.
pub fn finder_info(
	fd: impl AsFd,
	visibility: XattrVisibility,
) -> Result<Option<[u8; FINDER_INFO_BYTES]>, ObservationError> {
	read_xattr(fd, FINDER_INFO, visibility, FINDER_INFO_BYTES)?
		.map(|bytes| {
			bytes
				.try_into()
				.map_err(|_| ObservationError::Malformed("FinderInfo"))
		})
		.transpose()
}

/// Read the resource fork attribute under an explicit byte limit.
///
/// The query includes compression-visible attributes. `None` means the named
/// attribute was absent. Use [`resource_fork`] for separate fork-length evidence.
/// # Errors
/// Returns the same bounded observation errors as [`read_xattr`].
pub fn read_resource_fork(
	fd: impl AsFd,
	max_bytes: usize,
) -> Result<Option<Vec<u8>>, ObservationError> {
	read_xattr(
		fd,
		RESOURCE_FORK,
		XattrVisibility::IncludingCompression,
		max_bytes,
	)
}

/// Query the named resource-fork attribute and the kernel's fork length.
///
/// Both queries are descriptor-relative and request lengths only. The
/// observations can race metadata changes and should be bracketed by the
/// caller's live identity and metadata checks for strict operations.
/// # Errors
/// Returns an error for malformed length metadata, permission denial,
/// unsupported operations or descriptor I/O failure.
pub fn resource_fork(fd: impl AsFd) -> Result<ResourceFork, ObservationError> {
	let fd = fd.as_fd();
	let visibility = XattrVisibility::IncludingCompression;
	let attribute_length = match get_native(fd, RESOURCE_FORK, visibility, &mut []) {
		Ok(length) => Some(length as u64),
		Err(error) if error.raw_os_error() == Some(libc::ENOATTR) => None,
		Err(error) => return Err(error.into()),
	};
	let mut request = attributes::request(libc::ATTR_CMN_RETURNED_ATTRS);
	request.fileattr = libc::ATTR_FILE_RSRCLENGTH;
	let mut buffer = AttributeBuffer([0; RESOURCE_RESPONSE_BYTES]);
	let bytes = attributes::read(fd, request, &mut buffer, RESOURCE_RESPONSE_BYTES, 0)?;
	Ok(ResourceFork {
		attribute_length,
		reported_length: parse_fork_length(bytes)?,
	})
}

fn parse_fork_length(bytes: &[u8]) -> Result<Option<u64>, ObservationError> {
	let malformed = || ObservationError::Malformed("resource fork length");
	let fields = bytes.get(HEADER_BYTES..).ok_or_else(malformed)?;
	if attributes::returned_fields_equal(bytes, libc::ATTR_CMN_RETURNED_ATTRS, 0)
		&& (fields.is_empty() || fields == [0; size_of::<libc::off_t>()])
	{
		return Ok(None);
	}
	if !attributes::returned_fields_equal(
		bytes,
		libc::ATTR_CMN_RETURNED_ATTRS,
		libc::ATTR_FILE_RSRCLENGTH,
	) {
		return Err(malformed());
	}
	let length = i64::from_ne_bytes(fields.try_into().map_err(|_| malformed())?);
	Ok(Some(u64::try_from(length).map_err(|_| malformed())?))
}

fn read_bounded(
	length: usize,
	limit: usize,
	read: impl FnOnce(&mut [u8]) -> io::Result<usize>,
) -> Result<Vec<u8>, ObservationError> {
	if length > limit {
		return Err(ObservationError::Limit {
			limit,
			observed: length,
		});
	}
	let mut bytes = Vec::new();
	if length == 0 {
		return Ok(bytes);
	}
	bytes
		.try_reserve_exact(length)
		.map_err(ObservationError::Allocation)?;
	bytes.resize(length, 0);
	match read(&mut bytes) {
		Ok(read) if read <= length => {
			bytes.truncate(read);
			Ok(bytes)
		}
		Ok(_) => Err(ObservationError::Malformed("xattr byte count")),
		Err(error) if matches!(error.raw_os_error(), Some(libc::ERANGE | libc::ENOATTR)) => {
			Err(ObservationError::Changed)
		}
		Err(error) => Err(error.into()),
	}
}

#[allow(
	unsafe_code,
	reason = "Darwin xattr inventory query with a bounded caller buffer"
)]
fn list_native(
	fd: BorrowedFd<'_>,
	visibility: XattrVisibility,
	output: &mut [u8],
) -> io::Result<usize> {
	let data = if output.is_empty() {
		ptr::null_mut()
	} else {
		output.as_mut_ptr().cast()
	};
	// SAFETY: fd remains borrowed, and output is writable for its supplied
	// length. A null pointer only requests the size. Darwin retains
	// no buffer pointer after the call.
	let result =
		unsafe { libc::flistxattr(fd.as_raw_fd(), data, output.len(), visibility.options()) };
	usize::try_from(result).map_err(|_| io::Error::last_os_error())
}

#[allow(
	unsafe_code,
	reason = "Darwin compression-aware descriptor xattr query"
)]
fn get_native(
	fd: BorrowedFd<'_>,
	name: &CStr,
	visibility: XattrVisibility,
	output: &mut [u8],
) -> io::Result<usize> {
	let data = if output.is_empty() {
		ptr::null_mut()
	} else {
		output.as_mut_ptr().cast()
	};
	// SAFETY: fd remains borrowed, name is NUL-terminated and read-only, and
	// output is writable for its supplied length. A null pointer queries
	// the length only. Darwin retains neither pointer after the call.
	let result = unsafe {
		libc::fgetxattr(
			fd.as_raw_fd(),
			name.as_ptr(),
			data,
			output.len(),
			0,
			visibility.options(),
		)
	};
	usize::try_from(result).map_err(|_| io::Error::last_os_error())
}

#[cfg(test)]
mod tests;
