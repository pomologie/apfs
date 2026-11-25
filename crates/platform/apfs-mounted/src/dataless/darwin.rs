use std::io;

use libc::c_int;

use super::{PolicyError, PolicyIo, ThreadPolicy};

// Scalar Darwin ABI values and function signatures from <sys/resource.h>.
// libc 0.2.191 does not expose these declarations.
const IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES: c_int = 3;
const IOPOL_SCOPE_THREAD: c_int = 1;
const IOPOL_MATERIALIZE_DATALESS_FILES_DEFAULT: c_int = 0;
const IOPOL_MATERIALIZE_DATALESS_FILES_OFF: c_int = 1;
const IOPOL_MATERIALIZE_DATALESS_FILES_ON: c_int = 2;
const NATIVE_SUCCESS: c_int = 0;
const NATIVE_FAILURE: c_int = -1;

// SAFETY: These are the macOS SDK's C signatures. Both take and return only
// scalars. Darwin rejects unsupported arguments with errno and the caller
// supplies no memory or synchronization preconditions.
#[allow(unsafe_code, reason = "Darwin libSystem scalar policy declarations")]
unsafe extern "C" {
	safe fn getiopolicy_np(iotype: c_int, scope: c_int) -> c_int;
	safe fn setiopolicy_np(iotype: c_int, scope: c_int, policy: c_int) -> c_int;
}

pub(super) struct Native;

impl PolicyIo for Native {
	fn current(&self) -> Result<ThreadPolicy, PolicyError> {
		match getiopolicy_np(
			IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES,
			IOPOL_SCOPE_THREAD,
		) {
			IOPOL_MATERIALIZE_DATALESS_FILES_DEFAULT => Ok(ThreadPolicy::Inherited),
			IOPOL_MATERIALIZE_DATALESS_FILES_OFF => Ok(ThreadPolicy::Disabled),
			IOPOL_MATERIALIZE_DATALESS_FILES_ON => Ok(ThreadPolicy::Enabled),
			NATIVE_FAILURE => Err(PolicyError::Io(io::Error::last_os_error())),
			value => Err(PolicyError::UnknownPolicy(value)),
		}
	}

	fn set(&self, policy: ThreadPolicy) -> Result<(), PolicyError> {
		let raw = match policy {
			ThreadPolicy::Inherited => IOPOL_MATERIALIZE_DATALESS_FILES_DEFAULT,
			ThreadPolicy::Disabled => IOPOL_MATERIALIZE_DATALESS_FILES_OFF,
			ThreadPolicy::Enabled => IOPOL_MATERIALIZE_DATALESS_FILES_ON,
		};
		let result = setiopolicy_np(
			IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES,
			IOPOL_SCOPE_THREAD,
			raw,
		);
		if result == NATIVE_SUCCESS {
			Ok(())
		} else {
			Err(PolicyError::Io(io::Error::last_os_error()))
		}
	}
}
