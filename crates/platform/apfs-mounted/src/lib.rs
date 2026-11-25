//! Hosted observations and operations on caller-authorized macOS handles.
//!
//! The portable APFS image crates do not depend on this companion.

#![cfg(target_os = "macos")]
#![deny(unsafe_code)]

mod scope;

pub use scope::{
	Directory, DirectoryCreateError, EntryName, EventHandle, InvalidEntryName,
	MAX_ENTRY_NAME_BYTES, stored_name,
};
