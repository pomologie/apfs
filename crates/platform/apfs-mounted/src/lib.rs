//! Hosted observations and operations on caller-authorized macOS handles.
//!
//! The portable APFS image crates do not depend on this companion.

#![cfg(target_os = "macos")]

pub mod dataless;
pub mod identity;
pub mod lease;
mod scope;
pub mod source;
pub mod volume;

pub use identity::{BirthTime, IdentityError, MountIdentity, ObjectIdentity};
pub use scope::{
	Directory, DirectoryCreateError, EntryName, EventHandle, InvalidEntryName,
	MAX_ENTRY_NAME_BYTES, stored_name,
};
