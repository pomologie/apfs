//! Bounded APFS filesystem reads in an immutable selected volume.
#![no_std]
#![forbid(unsafe_code)]

mod ancestry;
mod check;
mod error;
mod extent_refs;
mod hard_links;
mod names;
mod node;
mod payload;
mod record;
mod volume;
mod walk;
mod wire;
mod xattr;

pub use check::{CheckData, CheckOptions, CheckReport};
pub use error::{Corruption, Error, Limit, Unsupported};
pub use hard_links::{EntryMetadata, HardLink, SiblingId};
pub use names::{NameError, NameProfile};
pub use payload::FileData;
pub use record::{DirectoryEntry, FileKind, Inode, InodeCount, InodeId, StreamSizes, Times};
pub use volume::{DirectoryCursor, DirectoryPage, TreeLimits, VolumeView};
pub use xattr::{Xattr, XattrCursor, XattrData, XattrPage, XattrStorage};
