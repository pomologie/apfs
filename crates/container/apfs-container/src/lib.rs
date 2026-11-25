//! Bounded APFS checkpoint selection, object-map lookup and volume discovery.
#![no_std]

mod allocation;
mod checkpoint;
mod container;
mod error;
mod object_map;
mod probe;
mod volume;

pub(crate) use allocation::alloc;
pub use checkpoint::{Diagnostic, OpenOptions};
pub use container::Container;
pub use error::{Corruption, Damage, Error, Limit, ObjectMapError, Unsupported, VolumeError};
pub use object_map::{LookupOptions, VirtualMapping, VirtualObject, VirtualType, VolumeObjects};
pub use volume::Volume;
