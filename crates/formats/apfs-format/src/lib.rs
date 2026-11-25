//! Allocation-free Apple File System codecs for raw container objects.
#![no_std]

mod binary;
pub mod checkpoint;
mod error;
pub mod object;
pub mod object_map;
pub mod superblock;
pub mod volume;

pub use error::Error;
