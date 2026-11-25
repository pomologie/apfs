//! Portable read-only APFS storage contracts.
#![no_std]

mod read_at;

pub use read_at::{BoundsError, ByteOffset, ReadAt};
