//! Allocation-free Apple File System codecs for raw container objects.
#![no_std]

mod binary;
pub mod checkpoint;
pub mod object;
pub mod object_map;
pub mod superblock;

/// A failed APFS object or container admission check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
	/// The available bytes end inside a structure.
	Truncated,
	/// APFS container magic is absent.
	InvalidMagic,
	/// A container's block geometry does not fit its bounded device.
	InvalidGeometry,
	/// The checksum disagrees with the bytes of the object.
	InvalidChecksum,
	/// The type and storage flags do not match the requested object kind.
	UnexpectedObjectType(u32),
	/// Fields of a checkpoint or map do not describe a valid range or index.
	InvalidCheckpoint,
	/// Unsupported flags in a checkpoint mapping block.
	UnsupportedCheckpointFlags(u32),
	/// An object map, node header or key/value layout is inconsistent.
	InvalidObjectMap,
	/// Object map or tree flags require an unsupported profile.
	UnsupportedObjectMapFlags(u32),
	/// An object map uses snapshot metadata or an in-progress revert.
	UnsupportedObjectMapSnapshot,
}

impl core::fmt::Display for Error {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			Self::Truncated => f.write_str("truncated APFS structure"),
			Self::InvalidMagic => f.write_str("invalid APFS container magic"),
			Self::InvalidGeometry => f.write_str("invalid APFS container block geometry"),
			Self::InvalidChecksum => f.write_str("APFS object checksum mismatch"),
			Self::UnexpectedObjectType(kind) => {
				write!(f, "unexpected APFS object type {kind:#010x}")
			}
			Self::InvalidCheckpoint => f.write_str("invalid APFS checkpoint metadata"),
			Self::UnsupportedCheckpointFlags(flags) => {
				write!(f, "unsupported APFS checkpoint flags {flags:#010x}")
			}
			Self::InvalidObjectMap => f.write_str("invalid APFS object map metadata"),
			Self::UnsupportedObjectMapFlags(flags) => {
				write!(f, "unsupported APFS object map or tree flags {flags:#010x}")
			}
			Self::UnsupportedObjectMapSnapshot => {
				f.write_str("unsupported APFS object map snapshot or pending revert")
			}
		}
	}
}

impl core::error::Error for Error {}
