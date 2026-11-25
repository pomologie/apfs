use core::fmt;

use apfs_format::object::ObjectId;

use crate::{names::NameError, record::InodeId};

/// Invalid structure encountered while reading a filesystem tree or record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Corruption {
	Truncated,
	NodeSize,
	NodeDescriptor,
	TableOfContents,
	OverlappingRecords,
	KeyOrder,
	Route,
	ReusedNode(ObjectId),
	MissingNode(ObjectId),
	RecordKey,
	RecordValue,
	ExtendedFields,
	DirectoryCount,
	DuplicateEntry,
	EquivalentDirectoryNames,
	DuplicateInode,
	RootInode,
	DirectoryTarget,
	RepeatedDirectory,
	RepeatedDataStream,
	OverlappingPayloadExtents,
	SiblingLink,
	SiblingMap,
	HardLinkCount,
	HardLinkDirectory,
	StreamRecord,
	ExtentRecord,
	ExtentCoverage,
	ExtentReference,
	ExtentMetadataAlias,
	SymlinkRecord,
	XattrRecord,
	FinderInfo,
	ResourceForkFlags,
	DuplicateXattr,
	PhysicalNode(apfs_format::Error),
}

/// A known APFS structure outside the admitted profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Unsupported {
	TreeFlags(u32),
	NodeFlags(u16),
	DirectoryEntryFlags(u16),
	DirectoryExtendedField(u8),
	InodeDataFlags(u64),
	InodeDataField(u8),
	ExtentFlags(u8),
	ExtentReferenceKind(u8),
	SharedData,
	SparseData,
	CompressedData,
	EncryptedData,
	SymlinkStorage(u16),
	XattrStorage(u16),
	XattrStreamRecord,
	InodeFinderInfo,
	CheckFileKind(u16),
	HardLinkKind,
}

/// A budget exhausted during checked filesystem traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Limit {
	Depth,
	Nodes,
	Records,
	Page,
	CheckDirectoryDepth,
	CheckDirectoryEntries,
	CheckAttributes,
	CheckExtentRanges,
	CheckPayloadBytes,
}

/// An APFS filesystem metadata operation failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error<E> {
	Container(apfs_container::Error<E>),
	Corrupt(Corruption),
	Unsupported(Unsupported),
	Limit(Limit),
	InvalidName,
	Name(NameError),
	InvalidXattrName,
	InvalidCursor,
	MissingInode(InodeId),
	NotDirectory,
	NotRegularFile,
	NotSymlink,
	FileRange {
		offset: u64,
		bytes: u64,
		length: u64,
	},
	Allocation,
	Cancelled,
}

impl<E> From<apfs_container::Error<E>> for Error<E> {
	fn from(error: apfs_container::Error<E>) -> Self {
		Self::Container(error)
	}
}

impl<E> From<Corruption> for Error<E> {
	fn from(error: Corruption) -> Self {
		Self::Corrupt(error)
	}
}

impl<E> From<Unsupported> for Error<E> {
	fn from(error: Unsupported) -> Self {
		Self::Unsupported(error)
	}
}

impl<E> From<NameError> for Error<E> {
	fn from(error: NameError) -> Self {
		Self::Name(error)
	}
}

impl<E: fmt::Display> fmt::Display for Error<E> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Container(error) => write!(f, "APFS object resolution failed: {error}"),
			Self::Corrupt(reason) => write!(f, "corrupt APFS filesystem metadata: {reason:?}"),
			Self::Unsupported(reason) => {
				write!(f, "unsupported APFS filesystem metadata: {reason:?}")
			}
			Self::Limit(limit) => write!(f, "APFS filesystem read limit exceeded: {limit:?}"),
			Self::InvalidName => f.write_str("invalid APFS name component"),
			Self::Name(error) => write!(f, "APFS native name comparison failed: {error}"),
			Self::InvalidXattrName => f.write_str("invalid APFS extended attribute name"),
			Self::InvalidCursor => f.write_str("APFS cursor is outside this view or inode"),
			Self::MissingInode(id) => write!(f, "APFS inode {} was not found", id.as_raw()),
			Self::NotDirectory => f.write_str("APFS directory inode required"),
			Self::NotRegularFile => f.write_str("APFS regular file inode required"),
			Self::NotSymlink => f.write_str("APFS symbolic link inode required"),
			Self::FileRange {
				offset,
				bytes,
				length,
			} => {
				write!(
					f,
					"APFS file range {offset} + {bytes} exceeds logical length {length}"
				)
			}
			Self::Allocation => f.write_str("could not allocate APFS filesystem read buffer"),
			Self::Cancelled => f.write_str("APFS filesystem verification cancelled"),
		}
	}
}

impl<E: core::error::Error + 'static> core::error::Error for Error<E> {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			Self::Container(error) => Some(error),
			Self::Name(error) => Some(error),
			_ => None,
		}
	}
}
