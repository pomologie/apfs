//! Metadata codec for ordinary, unencrypted APFS volume superblocks.

use core::{fmt, num::NonZeroU64, str};

use crate::{
	binary::{field, u16_at, u32_at, u64_at},
	object::{HEADER_BYTES, Header, ObjectId},
	superblock::{BlockAddress, Geometry},
};

const MAGIC_OFFSET: usize = HEADER_BYTES;
const APSB_MAGIC: [u8; 4] = *b"APSB";
const INDEX_OFFSET: usize = 36;
const FEATURES_OFFSET: usize = 40;
const READ_ONLY_COMPATIBLE_OFFSET: usize = 48;
const INCOMPATIBLE_OFFSET: usize = 56;
const RESERVE_OFFSET: usize = 72;
const QUOTA_OFFSET: usize = 80;
const ALLOCATED_OFFSET: usize = 88;
const ROOT_TREE_TYPE_OFFSET: usize = 116;
const EXTENT_TREE_TYPE_OFFSET: usize = 120;
const SNAPSHOT_TREE_TYPE_OFFSET: usize = 124;
const OBJECT_MAP_OFFSET: usize = 128;
const ROOT_TREE_OFFSET: usize = 136;
const EXTENT_TREE_OFFSET: usize = 144;
const SNAPSHOT_TREE_OFFSET: usize = 152;
const REVERT_TO_XID_OFFSET: usize = 160;
const REVERT_TO_SUPERBLOCK_OFFSET: usize = 168;
const SNAPSHOT_COUNT_OFFSET: usize = 216;
const UUID_OFFSET: usize = 240;
const STATUS_FLAGS_OFFSET: usize = 264;
const NAME_OFFSET: usize = 704;
const NAME_BYTES: usize = 256;
const ROLE_OFFSET: usize = 964;
const ROOT_TO_XID_OFFSET: usize = 968;
const ENCRYPTION_ROLL_OFFSET: usize = 976;
const SNAPSHOT_METADATA_EXTENSION_OFFSET: usize = 1000;
const VOLUME_GROUP_OFFSET: usize = 1008;
const INTEGRITY_META_OFFSET: usize = 1024;
const FILE_EXTENT_TREE_OFFSET: usize = 1032;
const UUID_BYTES: usize = 16;

const NO_SUBTYPE: u32 = 0;
const VIRTUAL_BTREE: u32 = 0x0002;
const PHYSICAL_BTREE: u32 = (1 << 30) | VIRTUAL_BTREE;
const FEATURE_GROUP_INODES: u64 = 1 << 4;
const INCOMPAT_CASE_INSENSITIVE: u64 = 1 << 0;
const INCOMPAT_NORMALIZATION_INSENSITIVE: u64 = 1 << 3;
const SUPPORTED_INCOMPATIBLE: u64 = INCOMPAT_CASE_INSENSITIVE | INCOMPAT_NORMALIZATION_INSENSITIVE;
const UNENCRYPTED: u64 = 1 << 0;
const STATUS_ALWAYS_CHECK_EXTENT_REF: u64 = 1 << 6;
const ORDINARY_STATUS_FLAGS: u64 = UNENCRYPTED | STATUS_ALWAYS_CHECK_EXTENT_REF;
const UNSPECIFIED_ROLE: u16 = 0;
const DATA_ROLE: u16 = 1 << 6;
const EMPTY_UUID: [u8; UUID_BYTES] = [0; UUID_BYTES];

/// A verified APFS volume label stored in its original UTF-8 representation.
#[derive(Clone, Eq, PartialEq)]
pub struct VolumeName {
	bytes: [u8; NAME_BYTES],
	length: usize,
}

impl VolumeName {
	/// Returns the on-disk name up to its first NUL terminator.
	#[must_use]
	pub fn as_str(&self) -> &str {
		str::from_utf8(&self.bytes[..self.length]).expect("volume label is validated at admission")
	}

	fn decode(mut bytes: [u8; NAME_BYTES]) -> Result<Self, Error> {
		let length = bytes
			.iter()
			.position(|&byte| byte == 0)
			.ok_or(Error::InvalidName)?;
		str::from_utf8(&bytes[..length]).map_err(|_| Error::InvalidName)?;
		bytes[length..].fill(0);
		Ok(Self { bytes, length })
	}
}

impl fmt::Debug for VolumeName {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.as_str().fmt(f)
	}
}

impl fmt::Display for VolumeName {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.as_str())
	}
}

/// Role values admitted for ordinary volumes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VolumeRole {
	/// No role is assigned.
	Unspecified,
	/// A data role without linked system-volume metadata.
	Data,
}

/// Feature fields preserved from the superblock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct VolumeFeatures {
	/// Optional feature mask.
	pub optional: u64,
	/// Read-only-compatible feature mask.
	pub read_only_compatible: u64,
	/// Required feature mask.
	pub incompatible: u64,
	/// Filesystem status flags.
	pub status: u64,
}

impl VolumeFeatures {
	/// Filename comparison is configured as case-insensitive on disk.
	#[must_use]
	pub const fn case_insensitive(self) -> bool {
		self.incompatible & INCOMPAT_CASE_INSENSITIVE != 0
	}

	/// Filename comparison is configured as normalization-insensitive on disk.
	#[must_use]
	pub const fn normalization_insensitive(self) -> bool {
		self.incompatible & INCOMPAT_NORMALIZATION_INSENSITIVE != 0
	}
}

/// Allocation declarations in volume superblock blocks, before allocator verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct VolumeAllocation {
	/// Container blocks reserved for the volume.
	pub reserved: u64,
	/// Allocation limit in container blocks, if a quota was set.
	pub quota: Option<NonZeroU64>,
	/// Currently allocated blocks as declared by this volume.
	pub allocated: u64,
}

/// Bounded physical references and a virtual filesystem-root reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct VolumeTrees {
	/// Physical block of the volume-specific object map.
	pub object_map: BlockAddress,
	/// Virtual object ID of the root in the volume's namespace.
	pub root: ObjectId,
	/// Physical block of the extent-reference tree.
	pub extent_references: BlockAddress,
	/// Physical block of the snapshot metadata tree.
	pub snapshot_metadata: BlockAddress,
}

/// A checksummed APSB within an admitted ordinary metadata profile.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct VolumeSuperblock {
	/// Verified virtual object header.
	pub object: Header,
	/// Position of this OID in the container's on-disk volume table.
	pub index: u32,
	/// Volume UUID in wire byte order.
	pub uuid: [u8; UUID_BYTES],
	/// Checked UTF-8 label.
	pub name: VolumeName,
	/// Admitted role.
	pub role: VolumeRole,
	/// Raw feature and status masks.
	pub features: VolumeFeatures,
	/// Bounded reserve, quota and allocation declarations.
	pub allocation: VolumeAllocation,
	/// Declared tree identities, before traversal.
	pub trees: VolumeTrees,
}

impl VolumeSuperblock {
	/// Virtual object kind of a volume superblock.
	pub const OBJECT_KIND: u16 = 0x000d;
	/// Standard volume superblock subtype.
	pub const OBJECT_SUBTYPE: u32 = NO_SUBTYPE;

	/// Decodes exactly one container-sized APSB object.
	///
	/// # Errors
	/// Returns an error for bad checksums, invalid identity/layout fields or
	/// unsupported roles, features and volume states.
	pub fn decode(bytes: &[u8], geometry: Geometry) -> Result<Self, Error> {
		if bytes.len() != geometry.block_bytes() as usize {
			return Err(Error::Format(crate::Error::InvalidGeometry));
		}
		let object = Header::decode(bytes)?;
		if object.object_type != u32::from(Self::OBJECT_KIND)
			|| object.subtype != Self::OBJECT_SUBTYPE
		{
			return Err(Error::Format(crate::Error::UnexpectedObjectType(
				object.object_type,
			)));
		}
		if field(bytes, MAGIC_OFFSET)? != APSB_MAGIC {
			return Err(Error::Format(crate::Error::InvalidMagic));
		}
		let features = VolumeFeatures {
			optional: u64_at(bytes, FEATURES_OFFSET)?,
			read_only_compatible: u64_at(bytes, READ_ONLY_COMPATIBLE_OFFSET)?,
			incompatible: u64_at(bytes, INCOMPATIBLE_OFFSET)?,
			status: u64_at(bytes, STATUS_FLAGS_OFFSET)?,
		};
		let role = ensure_profile(bytes, features)?;
		let uuid = field(bytes, UUID_OFFSET)?;
		if uuid == EMPTY_UUID {
			return Err(Error::InvalidUuid);
		}
		let allocation = VolumeAllocation {
			reserved: u64_at(bytes, RESERVE_OFFSET)?,
			quota: NonZeroU64::new(u64_at(bytes, QUOTA_OFFSET)?),
			allocated: u64_at(bytes, ALLOCATED_OFFSET)?,
		};
		let quota_limit = allocation
			.quota
			.map_or(geometry.block_count(), NonZeroU64::get);
		if quota_limit > geometry.block_count()
			|| allocation.reserved > quota_limit
			|| allocation.allocated > quota_limit
		{
			return Err(Error::InvalidAllocation);
		}
		let trees = decode_trees(bytes, geometry)?;
		Ok(Self {
			object,
			index: u32_at(bytes, INDEX_OFFSET)?,
			uuid,
			name: VolumeName::decode(field(bytes, NAME_OFFSET)?)?,
			role,
			features,
			allocation,
			trees,
		})
	}
}

fn ensure_profile(bytes: &[u8], features: VolumeFeatures) -> Result<VolumeRole, Error> {
	use Unsupported::*;

	if features.incompatible & !SUPPORTED_INCOMPATIBLE != 0 {
		return Err(Error::Unsupported(IncompatibleFeatures(
			features.incompatible,
		)));
	}
	if features.status & UNENCRYPTED == 0
		|| features.status & !ORDINARY_STATUS_FLAGS != 0
		|| u64_at(bytes, ENCRYPTION_ROLL_OFFSET)? != 0
	{
		return Err(Error::Unsupported(StatusFlags(features.status)));
	}
	if features.optional & FEATURE_GROUP_INODES != 0
		|| field(bytes, VOLUME_GROUP_OFFSET)? != EMPTY_UUID
	{
		return Err(Error::Unsupported(VolumeGroup));
	}
	if u64_at(bytes, SNAPSHOT_COUNT_OFFSET)? != 0
		|| u64_at(bytes, REVERT_TO_XID_OFFSET)? != 0
		|| u64_at(bytes, REVERT_TO_SUPERBLOCK_OFFSET)? != 0
		|| u64_at(bytes, ROOT_TO_XID_OFFSET)? != 0
		|| u64_at(bytes, SNAPSHOT_METADATA_EXTENSION_OFFSET)? != 0
	{
		return Err(Error::Unsupported(SnapshotOrRevert));
	}
	if u64_at(bytes, INTEGRITY_META_OFFSET)? != 0 || u64_at(bytes, FILE_EXTENT_TREE_OFFSET)? != 0 {
		return Err(Error::Unsupported(SealedMetadata));
	}
	match u16_at(bytes, ROLE_OFFSET)? {
		UNSPECIFIED_ROLE => Ok(VolumeRole::Unspecified),
		DATA_ROLE => Ok(VolumeRole::Data),
		role => Err(Error::Unsupported(Role(role))),
	}
}

fn decode_trees(bytes: &[u8], geometry: Geometry) -> Result<VolumeTrees, Error> {
	for (offset, supported) in [
		(ROOT_TREE_TYPE_OFFSET, VIRTUAL_BTREE),
		(EXTENT_TREE_TYPE_OFFSET, PHYSICAL_BTREE),
		(SNAPSHOT_TREE_TYPE_OFFSET, PHYSICAL_BTREE),
	] {
		let object_type = u32_at(bytes, offset)?;
		if object_type != supported {
			return Err(Error::Unsupported(Unsupported::TreeType(object_type)));
		}
	}
	let object_map = physical_reference(bytes, OBJECT_MAP_OFFSET, geometry)?;
	let extent_references = physical_reference(bytes, EXTENT_TREE_OFFSET, geometry)?;
	let snapshot_metadata = physical_reference(bytes, SNAPSHOT_TREE_OFFSET, geometry)?;
	let root = ObjectId(u64_at(bytes, ROOT_TREE_OFFSET)?);
	if object_map == extent_references
		|| object_map == snapshot_metadata
		|| extent_references == snapshot_metadata
		|| root.0 == 0
	{
		return Err(Error::InvalidTreeReference);
	}
	Ok(VolumeTrees {
		object_map,
		root,
		extent_references,
		snapshot_metadata,
	})
}

fn physical_reference(
	bytes: &[u8],
	offset: usize,
	geometry: Geometry,
) -> Result<BlockAddress, Error> {
	let address = BlockAddress(u64_at(bytes, offset)?);
	if address.0 == 0 || geometry.byte_range(address, 1).is_err() {
		return Err(Error::InvalidTreeReference);
	}
	Ok(address)
}

/// A feature or volume state outside the ordinary APSB profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Unsupported {
	/// At least one required feature is outside the supported mask.
	IncompatibleFeatures(u64),
	/// Encryption, an encryption transition, or an unknown status bit is present.
	StatusFlags(u64),
	/// System/data volume grouping metadata is present.
	VolumeGroup,
	/// A snapshot or pending revert requires a separate view.
	SnapshotOrRevert,
	/// The volume declares sealed-data integrity or file-extent metadata.
	SealedMetadata,
	/// Volume role requiring specialized interpretation.
	Role(u16),
	/// Unexpected tree kind, namespace, or flags.
	TreeType(u32),
}

/// A volume superblock failed metadata admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
	/// Standard object header, checksum or signature validation failed.
	Format(crate::Error),
	/// The bounded volume name is missing a terminator or is not UTF-8.
	InvalidName,
	/// The UUID is all zeroes.
	InvalidUuid,
	/// Reserve, quota and allocation declarations are outside bounds.
	InvalidAllocation,
	/// A tree reference is empty, aliased or outside the container geometry.
	InvalidTreeReference,
	/// The superblock requires an unimplemented profile.
	Unsupported(Unsupported),
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Format(error) => write!(f, "invalid APFS volume object: {error}"),
			Self::InvalidName => f.write_str("invalid APFS volume name"),
			Self::InvalidUuid => f.write_str("invalid APFS volume UUID"),
			Self::InvalidAllocation => f.write_str("invalid APFS volume allocation declarations"),
			Self::InvalidTreeReference => f.write_str("invalid APFS volume tree reference"),
			Self::Unsupported(reason) => write!(f, "unsupported APFS volume profile: {reason:?}"),
		}
	}
}

impl From<crate::Error> for Error {
	fn from(error: crate::Error) -> Self {
		Self::Format(error)
	}
}

impl core::error::Error for Error {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			Self::Format(error) => Some(error),
			_ => None,
		}
	}
}
