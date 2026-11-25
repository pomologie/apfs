use core::fmt;

use apfs_core::ReadAt;
use apfs_format::object::ObjectId;

use crate::{Container, Error, LookupOptions};

/// A native volume identifier interpreted within one selected checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VolumeSelector {
	/// An exact NXSB volume slot's object identifier.
	ObjectId(ObjectId),
	/// The 16 wire bytes of the checked volume superblock's UUID.
	Uuid([u8; 16]),
}

/// Why a checked checkpoint did not yield an unambiguous volume choice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum VolumeSelectionError {
	/// The checkpoint has no volumes to select implicitly.
	NoVolumes,
	/// The checkpoint requires an explicit selection among several volumes.
	AmbiguousVolumes(usize),
	/// The checkpoint does not contain the requested volume.
	UnknownVolume(VolumeSelector),
}

impl fmt::Display for VolumeSelectionError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::NoVolumes => formatter.write_str("APFS checkpoint has no volumes"),
			Self::AmbiguousVolumes(count) => {
				write!(
					formatter,
					"APFS checkpoint has {count} volumes; select one by UUID or object ID"
				)
			}
			Self::UnknownVolume(selector) => {
				write!(
					formatter,
					"APFS volume selector {selector:?} was not found in the chosen checkpoint"
				)
			}
		}
	}
}

impl core::error::Error for VolumeSelectionError {}

impl<S: ReadAt> Container<S> {
	/// Resolves a volume OID at this checkpoint for subsequent metadata or tree admission.
	///
	/// An explicit object ID only checks the NXSB volume table. UUID selection
	/// and implicit selection require complete metadata admission for every
	/// volume at the checkpoint under one aggregate lookup budget.
	///
	/// # Errors
	/// Returns a volume selection error for absent or ambiguous matches, or
	/// the precise cause of a failed checkpoint-local volume table or lookup.
	pub fn select_volume_id(
		&self,
		selector: Option<VolumeSelector>,
		options: LookupOptions,
	) -> Result<ObjectId, Error<S::Error>> {
		match selector {
			Some(selector @ VolumeSelector::ObjectId(id)) => {
				self.validate_volume_table()?;
				self.superblock()
					.volume_ids()
					.find(|&oid| oid == id)
					.ok_or(Error::VolumeSelection(VolumeSelectionError::UnknownVolume(
						selector,
					)))
			}
			Some(selector @ VolumeSelector::Uuid(uuid)) => self
				.volumes(options)?
				.into_iter()
				.find(|volume| volume.superblock.uuid == uuid)
				.map(|volume| volume.mapping.id)
				.ok_or(Error::VolumeSelection(VolumeSelectionError::UnknownVolume(
					selector,
				))),
			None => match self.volumes(options)?.as_slice() {
				[volume] => Ok(volume.mapping.id),
				[] => Err(Error::VolumeSelection(VolumeSelectionError::NoVolumes)),
				volumes => Err(Error::VolumeSelection(
					VolumeSelectionError::AmbiguousVolumes(volumes.len()),
				)),
			},
		}
	}
}
