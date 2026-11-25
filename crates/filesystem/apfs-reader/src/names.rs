//! Keys for the admitted APFS directory name equality profiles.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use crate::record::valid_name;

mod normalize;
mod tables;

/// How an admitted APFS volume compares directory name components.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NameProfile {
	/// An unhashed, bytewise UTF-8 directory catalog.
	Binary,
	/// Canonical decomposition of Unicode 9 scalars with case preserved.
	Unicode9Normalized,
	/// Canonical caseless matching of Unicode 9 scalars.
	Unicode9Folded,
}

impl NameProfile {
	/// Selects the on-disk profile from the admitted APFS volume flags.
	/// Case-insensitive directory names also use canonical decomposition.
	#[must_use]
	pub const fn for_flags(case_insensitive: bool, normalization_insensitive: bool) -> Self {
		match (case_insensitive, normalization_insensitive) {
			(true, _) => Self::Unicode9Folded,
			(false, true) => Self::Unicode9Normalized,
			(false, false) => Self::Binary,
		}
	}

	/// Returns the full UTF-8 equality key for one directory name component.
	/// The key has no trailing NUL. It is distinct from the stored name and
	/// the truncated directory-record hash.
	///
	/// # Errors
	/// Returns an error if the component is invalid, contains a scalar outside
	/// the qualified profile, exceeds the normalization bound, or cannot be
	/// allocated.
	pub fn key(self, name: &str) -> Result<Vec<u8>, NameError> {
		if !valid_name(name) {
			return Err(NameError::InvalidComponent);
		}
		match self {
			Self::Binary => copy_bytes(name, false),
			Self::Unicode9Normalized if name.is_ascii() => copy_bytes(name, false),
			Self::Unicode9Folded if name.is_ascii() => copy_bytes(name, true),
			Self::Unicode9Normalized | Self::Unicode9Folded => {
				normalize::key(name, self == Self::Unicode9Folded)
			}
		}
	}
}

/// An APFS directory equality key could not be produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NameError {
	/// The input is empty, reserved, contains a separator or NUL, or is too long.
	InvalidComponent,
	/// The input scalar is outside the qualified Unicode 9 repertoire.
	UnsupportedScalar { scalar: char },
	/// A normalization step exceeded its bounded depth or output size.
	NormalizationLimit,
	/// A mapping in the embedded Unicode data did not decode as scalars.
	InvalidTable,
	/// A name key buffer could not be reserved.
	Allocation,
}

impl fmt::Display for NameError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidComponent => formatter.write_str("invalid APFS name component"),
			Self::UnsupportedScalar { scalar } => write!(
				formatter,
				"scalar U+{:04X} is outside the APFS Unicode 9 name profile",
				u32::from(*scalar),
			),
			Self::NormalizationLimit => {
				formatter.write_str("APFS name normalization limit exceeded")
			}
			Self::InvalidTable => formatter.write_str("invalid APFS Unicode mapping data"),
			Self::Allocation => formatter.write_str("could not allocate APFS name key"),
		}
	}
}

impl core::error::Error for NameError {}

fn copy_bytes(name: &str, fold: bool) -> Result<Vec<u8>, NameError> {
	let mut key = Vec::new();
	key.try_reserve_exact(name.len())
		.map_err(|_| NameError::Allocation)?;
	key.extend_from_slice(name.as_bytes());
	if fold {
		key.make_ascii_lowercase();
	}
	Ok(key)
}

#[cfg(test)]
mod tests;
