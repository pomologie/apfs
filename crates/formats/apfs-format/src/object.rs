//! Checksum and identification for APFS objects with standard object headers.

use core::mem::size_of;

use crate::{
	Error,
	binary::{u32_at, u64_at},
};

// Byte offsets in the APFS obj_phys_t wire header.
const CHECKSUM_OFFSET: usize = 0;
const OBJECT_ID_OFFSET: usize = 8;
const TRANSACTION_ID_OFFSET: usize = 16;
const OBJECT_TYPE_OFFSET: usize = 24;
const SUBTYPE_OFFSET: usize = 28;

/// Standard object header size in bytes.
pub const HEADER_BYTES: usize = SUBTYPE_OFFSET + size_of::<u32>();
const CHECKSUM_BYTES: usize = size_of::<u64>();
const FLETCHER_WORD_BYTES: usize = size_of::<u32>();
const FLETCHER_MODULUS: u64 = (1 << u32::BITS) - 1;

/// Object identifier within the applicable physical, virtual or ephemeral namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId(pub u64);

/// Container-wide transaction identifier, also called an XID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransactionId(pub u64);

/// Verified APFS object header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Header {
	/// On-disk Fletcher-64 checksum.
	pub checksum: u64,
	/// Identifier in the header's storage namespace.
	pub id: ObjectId,
	/// Transaction that produced this version of the object.
	pub transaction: TransactionId,
	/// Full type word, including storage and object flags.
	pub object_type: u32,
	/// Structure-specific subtype.
	pub subtype: u32,
}

impl Header {
	/// Decode and verify the standard header over the complete physical object.
	///
	/// # Errors
	/// Returns an error for incomplete input or an incorrect checksum.
	pub fn decode(object: &[u8]) -> Result<Self, Error> {
		let stored_checksum = u64_at(object, CHECKSUM_OFFSET)?;
		if checksum(object)? != stored_checksum {
			return Err(Error::InvalidChecksum);
		}
		Ok(Self {
			checksum: stored_checksum,
			id: ObjectId(u64_at(object, OBJECT_ID_OFFSET)?),
			transaction: TransactionId(u64_at(object, TRANSACTION_ID_OFFSET)?),
			object_type: u32_at(object, OBJECT_TYPE_OFFSET)?,
			subtype: u32_at(object, SUBTYPE_OFFSET)?,
		})
	}
}

/// Compute the APFS Fletcher-64 check words for a complete object. The first
/// eight bytes of the object contain the stored checksum and are excluded.
///
/// # Errors
/// Returns [`Error::Truncated`] for an input shorter than the standard object
/// header or a partial 32-bit word at the end of the object.
pub fn checksum(object: &[u8]) -> Result<u64, Error> {
	if object.len() < HEADER_BYTES {
		return Err(Error::Truncated);
	}
	let (words, tail) = object[CHECKSUM_BYTES..].as_chunks::<FLETCHER_WORD_BYTES>();
	if !tail.is_empty() {
		return Err(Error::Truncated);
	}
	let (mut low, mut high) = (0, 0);
	for word in words {
		low = (low + u64::from(u32::from_le_bytes(*word))) % FLETCHER_MODULUS;
		high = (high + low) % FLETCHER_MODULUS;
	}
	let check_low = FLETCHER_MODULUS - (low + high) % FLETCHER_MODULUS;
	let check_high = FLETCHER_MODULUS - (low + check_low) % FLETCHER_MODULUS;
	Ok(check_low | (check_high << u32::BITS))
}
