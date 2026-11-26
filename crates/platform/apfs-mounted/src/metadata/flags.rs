//! BSD object flags reported by Darwin's stat interfaces.

// Darwin SDK sys/stat.h. These two flags are not exposed by the libc crate.
const SF_FIRMLINK: u32 = 0x0080_0000;
const SF_DATALESS: u32 = 0x4000_0000;

/// BSD object flags, including bits for which this crate supplies no interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectFlags(u32);

impl ObjectFlags {
	/// Interpret a raw Darwin `st_flags` value.
	#[must_use]
	pub const fn from_raw(bits: u32) -> Self {
		Self(bits)
	}

	/// All native bits, including uninterpreted flags.
	#[must_use]
	pub const fn raw(self) -> u32 {
		self.0
	}

	/// Darwin reports this object as a firmlink.
	#[must_use]
	pub const fn is_firmlink(self) -> bool {
		self.0 & SF_FIRMLINK != 0
	}

	/// Darwin reports this object as dataless.
	#[must_use]
	pub const fn is_dataless(self) -> bool {
		self.0 & SF_DATALESS != 0
	}

	/// Darwin reports filesystem compression for this object.
	#[must_use]
	pub const fn is_compressed(self) -> bool {
		self.0 & libc::UF_COMPRESSED != 0
	}
}

#[cfg(test)]
mod tests {
	use super::{ObjectFlags, SF_DATALESS, SF_FIRMLINK};

	#[test]
	fn known_bits_are_independent_and_other_bits_are_retained() {
		let firmlink = ObjectFlags::from_raw(SF_FIRMLINK);
		assert!(firmlink.is_firmlink());
		assert!(!firmlink.is_dataless());
		assert!(!firmlink.is_compressed());

		let bits = SF_DATALESS | libc::UF_COMPRESSED | libc::UF_IMMUTABLE;
		let flags = ObjectFlags::from_raw(bits);
		assert!(flags.is_dataless());
		assert!(flags.is_compressed());
		assert!(!flags.is_firmlink());
		assert_eq!(flags.raw(), bits);
	}
}
