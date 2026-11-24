//! Portable read-only APFS storage contracts.
#![no_std]

/// A byte displacement from the beginning of a bounded source.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ByteOffset(pub u64);

/// A finite source whose contents and identity remain stable for the view.
///
/// A source backed by mutable storage must detect changes and surface them as
/// errors. An exact read either fills the entire destination, or fails.
pub trait ReadAt {
	/// An underlying range, I/O or source-change error.
	type Error;

	/// Length of this source in bytes.
	fn len(&self) -> u64;

	/// Whether this source is empty.
	fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// Reads exactly the requested bytes. Empty reads at EOF succeed.
	///
	/// # Errors
	/// Rejects out-of-range requests and propagates I/O and source failures.
	fn read_exact_at(&self, offset: ByteOffset, out: &mut [u8]) -> Result<(), Self::Error>;
}

impl<S: ReadAt + ?Sized> ReadAt for &S {
	type Error = S::Error;
	fn len(&self) -> u64 {
		(**self).len()
	}
	fn read_exact_at(&self, offset: ByteOffset, out: &mut [u8]) -> Result<(), Self::Error> {
		(**self).read_exact_at(offset, out)
	}
}

/// A read falls outside the source slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundsError;

impl core::fmt::Display for BoundsError {
	fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		formatter.write_str("byte range exceeds the source")
	}
}

impl core::error::Error for BoundsError {}

impl ReadAt for [u8] {
	type Error = BoundsError;
	fn len(&self) -> u64 {
		self.len() as u64
	}
	fn read_exact_at(&self, offset: ByteOffset, out: &mut [u8]) -> Result<(), Self::Error> {
		let start = usize::try_from(offset.0).map_err(|_| BoundsError)?;
		let end = start.checked_add(out.len()).ok_or(BoundsError)?;
		out.copy_from_slice(self.get(start..end).ok_or(BoundsError)?);
		Ok(())
	}
}
