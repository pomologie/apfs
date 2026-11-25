//! Canonical decomposition and default root case folding for Unicode 9.

extern crate alloc;

use alloc::vec::Vec;

use super::{tables, NameError};

// Unicode 9 full canonical decompositions contain at most four scalars.
const MAX_DECOMPOSED_SCALARS: usize = 4;
const MAX_DECOMPOSITION_DEPTH: usize = 4;
const UTF8_SCALAR_BYTES: usize = 4;

const HANGUL_SYLLABLE_BASE: u32 = 0xac00;
const LEADING_JAMO_BASE: u32 = 0x1100;
const VOWEL_JAMO_BASE: u32 = 0x1161;
const TRAILING_JAMO_BASE: u32 = 0x11a7;
const LEADING_JAMO_COUNT: u32 = 19;
const VOWEL_JAMO_COUNT: u32 = 21;
const TRAILING_JAMO_COUNT: u32 = 28;
const VOWEL_TRAILING_COUNT: u32 = VOWEL_JAMO_COUNT * TRAILING_JAMO_COUNT;
const HANGUL_SYLLABLE_COUNT: u32 = LEADING_JAMO_COUNT * VOWEL_TRAILING_COUNT;

pub(super) fn key(name: &str, folded: bool) -> Result<Vec<u8>, NameError> {
	let mut decomposed = OrderedScalars::with_bound(name.len(), MAX_DECOMPOSED_SCALARS)?;
	for scalar in name.chars() {
		if !tables::assigned(scalar) {
			return Err(NameError::UnsupportedScalar { scalar });
		}
		decomposed.decompose(scalar, MAX_DECOMPOSITION_DEPTH)?;
	}
	decomposed.reorder();
	if !folded {
		return decomposed.encode();
	}

	// Canonical caseless matching needs NFD both before and after default
	// folding. Reordering before folding affects U+0345 (combining iota).
	let mut canonical = OrderedScalars::with_bound(
		decomposed.scalars.len(),
		tables::MAX_FOLD_SCALARS * MAX_DECOMPOSED_SCALARS,
	)?;
	for entry in decomposed.scalars {
		if let Some(mapping) = tables::full_fold(entry.scalar) {
			for code in mapping {
				canonical.decompose(decode_scalar(code)?, MAX_DECOMPOSITION_DEPTH)?;
			}
		} else {
			canonical.push(entry.scalar)?;
		}
	}
	canonical.reorder();
	canonical.encode()
}

struct WeightedScalar {
	scalar: char,
	class: u8,
	position: usize,
}

struct OrderedScalars {
	scalars: Vec<WeightedScalar>,
	limit: usize,
}

impl OrderedScalars {
	fn with_bound(input_bound: usize, expansion: usize) -> Result<Self, NameError> {
		let limit = input_bound
			.checked_mul(expansion)
			.ok_or(NameError::NormalizationLimit)?;
		Ok(Self {
			scalars: Vec::new(),
			limit,
		})
	}

	fn decompose(&mut self, scalar: char, depth: usize) -> Result<(), NameError> {
		if let Some((leading, vowel, trailing)) = hangul_jamo(scalar) {
			self.push(decode_scalar(leading)?)?;
			self.push(decode_scalar(vowel)?)?;
			if let Some(trailing) = trailing {
				self.push(decode_scalar(trailing)?)?;
			}
		} else if let Some(mapping) = tables::decomposition(scalar) {
			let next = depth.checked_sub(1).ok_or(NameError::NormalizationLimit)?;
			for code in mapping {
				self.decompose(decode_scalar(code)?, next)?;
			}
		} else {
			self.push(scalar)?;
		}
		Ok(())
	}

	fn push(&mut self, scalar: char) -> Result<(), NameError> {
		let position = self.scalars.len();
		if position >= self.limit {
			return Err(NameError::NormalizationLimit);
		}
		self.scalars
			.try_reserve(1)
			.map_err(|_| NameError::Allocation)?;
		self.scalars.push(WeightedScalar {
			scalar,
			class: tables::combining_class(scalar),
			position,
		});
		Ok(())
	}

	fn reorder(&mut self) {
		for marks in self
			.scalars
			.split_mut(|entry| entry.class == tables::STARTER_CLASS)
		{
			// Position preserves equal-class order without sorting scratch space.
			marks.sort_unstable_by_key(|entry| (entry.class, entry.position));
		}
	}

	fn encode(self) -> Result<Vec<u8>, NameError> {
		let bytes = self
			.scalars
			.iter()
			.map(|entry| entry.scalar.len_utf8())
			.sum();
		let mut key = Vec::new();
		key.try_reserve_exact(bytes)
			.map_err(|_| NameError::Allocation)?;
		let mut buffer = [0; UTF8_SCALAR_BYTES];
		for entry in self.scalars {
			key.extend_from_slice(entry.scalar.encode_utf8(&mut buffer).as_bytes());
		}
		Ok(key)
	}
}

fn decode_scalar(code: u32) -> Result<char, NameError> {
	char::from_u32(code).ok_or(NameError::InvalidTable)
}

fn hangul_jamo(scalar: char) -> Option<(u32, u32, Option<u32>)> {
	let index = u32::from(scalar).checked_sub(HANGUL_SYLLABLE_BASE)?;
	if index >= HANGUL_SYLLABLE_COUNT {
		return None;
	}
	let leading = LEADING_JAMO_BASE + index / VOWEL_TRAILING_COUNT;
	let vowel = VOWEL_JAMO_BASE + (index % VOWEL_TRAILING_COUNT) / TRAILING_JAMO_COUNT;
	let trailing = index % TRAILING_JAMO_COUNT;
	Some((
		leading,
		vowel,
		(trailing != 0).then_some(TRAILING_JAMO_BASE + trailing),
	))
}
