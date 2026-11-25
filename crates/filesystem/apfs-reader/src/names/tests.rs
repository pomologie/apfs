use super::{NameError, NameProfile};

const BINARY: NameProfile = NameProfile::Binary;
const NORMALIZED: NameProfile = NameProfile::Unicode9Normalized;
const FOLDED: NameProfile = NameProfile::Unicode9Folded;

// The low bits of a hashed directory key also encode the terminating NUL.
const UNENCODABLE_COMPONENT_BYTES: usize = 1023;

#[test]
fn selects_the_profile_from_both_volume_flags() {
	assert_eq!(NameProfile::for_flags(false, false), BINARY);
	assert_eq!(NameProfile::for_flags(false, true), NORMALIZED);
	assert_eq!(NameProfile::for_flags(true, false), FOLDED);
	assert_eq!(NameProfile::for_flags(true, true), FOLDED);
}

#[test]
fn preserves_stored_bytes_in_the_binary_profile() {
	assert_eq!(BINARY.key("Étude").unwrap(), "Étude".as_bytes());
	assert_ne!(BINARY.key("Étude"), BINARY.key("E\u{0301}tude"));
	assert_eq!(NORMALIZED.key("Report").unwrap(), b"Report");
	assert_eq!(FOLDED.key("Report").unwrap(), b"report");
}

#[test]
fn decomposes_hangul_and_reorders_marks_stably_within_starters() {
	for (input, decomposed) in [
		(
			"\u{AC00}\u{AC01}",
			"\u{1100}\u{1161}\u{1100}\u{1161}\u{11A8}",
		),
		("Étage", "E\u{0301}tage"),
		(
			"\u{0301}\u{0327}a\u{0300}\u{0327}b",
			"\u{0327}\u{0301}a\u{0327}\u{0300}b",
		),
		("a\u{0301}\u{0300}", "a\u{0301}\u{0300}"),
	] {
		assert_eq!(NORMALIZED.key(input).unwrap(), decomposed.as_bytes());
	}
	assert_ne!(
		NORMALIZED.key("a\u{0300}\u{0301}"),
		NORMALIZED.key("a\u{0301}\u{0300}")
	);
	assert_ne!(NORMALIZED.key("Étude"), NORMALIZED.key("étude"));
}

#[test]
fn applies_full_root_folding_and_orders_before_folding_combining_iota() {
	for (input, folded) in [
		("Straße", "strasse"),
		("\u{FB02}ute", "flute"),
		("Σςσ", "σσσ"),
		("Kelvin", "kelvin"),
		("İ", "i\u{0307}"),
		("α\u{0345}\u{0301}", "α\u{0301}ι"),
	] {
		assert_eq!(FOLDED.key(input).unwrap(), folded.as_bytes());
	}
	assert_ne!(FOLDED.key("I"), FOLDED.key("ı"));
	assert_ne!(FOLDED.key("Ａ"), FOLDED.key("A"));
	assert_ne!(FOLDED.key("a\u{200D}b"), FOLDED.key("ab"));
}

#[test]
fn rejects_names_outside_the_wire_or_unicode_profile() {
	for invalid in ["", ".", "..", "a/b", "a\0b"] {
		for profile in [BINARY, NORMALIZED, FOLDED] {
			assert_eq!(profile.key(invalid), Err(NameError::InvalidComponent));
		}
	}
	let maximum = "a".repeat(UNENCODABLE_COMPONENT_BYTES - 1);
	assert_eq!(NORMALIZED.key(&maximum).unwrap(), maximum.as_bytes());
	let overlong = "a".repeat(UNENCODABLE_COMPONENT_BYTES);
	assert_eq!(BINARY.key(&overlong), Err(NameError::InvalidComponent));
	assert_eq!(FOLDED.key(&overlong), Err(NameError::InvalidComponent));
	for scalar in ['\u{0378}', '\u{1C90}', '\u{11F04}', '\u{FFFF}'] {
		let mut buffer = [0; 4];
		let name = scalar.encode_utf8(&mut buffer);
		assert_eq!(
			NORMALIZED.key(name),
			Err(NameError::UnsupportedScalar { scalar })
		);
		assert_eq!(
			FOLDED.key(name),
			Err(NameError::UnsupportedScalar { scalar })
		);
		assert_eq!(BINARY.key(name).unwrap(), name.as_bytes());
	}
}
