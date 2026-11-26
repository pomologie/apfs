use super::{Error, checksum_words};

// Wire dimensions from the APFS object header and Fletcher-64 specification.
const STORED_CHECKSUM_BYTES: usize = 8;
const STANDARD_HEADER_BYTES: usize = 32;
const WORD_BYTES: usize = 4;
const MAX_CHECKED_WORDS: usize = 8;
const MAX_OBJECT_BYTES: usize = STORED_CHECKSUM_BYTES + MAX_CHECKED_WORDS * WORD_BYTES;

#[kani::proof]
#[kani::unwind(33)]
fn object_checksum_window_matches_wire_layout() {
	let storage: [u8; MAX_OBJECT_BYTES] = kani::any();
	let len: usize = kani::any();
	kani::assume(len <= storage.len());
	let object = &storage[..len];
	let actual = checksum_words(object);
	let header_complete = len >= STANDARD_HEADER_BYTES;
	let aligned = len.is_multiple_of(WORD_BYTES);
	if header_complete && aligned {
		let Ok(words) = actual else {
			panic!("complete aligned object must have a checksum window");
		};
		let bytes = words.as_flattened();
		assert!(bytes.len() == len - STORED_CHECKSUM_BYTES);
		for (index, &byte) in bytes.iter().enumerate() {
			assert!(byte == object[STORED_CHECKSUM_BYTES + index]);
		}
	} else {
		assert!(matches!(actual, Err(Error::Truncated)));
	}
	kani::cover!(len == STANDARD_HEADER_BYTES - 1, "incomplete header");
	kani::cover!(
		len == STANDARD_HEADER_BYTES,
		"complete header with no payload"
	);
	kani::cover!(len == STANDARD_HEADER_BYTES + 1, "incomplete payload word");
	kani::cover!(
		len == MAX_OBJECT_BYTES,
		"complete header with two payload words"
	);
}
