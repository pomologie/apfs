use apfs_format::object::{Header, checksum};

const CHECK_BYTES: usize = 8;
const WORD_BYTES: usize = 4;
const MODULUS: u128 = u32::MAX as u128;
const BLOCK_SIZES: [usize; 5] = [4096, 8192, 16_384, 32_768, 65_536];

macro_rules! fixture {
	($name:literal) => {
		($name, include_bytes!(concat!("fixtures/", $name)))
	};
}

const SONOMA_OBJECTS: &[(&str, &[u8])] = &[
	fixture!("native-block-0.bin"),
	fixture!("native-block-1.bin"),
	fixture!("native-block-2.bin"),
	fixture!("native-block-3.bin"),
	fixture!("native-block-4.bin"),
	fixture!("sonoma-populated-omap-container.bin"),
	fixture!("sonoma-populated-omap-volume.bin"),
];

fn assert_fletcher_check_words(payload: &[u8], check: [u8; CHECK_BYTES]) {
	// Append the check words in wire order, then compute each Fletcher residue
	// by a direct wide sum. The weighted sum counts how many prefixes include
	// each word. Neither sum uses the production recurrence.
	let (words, remainder) = payload.as_chunks::<WORD_BYTES>();
	assert!(remainder.is_empty());
	let (check_words, remainder) = check.as_chunks::<WORD_BYTES>();
	assert!(remainder.is_empty());
	assert!(
		check_words
			.iter()
			.all(|word| u32::from_le_bytes(*word) != 0)
	);
	let count = (words.len() + check_words.len()) as u128;
	let (sum, weighted) = words.iter().chain(check_words).zip((1..=count).rev()).fold(
		(0, 0),
		|(sum, weighted), (word, weight)| {
			let value = u128::from(u32::from_le_bytes(*word));
			(sum + value, weighted + value * weight)
		},
	);
	assert_eq!((sum % MODULUS, weighted % MODULUS), (0, 0));
}

#[test]
fn checks_retained_sonoma_objects_against_the_wire_checksum() {
	println!();
	for (name, object) in SONOMA_OBJECTS {
		let (stored, payload) = object.split_at(CHECK_BYTES);
		let expected = <[u8; CHECK_BYTES]>::try_from(stored).unwrap();
		assert_fletcher_check_words(payload, expected);
		let expected = u64::from_le_bytes(expected);
		assert_eq!(checksum(object), Ok(expected));
		assert_eq!(Header::decode(object).unwrap().checksum, expected);
		println!(
			"APFS checksum native {name} {} {expected:016x}",
			object.len()
		);
	}
}

#[test]
fn checks_aligned_native_prefixes_against_wire_model() {
	const OBJECT_ID_OFFSET: usize = 8;
	const TRANSACTION_ID_OFFSET: usize = 16;
	const TYPE_OFFSET: usize = 24;
	const SUBTYPE_OFFSET: usize = 28;
	const WIRE_HEADER_BYTES: usize = SUBTYPE_OFFSET + WORD_BYTES;

	println!();
	for (name, object) in SONOMA_OBJECTS {
		let wide = |offset| u64::from_le_bytes(object[offset..][..CHECK_BYTES].try_into().unwrap());
		let word = |offset| u32::from_le_bytes(object[offset..][..WORD_BYTES].try_into().unwrap());
		let header = Header::decode(object).unwrap();
		assert_eq!(header.checksum, wide(0));
		assert_eq!(header.id.0, wide(OBJECT_ID_OFFSET));
		assert_eq!(header.transaction.0, wide(TRANSACTION_ID_OFFSET));
		assert_eq!(header.object_type, word(TYPE_OFFSET));
		assert_eq!(header.subtype, word(SUBTYPE_OFFSET));

		let mut checked = 0;
		for length in (WIRE_HEADER_BYTES..=object.len()).step_by(WORD_BYTES) {
			let prefix = &object[..length];
			assert_eq!(Header::type_hint(prefix), Ok(word(TYPE_OFFSET)));
			let computed = checksum(prefix).unwrap();
			assert_fletcher_check_words(&prefix[CHECK_BYTES..], computed.to_le_bytes());
			checked += 1;
		}
		println!(
			"APFS native window {name} {} {checked} {:016x}",
			object.len(),
			header.checksum,
		);
	}
}

#[test]
fn checks_fletcher_residues_at_each_admitted_block_size() {
	const WORD_PATTERNS: [u32; 4] = [0, 1, u32::MAX - 1, u32::MAX];
	const DISTINCT_WORD: u32 = 0x1234_5678;

	println!();
	for size in BLOCK_SIZES {
		let mut object = vec![0; size];
		for word in WORD_PATTERNS {
			let (words, remainder) = object[CHECK_BYTES..].as_chunks_mut::<WORD_BYTES>();
			assert!(remainder.is_empty());
			words.fill(word.to_le_bytes());
			let uniform = checksum(&object).unwrap();
			assert_fletcher_check_words(&object[CHECK_BYTES..], uniform.to_le_bytes());
			if word == 0 || word == u32::MAX {
				assert_eq!(uniform, u64::MAX);
			}
			println!("APFS checksum uniform {size} {word}");

			for position in [CHECK_BYTES, size / 2, size - WORD_BYTES] {
				let word_bytes = position..position + WORD_BYTES;
				object[word_bytes.clone()].copy_from_slice(&DISTINCT_WORD.to_le_bytes());
				let check = checksum(&object).unwrap();
				assert_fletcher_check_words(&object[CHECK_BYTES..], check.to_le_bytes());
				object[..CHECK_BYTES].copy_from_slice(&check.to_le_bytes());
				assert_eq!(checksum(&object), Ok(check));
				assert_eq!(Header::decode(&object).unwrap().checksum, check);
				object[word_bytes].copy_from_slice(&word.to_le_bytes());
				println!("APFS checksum singleton {size} {word} {position} {DISTINCT_WORD}");
			}
		}
	}
}
