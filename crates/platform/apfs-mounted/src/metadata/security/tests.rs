use super::*;

fn write_word(bytes: &mut [u8], offset: usize, word: u32) {
	bytes[offset..offset + WORD_BYTES].copy_from_slice(&word.to_ne_bytes());
}

fn security_payload(count: u32) -> Vec<u8> {
	let length = FILESEC_HEADER_BYTES
		+ (if count == FILESEC_NO_ACL {
			0
		} else {
			count as usize
		}) * ACE_BYTES;
	let mut bytes = vec![0; PAYLOAD_OFFSET + length];
	write_word(&mut bytes, 0, (PAYLOAD_OFFSET + length) as u32);
	write_word(&mut bytes, WORD_BYTES, SECURITY_MASK);
	write_word(&mut bytes, HEADER_BYTES, REFERENCE_BYTES as u32);
	write_word(&mut bytes, HEADER_BYTES + WORD_BYTES, length as u32);
	write_word(&mut bytes, PAYLOAD_OFFSET, FILESEC_MAGIC);
	write_word(&mut bytes, PAYLOAD_OFFSET + ENTRY_COUNT_OFFSET, count);
	bytes
}

#[test]
fn distinguishes_unreported_empty_and_absent_acl() {
	let mut absent = [0; PAYLOAD_OFFSET];
	write_word(&mut absent, WORD_BYTES, libc::ATTR_CMN_RETURNED_ATTRS);
	assert_eq!(
		parse_security(&absent[..HEADER_BYTES]).unwrap(),
		ExtendedSecurity::NotReturned {
			empty_reference: false
		}
	);
	assert_eq!(
		parse_security(&absent).unwrap(),
		ExtendedSecurity::NotReturned {
			empty_reference: true
		}
	);
	for (raw, wanted) in [(0, Some(0)), (FILESEC_NO_ACL, None)] {
		let parsed = parse_security(&security_payload(raw)).unwrap();
		assert!(parsed.has_no_acl_entries());
		let ExtendedSecurity::Present(payload) = parsed else {
			panic!("security payload absent")
		};
		assert_eq!(payload.entry_count, wanted);
	}
}

#[test]
fn retains_extended_security_guids_flags_and_opaque_ace() {
	let mut bytes = security_payload(1);
	bytes[PAYLOAD_OFFSET + WORD_BYTES] = 4;
	bytes[PAYLOAD_OFFSET + WORD_BYTES + GUID_BYTES] = 5;
	write_word(&mut bytes, PAYLOAD_OFFSET + FLAGS_OFFSET, 7);
	bytes[PAYLOAD_OFFSET + FILESEC_HEADER_BYTES..].fill(0x2a);
	let parsed = parse_security(&bytes).unwrap();
	assert!(!parsed.has_no_acl_entries());
	let ExtendedSecurity::Present(payload) = parsed else {
		panic!("security payload absent")
	};
	assert_eq!(payload.owner_guid[0], 4);
	assert_eq!(payload.group_guid[0], 5);
	assert_eq!(payload.entry_count, Some(1));
	assert_eq!(payload.flags, 7);
	assert_eq!(payload.raw_entries, [0x2a; ACE_BYTES]);
}

#[test]
fn rejects_truncated_or_inconsistent_security_records() {
	let valid = security_payload(0);
	for available in 0..valid.len() {
		assert!(
			parse_security(&valid[..available]).is_err(),
			"accepted {available} bytes"
		);
	}
	for (offset, value) in [
		(HEADER_BYTES, u32::MAX),
		(HEADER_BYTES + WORD_BYTES, 0),
		(PAYLOAD_OFFSET, 0),
		(PAYLOAD_OFFSET + ENTRY_COUNT_OFFSET, NATIVE_MAX_ENTRIES + 1),
	] {
		let mut invalid = valid.clone();
		write_word(&mut invalid, offset, value);
		assert!(
			parse_security(&invalid).is_err(),
			"accepted malformed field at {offset}"
		);
	}
}

#[test]
fn distinguishes_omitted_guids_from_reported_zero_values() {
	let mut bytes = [0; GUID_RESPONSE_BYTES];
	write_word(&mut bytes, 0, GUID_RESPONSE_BYTES as u32);
	write_word(
		&mut bytes,
		WORD_BYTES,
		libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_UUID,
	);
	assert_eq!(
		parse_guids(&bytes).unwrap(),
		SecurityGuids {
			owner: Some([0; GUID_BYTES]),
			group: None,
		}
	);
	bytes[HEADER_BYTES + GUID_BYTES] = 1;
	assert!(parse_guids(&bytes).is_err());
	write_word(&mut bytes, WORD_BYTES, GUID_MASK);
	assert_eq!(parse_guids(&bytes).unwrap().group.unwrap()[0], 1);
}
