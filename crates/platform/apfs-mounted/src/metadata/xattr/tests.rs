use super::*;

#[test]
fn confirms_fork_absence_only_with_two_conclusive_observations() {
	for (attribute_length, reported_length, absent) in [
		(None, Some(0), true),
		(None, None, false),
		(Some(0), Some(0), false),
		(Some(0), None, false),
		(None, Some(1), false),
	] {
		let fork = ResourceFork {
			attribute_length,
			reported_length,
		};
		assert_eq!(fork.confirmed_absent(), absent, "{fork:?}");
	}
}

#[test]
fn validates_list_framing_and_preserves_raw_name_bytes() {
	let names = parse_names(b"com.apple.provenance\0user.\xff\0").unwrap();
	assert_eq!(names[0].as_c_str(), c"com.apple.provenance");
	assert_eq!(names[1].as_bytes(), b"user.\xff");
	assert!(parse_names(b"missing terminator").is_err());
	assert!(parse_names(b"empty\0\0").is_err());
}

#[test]
fn refuses_oversized_and_unstable_native_transfers() {
	assert!(matches!(
		read_bounded(2, 1, |_| panic!("oversized read")),
		Err(ObservationError::Limit {
			limit: 1,
			observed: 2
		})
	));
	assert!(matches!(
		read_bounded(1, 1, |_| Err(io::Error::from_raw_os_error(libc::ERANGE))),
		Err(ObservationError::Changed)
	));
	assert!(matches!(
		read_bounded(1, 1, |_| Err(io::Error::from_raw_os_error(libc::ENOATTR))),
		Err(ObservationError::Changed)
	));
	assert!(matches!(
		read_bounded(1, 1, |_| Ok(2)),
		Err(ObservationError::Malformed(_))
	));
}

#[test]
fn fork_length_needs_returned_attribute_bit_and_nonnegative_value() {
	const LENGTH_WIDTH: usize = size_of::<libc::off_t>();
	let mut response = [0; RESOURCE_RESPONSE_BYTES];
	let words = [
		RESOURCE_RESPONSE_BYTES as u32,
		libc::ATTR_CMN_RETURNED_ATTRS,
		0,
		0,
		0,
		0,
	];
	for (bytes, word) in response[..HEADER_BYTES]
		.as_chunks_mut::<{ size_of::<u32>() }>()
		.0
		.iter_mut()
		.zip(words)
	{
		*bytes = word.to_ne_bytes();
	}
	assert_eq!(parse_fork_length(&response).unwrap(), None);
	let file_attr_offset = HEADER_BYTES - 2 * size_of::<u32>();
	response[file_attr_offset..file_attr_offset + size_of::<u32>()]
		.copy_from_slice(&libc::ATTR_FILE_RSRCLENGTH.to_ne_bytes());
	assert_eq!(parse_fork_length(&response).unwrap(), Some(0));
	response[HEADER_BYTES..HEADER_BYTES + LENGTH_WIDTH].fill(0xff);
	assert!(parse_fork_length(&response).is_err());
}
