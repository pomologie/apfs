use std::{fs::File, io::Write};

use rustix::fs::{XattrFlags, fsetxattr};

use super::*;

#[test]
fn native_descriptor_reports_metadata_and_timestamp_readback() {
	let mut file = tempfile::tempfile().unwrap();
	file.write_all(b"three bytes").unwrap();
	let observed = stat(&file).unwrap();
	assert_eq!(observed.file_type, FileType::RegularFile);
	assert_eq!(observed.length, 11);
	let desired = AccessModificationTimes {
		access: Timestamp::new(1_500_000_000, 123).unwrap(),
		modification: Timestamp::new(1_500_000_004, 456).unwrap(),
	};
	assert_eq!(set_times(&file, desired).unwrap(), desired);
	assert_eq!(stat(&file).unwrap().times, desired);
	assert_eq!(Timestamp::new(0, -1), None);
	assert_eq!(Timestamp::new(0, NANOS_PER_SECOND), None);
}

#[test]
fn native_inventory_distinguishes_missing_empty_and_nonempty_values() {
	const ATTR: &std::ffi::CStr = c"user.apfs-mounted.test";
	const TEST_BYTES: &[u8] = b"opaque\0\xff";
	let file = tempfile::tempfile().unwrap();
	let visibility = XattrVisibility::IncludingCompression;
	assert_eq!(read_xattr(&file, ATTR, visibility, 64).unwrap(), None);
	assert_eq!(finder_info(&file, visibility).unwrap(), None);
	assert!(resource_fork(&file).unwrap().confirmed_absent());
	fsetxattr(&file, ATTR, &[], XattrFlags::empty()).unwrap();
	assert_eq!(
		read_xattr(&file, ATTR, visibility, 0).unwrap(),
		Some(vec![])
	);
	fsetxattr(&file, ATTR, TEST_BYTES, XattrFlags::empty()).unwrap();
	assert_eq!(
		read_xattr(&file, ATTR, visibility, TEST_BYTES.len())
			.unwrap()
			.as_deref(),
		Some(TEST_BYTES)
	);
	assert!(matches!(
		read_xattr(&file, ATTR, visibility, TEST_BYTES.len() - 1),
		Err(ObservationError::Limit { .. })
	));
	for visibility in [
		XattrVisibility::Visible,
		XattrVisibility::IncludingCompression,
	] {
		assert!(
			list_xattrs(&file, visibility, 4096)
				.unwrap()
				.iter()
				.any(|name| name.as_c_str() == ATTR)
		);
	}
}

#[test]
fn native_finder_info_and_resource_fork_preserve_opaque_bytes() {
	const FINDER_INFO: &std::ffi::CStr = c"com.apple.FinderInfo";
	const RESOURCE_FORK: &std::ffi::CStr = c"com.apple.ResourceFork";
	const FORK_PAYLOAD: &[u8] = b"synthetic\0resource";
	let file = tempfile::tempfile().unwrap();
	let mut finder_payload = [0; FINDER_INFO_BYTES];
	finder_payload[..b"TEST".len()].copy_from_slice(b"TEST");
	fsetxattr(&file, FINDER_INFO, &finder_payload, XattrFlags::empty()).unwrap();
	fsetxattr(&file, RESOURCE_FORK, FORK_PAYLOAD, XattrFlags::empty()).unwrap();
	let visibility = XattrVisibility::IncludingCompression;
	assert_eq!(
		finder_info(&file, visibility).unwrap(),
		Some(finder_payload)
	);
	assert_eq!(
		read_resource_fork(&file, FORK_PAYLOAD.len())
			.unwrap()
			.as_deref(),
		Some(FORK_PAYLOAD),
	);
	let fork = resource_fork(&file).unwrap();
	assert_eq!(fork.attribute_length, Some(FORK_PAYLOAD.len() as u64));
	assert_eq!(fork.reported_length, Some(FORK_PAYLOAD.len() as u64));
	assert!(!fork.confirmed_absent());
}

#[test]
fn native_empty_acl_provisioning_reads_back_an_explicit_empty_payload() {
	let directory = tempfile::tempdir().unwrap();
	let descriptor = File::open(directory.path()).unwrap();
	let original_guids = security_guids(&descriptor).unwrap();
	let observed = set_empty_acl_on_fresh_directory(&descriptor).unwrap();
	assert!(matches!(
		observed,
		ExtendedSecurity::Present(SecurityPayload {
			entry_count: Some(0),
			flags: 0,
			..
		})
	));
	assert_eq!(
		extended_security(&descriptor, MAX_EXTENDED_SECURITY_BYTES).unwrap(),
		observed
	);
	assert_eq!(security_guids(&descriptor).unwrap(), original_guids);
	let file = tempfile::tempfile().unwrap();
	assert!(
		matches!(set_empty_acl_on_fresh_directory(&file), Err(ApplyError::Update(error)) if error.kind() == io::ErrorKind::NotADirectory)
	);
}
