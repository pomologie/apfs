use super::*;

const FORMAT: usize = HEADER_WORDS + libc::VOL_CAPABILITIES_FORMAT;
const INTERFACES: usize = HEADER_WORDS + libc::VOL_CAPABILITIES_INTERFACES;
const OWNERSHIP: usize = HEADER_WORDS + CAPABILITIES_WORDS;
const POSITIVE_INTERFACES: u32 =
	libc::VOL_CAP_INT_EXTENDED_SECURITY | libc::VOL_CAP_INT_FLOCK | libc::VOL_CAP_INT_RENAME_EXCL;
const NO_PERMISSIONS: u32 = libc::VOL_CAP_FMT_NO_PERMISSIONS;

fn supported_response() -> [u32; RESPONSE_WORDS] {
	let mut words = [0; RESPONSE_WORDS];
	words[0] = (RESPONSE_WORDS * WORD_BYTES) as u32;
	words[1] = RETURNED_ATTRIBUTES;
	words[2] = VOLUME_FIELDS;
	words[FORMAT + VALID_WORD_OFFSET] = NO_PERMISSIONS;
	words[INTERFACES] = POSITIVE_INTERFACES;
	words[INTERFACES + VALID_WORD_OFFSET] = POSITIVE_INTERFACES;
	words[OWNERSHIP] = OWNERSHIP_ATTRIBUTES;
	words
}

fn decode(words: &[u32; RESPONSE_WORDS], flags: u32) -> VolumeCapabilities {
	let (caps, attrs) = parse_response(words).unwrap();
	volume_capabilities(caps, attrs, flags)
}

#[test]
fn valid_bits_report_each_supported_operation() {
	let reported = decode(&supported_response(), 0);
	assert_eq!(reported.permissions, Capability::Supported);
	assert_eq!(reported.ownership, Capability::Supported);
	assert_eq!(reported.acls, Capability::Supported);
	assert_eq!(reported.advisory_locking, Capability::Supported);
	assert_eq!(reported.exclusive_rename, Capability::Supported);
}

#[test]
fn invalid_bits_do_not_claim_support_or_absence() {
	let mut words = supported_response();
	words[FORMAT] = NO_PERMISSIONS;
	words[FORMAT + VALID_WORD_OFFSET] = 0;
	words[INTERFACES] &= !libc::VOL_CAP_INT_RENAME_EXCL;
	words[INTERFACES + VALID_WORD_OFFSET] &= !libc::VOL_CAP_INT_FLOCK;
	let reported = decode(&words, 0);
	assert_eq!(reported.permissions, Capability::Unknown);
	assert_eq!(reported.acls, Capability::Supported);
	assert_eq!(reported.advisory_locking, Capability::Unknown);
	assert_eq!(reported.exclusive_rename, Capability::Unsupported);
}

#[test]
fn negative_permission_bit_and_mount_ownership_are_independent() {
	let mut words = supported_response();
	words[FORMAT] = NO_PERMISSIONS;
	assert_eq!(decode(&words, 0).permissions, Capability::Unsupported);
	assert_eq!(decode(&words, 0).ownership, Capability::Supported);
	let ignored = decode(&words, libc::MNT_IGNORE_OWNERSHIP as u32);
	assert_eq!(ignored.ownership, Capability::Unsupported);
	assert_eq!(ignored.acls, Capability::Supported);
	words[OWNERSHIP] = libc::ATTR_CMN_OWNERID;
	assert_eq!(decode(&words, 0).ownership, Capability::Unsupported);
}

#[test]
fn absent_attributes_keep_the_remaining_facts() {
	let mut words = supported_response();
	words[0] = ((HEADER_WORDS + CAPABILITIES_WORDS) * WORD_BYTES) as u32;
	words[2] = VOLUME_CAPABILITIES;
	let caps_only = decode(&words, 0);
	assert_eq!(caps_only.permissions, Capability::Supported);
	assert_eq!(caps_only.ownership, Capability::Unknown);
	words[0] = ((HEADER_WORDS + VOLUME_ATTRIBUTES_WORDS) * WORD_BYTES) as u32;
	words[2] = VOLUME_ATTRIBUTES;
	words[HEADER_WORDS] = OWNERSHIP_ATTRIBUTES;
	let attrs_only = decode(&words, 0);
	assert_eq!(attrs_only.permissions, Capability::Unknown);
	assert_eq!(attrs_only.ownership, Capability::Supported);
	words[0] = (HEADER_WORDS * WORD_BYTES) as u32;
	words[2] = 0;
	let none = decode(&words, 0);
	assert_eq!(none.permissions, Capability::Unknown);
	assert_eq!(none.ownership, Capability::Unknown);
	assert_eq!(none.acls, Capability::Unknown);
	assert_eq!(none.advisory_locking, Capability::Unknown);
	assert_eq!(none.exclusive_rename, Capability::Unknown);
}

#[test]
fn malformed_length_and_bitmap_cannot_claim_capabilities() {
	let mutations = [
		(0, 0),
		(0, u32::MAX),
		(0, (RESPONSE_WORDS * WORD_BYTES - 1) as u32),
		(0, (RESPONSE_WORDS * WORD_BYTES - WORD_BYTES) as u32),
		(1, 0),
		(2, libc::ATTR_VOL_UUID),
		(2, VOLUME_CAPABILITIES),
		(3, libc::ATTR_DIR_LINKCOUNT),
	];
	for (field, value) in mutations {
		let mut words = supported_response();
		words[field] = value;
		assert_eq!(
			parse_response(&words).unwrap_err().kind(),
			io::ErrorKind::InvalidData
		);
	}
}

#[test]
fn mount_flags_distinguish_ownership_from_other_properties() {
	let mut mount = MountFacts {
		filesystem_type: c"apfs".to_owned(),
		mount_flags: (libc::MNT_RDONLY | libc::MNT_AUTOMOUNTED) as u32,
		locality: Locality::Local,
	};
	assert_eq!(mount.ownership_mode(), OwnershipMode::Native);
	assert!(mount.is_read_only());
	assert!(mount.is_automounted());
	mount.mount_flags |= libc::MNT_IGNORE_OWNERSHIP as u32;
	assert_eq!(mount.ownership_mode(), OwnershipMode::Ignored);
}

#[test]
fn live_mount_classification_agrees_with_the_full_observation() {
	let dir = tempfile::tempdir().unwrap();
	let file = std::fs::File::open(dir.path()).unwrap();
	let mount = observe_mount(&file).unwrap();
	let volume = observe(&file).unwrap();
	assert_eq!(mount.filesystem_type(), volume.filesystem_type());
	assert_eq!(mount.mount_flags(), volume.mount_flags());
	assert_eq!(mount.locality, volume.locality);
	assert_eq!(
		mount.ownership_mode() == OwnershipMode::Ignored,
		volume.ignores_ownership()
	);

	let regular = tempfile::tempfile_in(dir.path()).unwrap();
	assert_eq!(
		observe_mount(regular).unwrap_err().kind(),
		io::ErrorKind::NotADirectory
	);
}
