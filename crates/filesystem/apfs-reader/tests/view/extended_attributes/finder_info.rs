use super::*;

const INODE_TYPE: u64 = 3;
const SLOT_VALUE_LENGTH: usize = 3 * size_of::<u16>();
const INODE_FLAGS: usize = 48;
const INODE_FIXED_BYTES: usize = 92;
const HAS_FINDER_INFO: u64 = 1 << 8;
const XFIELD_HEADER_BYTES: usize = 2 * size_of::<u16>();
const XFIELD_DESCRIPTOR_BYTES: usize = 2 * size_of::<u16>();
const XFIELD_LENGTH: usize = size_of::<u16>();
const FINDER_INFO_XFIELD: u8 = 7;
const DATA_STREAM_XFIELD: u8 = 8;
const NATIVE_NAME_PADDED_BYTES: usize = 16;
const XATTR_LENGTH: usize = size_of::<u16>();

#[test]
fn reads_native_finder_info_and_distinguishes_absence_from_no_inode() {
	let source = container(fixture());
	let mut view = open(&source);
	assert_eq!(view.finder_info(INODE).unwrap(), Some(finder_info_bytes()));
	assert_eq!(view.finder_info(InodeId::ROOT).unwrap(), None);
	assert!(matches!(
		view.finder_info(MISSING_INODE),
		Err(Error::MissingInode(MISSING_INODE)),
	));
}

#[test]
fn reads_inode_field_and_refuses_conflicting_finder_info_storage() {
	for (retain_attribute, field_bytes) in [
		(false, FINDER_INFO_BYTES),
		(true, FINDER_INFO_BYTES),
		(false, FINDER_INFO_BYTES - 1),
	] {
		let mut image = fixture();
		let leaf = image.0.get_mut(&XATTR_LEAF).unwrap();
		store_inode_finder_info(leaf, field_bytes);
		if !retain_attribute {
			rename_finder_info_attribute(leaf);
		}
		update_checksum(leaf);
		let source = container(image);
		let result = open(&source).finder_info(INODE);
		match (retain_attribute, field_bytes) {
			(false, FINDER_INFO_BYTES) => assert_eq!(result.unwrap(), Some(finder_info_bytes())),
			(true, _) => assert!(matches!(
				result,
				Err(Error::Corrupt(Corruption::FinderInfo))
			)),
			_ => assert!(matches!(
				result,
				Err(Error::Corrupt(Corruption::ExtendedFields))
			)),
		}
	}
}

#[test]
fn refuses_malformed_or_undeclared_finder_info() {
	let mutations: [fn(&mut [u8]); 3] = [
		|leaf| {
			let (slot, _) = record_offsets(leaf, INODE.as_raw(), XATTR_TYPE, Some(FINDER_INFO));
			let value = value_offset(leaf, INODE.as_raw(), XATTR_TYPE, Some(FINDER_INFO));
			let length = FINDER_INFO_BYTES - 1;
			write_u16(leaf, value + XATTR_LENGTH, length);
			write_u16(
				leaf,
				slot + SLOT_VALUE_LENGTH,
				XATTR_RECORD_DATA_OFFSET + length,
			);
		},
		rename_finder_info_attribute,
		|leaf| {
			let flags = value_offset(leaf, INODE.as_raw(), INODE_TYPE, None) + INODE_FLAGS;
			let field = &mut leaf[flags..flags + size_of::<u64>()];
			let value = u64::from_le_bytes((&*field).try_into().unwrap());
			assert_ne!(value & HAS_FINDER_INFO, 0);
			field.copy_from_slice(&(value & !HAS_FINDER_INFO).to_le_bytes());
		},
	];
	for mutate in mutations {
		let mut image = fixture();
		let leaf = image.0.get_mut(&XATTR_LEAF).unwrap();
		mutate(leaf);
		update_checksum(leaf);
		let source = container(image);
		assert!(matches!(
			open(&source).finder_info(INODE),
			Err(Error::Corrupt(Corruption::FinderInfo)),
		));
	}
}

#[test]
fn refuses_external_finder_info_without_opening_the_stream() {
	let mut image = fixture();
	let leaf = image.0.get_mut(&XATTR_LEAF).unwrap();
	let (finder, _) = record_offsets(leaf, INODE.as_raw(), XATTR_TYPE, Some(FINDER_INFO));
	let (large, _) = record_offsets(leaf, INODE.as_raw(), XATTR_TYPE, Some(LARGE));
	for offset in [BTREE_VALUE_OFFSET_IN_SLOT, SLOT_VALUE_LENGTH] {
		let finder_field = usize::from(u16_at(leaf, finder + offset));
		let large_field = usize::from(u16_at(leaf, large + offset));
		write_u16(leaf, finder + offset, large_field);
		write_u16(leaf, large + offset, finder_field);
	}
	update_checksum(leaf);
	let source = container(image);
	assert!(matches!(
		open(&source).finder_info(INODE),
		Err(Error::Unsupported(Unsupported::XattrStorage(flags)))
			if flags == DATA_STREAM | SONOMA_EXTERNAL_USER_FLAG,
	));
}

fn rename_finder_info_attribute(leaf: &mut [u8]) {
	let (_, key) = record_offsets(leaf, INODE.as_raw(), XATTR_TYPE, Some(FINDER_INFO));
	let last = key + XATTR_KEY_NAME_OFFSET + FINDER_INFO.len() - 1;
	leaf[last] = leaf[last].to_ascii_uppercase();
}

fn store_inode_finder_info(leaf: &mut [u8], length: usize) {
	// Replace the native fixture's second xfield while retaining its inode and name.
	let (slot, _) = record_offsets(leaf, INODE.as_raw(), INODE_TYPE, None);
	let value = value_offset(leaf, INODE.as_raw(), INODE_TYPE, None);
	let header = value + INODE_FIXED_BYTES;
	let descriptor = header + XFIELD_HEADER_BYTES + XFIELD_DESCRIPTOR_BYTES;
	assert_eq!(leaf[descriptor], DATA_STREAM_XFIELD);
	let payload = descriptor + XFIELD_DESCRIPTOR_BYTES + NATIVE_NAME_PADDED_BYTES;
	leaf[payload..payload + FINDER_INFO_BYTES].copy_from_slice(&finder_info_bytes());
	leaf[descriptor] = FINDER_INFO_XFIELD;
	write_u16(leaf, descriptor + XFIELD_LENGTH, length);
	write_u16(
		leaf,
		header + XFIELD_LENGTH,
		NATIVE_NAME_PADDED_BYTES + FINDER_INFO_BYTES,
	);
	write_u16(
		leaf,
		slot + SLOT_VALUE_LENGTH,
		payload + FINDER_INFO_BYTES - value,
	);
}

fn write_u16(bytes: &mut [u8], offset: usize, value: usize) {
	bytes[offset..offset + size_of::<u16>()]
		.copy_from_slice(&u16::try_from(value).unwrap().to_le_bytes());
}
