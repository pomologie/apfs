//! Volume namespace and selected-transaction checks for A-CONT-03-T01.

use apfs_container::{
	Container, Error, Limit, LookupOptions, ObjectMapError, OpenOptions, VirtualType,
};
use apfs_format::{Error as FormatError, object::ObjectId, superblock::BlockAddress};

use super::{
	BLOCK_BYTES, Fixture, LATEST_FIRST_DATA, LATEST_XID, MAP_FLAGS_OFFSET, OBJECT_ID_OFFSET,
	VOLUME_FSROOT, VOLUME_OMAP, VOLUME_OMAP_ROOT, VOLUME_SUPERBLOCK, XID_OFFSET,
};

const NATIVE_VOLUME: ObjectId = ObjectId(1026);
const ABSENT_VOLUME: ObjectId = ObjectId(1027);
const NATIVE_FSROOT: ObjectId = ObjectId(1028);
const FSROOT_TYPE: VirtualType = VirtualType {
	kind: 2,
	subtype: 14,
};
const APSB_TYPE: VirtualType = VirtualType {
	kind: 13,
	subtype: 0,
};
const ROOT_ADDRESS_OFFSET: usize = 48;
const ROOT_FOOTER_BYTES: usize = 40;
const FIRST_VALUE_ADDRESS: usize = BLOCK_BYTES - ROOT_FOOTER_BYTES - size_of::<u64>();
const FIRST_VALUE_FLAGS: usize = FIRST_VALUE_ADDRESS - 2 * size_of::<u32>();
const MANUALLY_MANAGED: u32 = 1;
const TOMBSTONE: u32 = 1;

#[test]
fn resolves_the_native_filesystem_root_only_in_the_volume_namespace() {
	let container = open(Fixture::native());
	let options = LookupOptions::default();
	assert!(
		container
			.open_volume_objects(ABSENT_VOLUME, options)
			.unwrap()
			.is_none()
	);
	assert!(
		container
			.lookup_virtual_mapping(NATIVE_FSROOT, LATEST_XID, options)
			.unwrap()
			.is_none()
	);
	assert!(
		container
			.read_virtual_object(NATIVE_VOLUME, APSB_TYPE, options)
			.unwrap()
			.is_some()
	);

	let mut view = container
		.open_volume_objects(NATIVE_VOLUME, options)
		.unwrap()
		.unwrap();
	assert_eq!(view.volume().mapping.id, NATIVE_VOLUME);
	assert_eq!(view.volume().checkpoint, LATEST_XID);
	assert!(
		view.lookup_virtual_mapping(NATIVE_VOLUME)
			.unwrap()
			.is_none()
	);
	let mapping = view.lookup_virtual_mapping(NATIVE_FSROOT).unwrap().unwrap();
	assert_eq!(mapping.address, BlockAddress(VOLUME_FSROOT));
	assert_eq!(mapping.transaction, LATEST_XID);
	let object = view
		.read_virtual_object(NATIVE_FSROOT, FSROOT_TYPE)
		.unwrap()
		.unwrap();
	assert_eq!(object.mapping, mapping);
	assert_eq!(object.header.id, NATIVE_FSROOT);
	assert_eq!(object.header.transaction, LATEST_XID);
	assert_eq!(object.as_bytes(), &container.source().0[&VOLUME_FSROOT]);
}

#[test]
fn read_budget_covers_volume_open_and_subsequent_scope_lookups() {
	let container = open(Fixture::native());
	let options = LookupOptions {
		max_read_bytes: 3 * BLOCK_BYTES as u64,
		..LookupOptions::default()
	};
	assert!(matches!(
		container.open_volume_objects(NATIVE_VOLUME, options),
		Err(Error::Limit(Limit::ReadBytes))
	));
	let options = LookupOptions {
		max_read_bytes: 6 * BLOCK_BYTES as u64,
		..options
	};
	let mut view = container
		.open_volume_objects(NATIVE_VOLUME, options)
		.unwrap()
		.unwrap();
	assert!(
		view.read_virtual_object(NATIVE_FSROOT, FSROOT_TYPE)
			.unwrap()
			.is_some()
	);
	assert!(matches!(
		view.lookup_virtual_mapping(NATIVE_FSROOT),
		Err(Error::Limit(Limit::ReadBytes))
	));
}

#[test]
fn rejects_container_flags_stale_owners_and_protected_tree_addresses() {
	let options = LookupOptions::default();
	let mut fixture = Fixture::native();
	fixture.set_u32(VOLUME_OMAP, MAP_FLAGS_OFFSET, MANUALLY_MANAGED);
	assert!(matches!(
		open(fixture).open_volume_objects(NATIVE_VOLUME, options),
		Err(Error::ObjectMap {
			address: BlockAddress(VOLUME_OMAP),
			reason: ObjectMapError::Format(FormatError::UnsupportedObjectMapFlags(
				MANUALLY_MANAGED
			)),
		})
	));

	for (offset, value) in [
		(OBJECT_ID_OFFSET, VOLUME_OMAP_ROOT),
		(XID_OFFSET, LATEST_XID.0 + 1),
	] {
		let mut fixture = Fixture::native();
		fixture.set_u64(VOLUME_OMAP, offset, value);
		assert!(matches!(
			open(fixture).open_volume_objects(NATIVE_VOLUME, options),
			Err(Error::ObjectMap {
				address: BlockAddress(VOLUME_OMAP),
				reason: ObjectMapError::Identity,
			})
		));
	}

	let mut fixture = Fixture::native();
	fixture.set_u64(VOLUME_OMAP, ROOT_ADDRESS_OFFSET, VOLUME_SUPERBLOCK);
	assert!(matches!(
		open(fixture).open_volume_objects(NATIVE_VOLUME, options),
		Err(Error::ObjectMap {
			address: BlockAddress(VOLUME_SUPERBLOCK),
			reason: ObjectMapError::Address,
		})
	));
}

#[test]
fn rejects_mapped_objects_that_alias_metadata_or_disagree_with_the_mapping() {
	let options = LookupOptions::default();
	for address in [VOLUME_OMAP_ROOT, VOLUME_SUPERBLOCK] {
		let mut fixture = Fixture::native();
		fixture.set_u64(VOLUME_OMAP_ROOT, FIRST_VALUE_ADDRESS, address);
		let container = open(fixture);
		let mut view = container
			.open_volume_objects(NATIVE_VOLUME, options)
			.unwrap()
			.unwrap();
		assert!(matches!(
			view.lookup_virtual_mapping(NATIVE_FSROOT),
			Err(Error::ObjectMap { address: BlockAddress(actual), reason: ObjectMapError::Address })
				if actual == address
		));
	}

	let mut fixture = Fixture::native();
	fixture.set_u64(VOLUME_FSROOT, XID_OFFSET, LATEST_XID.0 - 1);
	let container = open(fixture);
	let mut view = container
		.open_volume_objects(NATIVE_VOLUME, options)
		.unwrap()
		.unwrap();
	assert!(matches!(
		view.read_virtual_object(NATIVE_FSROOT, FSROOT_TYPE),
		Err(Error::ObjectMap {
			address: BlockAddress(VOLUME_FSROOT),
			reason: ObjectMapError::Identity
		})
	));
}

#[test]
fn honors_volume_tombstones_and_uses_the_selected_checkpoint_only() {
	let options = LookupOptions::default();
	let mut fixture = Fixture::native();
	fixture.set_u32(VOLUME_OMAP_ROOT, FIRST_VALUE_FLAGS, TOMBSTONE);
	let container = open(fixture);
	let mut view = container
		.open_volume_objects(NATIVE_VOLUME, options)
		.unwrap()
		.unwrap();
	assert!(
		view.read_virtual_object(NATIVE_FSROOT, FSROOT_TYPE)
			.unwrap()
			.is_none()
	);

	let mut fixture = Fixture::native();
	fixture.0.get_mut(&LATEST_FIRST_DATA).unwrap()[BLOCK_BYTES - 1] ^= 1;
	let container = open(fixture);
	assert!(
		container
			.open_volume_objects(NATIVE_VOLUME, options)
			.unwrap()
			.is_none()
	);
}

fn open(fixture: Fixture) -> Container<Fixture> {
	Container::open(fixture, OpenOptions::default()).unwrap()
}
