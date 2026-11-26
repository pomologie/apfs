//! A-CONT-01-T03 resolution evidence for equal numeric identities.

use apfs_container::{Container, Corruption, Error, LookupOptions, ObjectMapError, OpenOptions};
use apfs_format::{
	Error as FormatError, object::ObjectId, object_map::ObjectMap, superblock::BlockAddress,
};

use super::{
	Fixture, LATEST_NXSB, LATEST_OMAP, LATEST_OMAP_ROOT, LATEST_XID, OBJECT_ID_OFFSET,
	VOLUME_SUPERBLOCK,
};

// The native checkpoint already maps this ephemeral queue OID to block 13.
const COMMON_ID: ObjectId = ObjectId(1027);
const PHYSICAL_MAP: BlockAddress = BlockAddress(COMMON_ID.0);
const EPHEMERAL_QUEUE: BlockAddress = BlockAddress(13);
const VIRTUAL_VOLUME: BlockAddress = BlockAddress(VOLUME_SUPERBLOCK);
const NXSB_OBJECT_MAP_OFFSET: usize = 160;
const NXSB_FIRST_VOLUME_OFFSET: usize = 184;
// One record, after the fixed root-leaf header and native 448-byte table.
const OMAP_ROOT_FIRST_KEY_OFFSET: usize = 56 + 448;

fn collision_fixture() -> Fixture {
	let mut fixture = Fixture::native();
	let physical = fixture.0.remove(&LATEST_OMAP).unwrap();
	assert!(fixture.0.insert(PHYSICAL_MAP.0, physical).is_none());
	fixture.set_u64(PHYSICAL_MAP.0, OBJECT_ID_OFFSET, PHYSICAL_MAP.0);
	fixture.set_u64(LATEST_NXSB, NXSB_OBJECT_MAP_OFFSET, PHYSICAL_MAP.0);
	fixture.set_u64(LATEST_NXSB, NXSB_FIRST_VOLUME_OFFSET, COMMON_ID.0);
	fixture.set_u64(LATEST_OMAP_ROOT, OMAP_ROOT_FIRST_KEY_OFFSET, COMMON_ID.0);
	fixture.set_u64(VIRTUAL_VOLUME.0, OBJECT_ID_OFFSET, COMMON_ID.0);
	fixture
}

fn open(fixture: Fixture) -> Result<Container<Fixture>, Error<u64>> {
	Container::open_at(fixture, OpenOptions::default(), LATEST_XID)
}

#[test]
fn resolves_equal_numeric_ids_in_separate_namespaces() {
	let view = open(collision_fixture()).unwrap();
	assert_eq!(view.superblock().object_map, PHYSICAL_MAP);
	assert_eq!(
		view.superblock().volume_ids().collect::<Vec<_>>(),
		[COMMON_ID]
	);
	assert_eq!(
		view.ephemeral_mapping(COMMON_ID).unwrap().physical,
		EPHEMERAL_QUEUE,
	);
	let volume = view
		.volume(COMMON_ID, LookupOptions::default())
		.unwrap()
		.unwrap();
	assert_eq!(volume.mapping.address, VIRTUAL_VOLUME);
	assert_eq!(volume.superblock.object.id, COMMON_ID);
	assert!(view.diagnostics().is_empty());
}

#[test]
fn rejects_equal_id_objects_substituted_from_another_namespace() {
	for (destination, replacement) in [
		(PHYSICAL_MAP, VIRTUAL_VOLUME),
		(EPHEMERAL_QUEUE, PHYSICAL_MAP),
	] {
		let mut fixture = collision_fixture();
		let replacement = fixture.0[&replacement.0];
		fixture.0.insert(destination.0, replacement);
		assert!(matches!(
			open(fixture),
			Err(Error::CandidateCorruption(damage))
				if damage.descriptor == BlockAddress(LATEST_NXSB)
					&& damage.transaction == Some(LATEST_XID)
					&& damage.reason == Corruption::Object
		));
	}

	let mut fixture = collision_fixture();
	let physical = fixture.0[&PHYSICAL_MAP.0];
	fixture.0.insert(VIRTUAL_VOLUME.0, physical);
	let view = open(fixture).unwrap();
	assert!(matches!(
		view.volume(COMMON_ID, LookupOptions::default()),
		Err(Error::ObjectMap {
			address: VIRTUAL_VOLUME,
			reason: ObjectMapError::Format(FormatError::UnexpectedObjectType(
				ObjectMap::OBJECT_TYPE
			)),
		})
	));
}
