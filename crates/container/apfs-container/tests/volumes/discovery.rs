//! Volume metadata and explicit selection cases for A-CONT-04-T01.

use apfs_container::{
	Container, Error, Limit, LookupOptions, OpenOptions, VolumeError, VolumeSelectionError,
	VolumeSelector,
};
use apfs_format::{
	object::ObjectId,
	superblock::BlockAddress,
	volume::{Error as FormatError, Unsupported, VolumeRole},
};

use super::{
	BLOCK_BYTES, DATA_RING_START, EARLY_XID, Fixture, LATEST_FIRST_DATA, LATEST_NXSB,
	LATEST_OMAP_ROOT, LATEST_XID, OBJECT_ID_OFFSET, VOLUME_SUPERBLOCK, XID_OFFSET, update_checksum,
};

const VOLUME_ID: ObjectId = ObjectId(1026);
const OTHER_ID: ObjectId = ObjectId(1027);
const OTHER_ROOT: ObjectId = ObjectId(1029);
const RESERVED_OID: ObjectId = ObjectId(1);
const NATIVE_NAME: &str = "Pomologie APFS Fixture";
const UUID: [u8; 16] = 0x55dd_69c3_cb57_4400_bd30_0676_0ace_eaef_u128.to_be_bytes();
const OTHER_UUID: [u8; 16] = 0xc792_a73e_fab2_42db_9895_6c95_32ed_42bd_u128.to_be_bytes();
const NATIVE_ROOT: ObjectId = ObjectId(1028);
const NATIVE_MAP: BlockAddress = BlockAddress(193);
const NATIVE_EXTENT_REF: BlockAddress = BlockAddress(195);
const NATIVE_SNAPSHOT_META: BlockAddress = BlockAddress(196);
const OTHER_VOLUME: u64 = 197;
const OTHER_SLOT: u32 = 2;
const OTHER_NAME: &str = "Archive";

const NXSB_MAX_VOLUMES: usize = 180;
const NXSB_VOLUME_IDS: usize = 184;
const OTHER_NXSB_ENTRY: usize = NXSB_VOLUME_IDS + OTHER_SLOT as usize * size_of::<u64>();
const VOLUME_INDEX: usize = 36;
const OPTIONAL_FEATURES: usize = 40;
const READ_ONLY_FEATURES: usize = 48;
const INCOMPATIBLE_FEATURES: usize = 56;
const QUOTA_OFFSET: usize = 80;
const VOLUME_MAP: usize = 128;
const VOLUME_ROOT: usize = 136;
const VOLUME_EXTENTS: usize = 144;
const VOLUME_SNAPSHOTS: usize = 152;
const SNAPSHOT_COUNT: usize = 216;
const VOLUME_UUID: usize = 240;
const VOLUME_FLAGS: usize = 264;
const VOLUME_NAME: usize = 704;
const MAX_NAME_BYTES: usize = 256;
const VOLUME_ROLE: usize = 964;
const VOLUME_GROUP: usize = 1008;
const SEALED_FEATURE: u64 = 1 << 5;
const SYSTEM_ROLE: u16 = 1;
const DATA_ROLE: u16 = 1 << 6;
const KNOWN_OPTIONAL_NATIVE: u64 = 1 << 1;
const UNKNOWN_FEATURE: u64 = 1 << 63;

const NODE_RECORD_COUNT: usize = 36;
const NODE_FREE_START: usize = 44;
const NODE_FREE_LENGTH: usize = 46;
const SECOND_SLOT: usize = 60;
const KEY_BYTES: usize = 2 * size_of::<u64>();
const VALUE_BYTES: usize = 2 * size_of::<u32>() + size_of::<u64>();
const FIRST_KEY: usize = 504;
const ROOT_FOOTER: usize = BLOCK_BYTES - 40;
const ROOT_KEYS: usize = ROOT_FOOTER + 24;
const VALUE_SIZE_FIELD: usize = size_of::<u32>();
const VALUE_ADDRESS_FIELD: usize = 2 * size_of::<u32>();

#[test]
fn discovers_native_volume_and_matches_independent_fsck_identity() {
	let view = open(Fixture::native());
	let opts = LookupOptions::default();
	let volumes = view.volumes(opts).unwrap();
	let [volume] = volumes.as_slice() else {
		panic!("expected the one native volume");
	};
	assert_eq!(volume.checkpoint, LATEST_XID);
	assert_eq!(volume.mapping.id, VOLUME_ID);
	assert_eq!(volume.mapping.transaction, LATEST_XID);
	assert_eq!(volume.mapping.address, BlockAddress(VOLUME_SUPERBLOCK));
	let metadata = &volume.superblock;
	assert_eq!(metadata.index, 0);
	assert_eq!(metadata.name.as_str(), NATIVE_NAME);
	assert_eq!(metadata.uuid, UUID);
	assert_eq!(metadata.role, VolumeRole::Unspecified);
	assert!(metadata.features.case_insensitive());
	assert!(!metadata.features.normalization_insensitive());
	assert_eq!(metadata.features.optional, KNOWN_OPTIONAL_NATIVE);
	assert_eq!(metadata.allocation.allocated, 5);
	assert_eq!(metadata.allocation.reserved, 0);
	assert_eq!(metadata.allocation.quota, None);
	assert_eq!(metadata.trees.object_map, NATIVE_MAP);
	assert_eq!(metadata.trees.root, NATIVE_ROOT);
	assert_eq!(metadata.trees.extent_references, NATIVE_EXTENT_REF);
	assert_eq!(metadata.trees.snapshot_metadata, NATIVE_SNAPSHOT_META);
	assert_eq!(view.volume(VOLUME_ID, opts).unwrap().as_ref(), Some(volume));
	assert!(view.volume(OTHER_ID, opts).unwrap().is_none());
	assert_eq!(view.select_volume_id(None, opts).unwrap(), VOLUME_ID);
	assert_eq!(
		view.select_volume_id(Some(VolumeSelector::Uuid(UUID)), opts)
			.unwrap(),
		VOLUME_ID
	);
	assert!(matches!(
		view.select_volume_id(Some(VolumeSelector::ObjectId(OTHER_ID)), opts),
		Err(Error::VolumeSelection(VolumeSelectionError::UnknownVolume(VolumeSelector::ObjectId(id))))
			if id == OTHER_ID
	));
	assert!(matches!(
		view.select_volume_id(Some(VolumeSelector::Uuid(OTHER_UUID)), opts),
		Err(Error::VolumeSelection(VolumeSelectionError::UnknownVolume(VolumeSelector::Uuid(uuid))))
			if uuid == OTHER_UUID
	));
}

#[test]
fn discovers_an_empty_checkpoint_and_accepts_visible_older_cow_objects() {
	let opts = LookupOptions::default();
	let mut fixture = Fixture::native();
	fixture.0.get_mut(&LATEST_FIRST_DATA).unwrap()[BLOCK_BYTES - 1] ^= 1;
	let view = open(fixture);
	assert_eq!(view.superblock().object.transaction, EARLY_XID);
	assert!(view.volumes(opts).unwrap().is_empty());
	assert!(view.volume(VOLUME_ID, opts).unwrap().is_none());
	assert!(matches!(
		view.select_volume_id(None, opts),
		Err(Error::VolumeSelection(VolumeSelectionError::NoVolumes))
	));

	let mut fixture = Fixture::native();
	fixture.set_u64(LATEST_OMAP_ROOT, FIRST_KEY + size_of::<u64>(), EARLY_XID.0);
	fixture.set_u64(VOLUME_SUPERBLOCK, XID_OFFSET, EARLY_XID.0);
	let volume = open(fixture).volume(VOLUME_ID, opts).unwrap().unwrap();
	assert_eq!(volume.checkpoint, LATEST_XID);
	assert_eq!(volume.mapping.transaction, EARLY_XID);
}

#[test]
fn enumerates_sparse_slots_without_guessing_a_volume_and_shares_one_budget() {
	let opts = LookupOptions::default();
	let view = open(two_volumes(OTHER_UUID));
	assert!(view.ephemeral_mapping(OTHER_ID).is_some());
	let volumes = view.volumes(opts).unwrap();
	let [first, other] = volumes.as_slice() else {
		panic!("expected both declared volumes");
	};
	assert_eq!(first.mapping.id, VOLUME_ID);
	assert_eq!(other.mapping.id, OTHER_ID);
	assert_eq!(other.superblock.index, OTHER_SLOT);
	assert_eq!(other.superblock.name.as_str(), OTHER_NAME);
	assert_eq!(other.superblock.role, VolumeRole::Data);
	assert!(matches!(
		view.select_volume_id(None, opts),
		Err(Error::VolumeSelection(
			VolumeSelectionError::AmbiguousVolumes(2)
		))
	));
	assert_eq!(
		view.select_volume_id(Some(VolumeSelector::Uuid(OTHER_UUID)), opts)
			.unwrap(),
		OTHER_ID
	);
	assert_eq!(view.volume(OTHER_ID, opts).unwrap().as_ref(), Some(other));
	assert!(matches!(
		view.volumes(LookupOptions {
			max_read_bytes: 3 * BLOCK_BYTES as u64,
			..opts
		}),
		Err(Error::Limit(Limit::ReadBytes))
	));
	assert!(matches!(
		open(two_volumes(UUID)).volumes(opts),
		Err(Error::Volume {
			id: OTHER_ID,
			reason: VolumeError::DuplicateUuid
		})
	));

	let mut fixture = two_volumes(OTHER_UUID);
	fixture.set_u64(OTHER_VOLUME, VOLUME_ROOT, NATIVE_ROOT.0);
	assert!(matches!(
		open(fixture).volumes(opts),
		Err(Error::Volume {
			id: OTHER_ID,
			reason: VolumeError::AliasedTree
		})
	));

	let mut fixture = two_volumes(OTHER_UUID);
	fixture.set_u64(VOLUME_SUPERBLOCK, INCOMPATIBLE_FEATURES, SEALED_FEATURE);
	let view = open(fixture);
	assert!(view.volumes(opts).is_err());
	assert!(view.select_volume_id(None, opts).is_err());
	assert!(
		view.select_volume_id(Some(VolumeSelector::Uuid(OTHER_UUID)), opts)
			.is_err()
	);
	assert_eq!(
		view.select_volume_id(Some(VolumeSelector::ObjectId(OTHER_ID)), opts)
			.unwrap(),
		OTHER_ID
	);
	assert_eq!(
		view.volume(OTHER_ID, opts).unwrap().unwrap().mapping.id,
		OTHER_ID
	);
}

#[test]
fn rejects_malformed_volume_tables_and_mismatched_slots() {
	let opts = LookupOptions::default();
	let mut fixture = Fixture::native();
	fixture.set_u64(LATEST_NXSB, OTHER_NXSB_ENTRY, OTHER_ID.0);
	assert!(matches!(
		open(fixture).volumes(opts),
		Err(Error::Volume {
			id: OTHER_ID,
			reason: VolumeError::SlotBounds(OTHER_SLOT)
		})
	));
	let mut fixture = two_volumes(OTHER_UUID);
	fixture.set_u64(LATEST_NXSB, OTHER_NXSB_ENTRY, VOLUME_ID.0);
	assert!(matches!(
		open(fixture).volume(VOLUME_ID, opts),
		Err(Error::Volume {
			id: VOLUME_ID,
			reason: VolumeError::DuplicateId
		})
	));

	let mut fixture = Fixture::native();
	fixture.set_u64(LATEST_NXSB, NXSB_VOLUME_IDS, OTHER_ID.0);
	assert!(matches!(
		open(fixture).volumes(opts),
		Err(Error::Volume {
			id: OTHER_ID,
			reason: VolumeError::MissingObject
		})
	));
	let mut fixture = Fixture::native();
	fixture.set_u32(VOLUME_SUPERBLOCK, VOLUME_INDEX, OTHER_SLOT);
	assert!(matches!(
		open(fixture).volumes(opts),
		Err(Error::Volume {
			id: VOLUME_ID,
			reason: VolumeError::SlotMismatch {
				expected: 0,
				actual: OTHER_SLOT
			}
		})
	));
	let mut fixture = Fixture::native();
	fixture.set_u64(LATEST_NXSB, NXSB_VOLUME_IDS, RESERVED_OID.0);
	assert!(matches!(
		open(fixture).volumes(opts),
		Err(Error::Volume {
			reason: VolumeError::InvalidId,
			..
		})
	));
}

#[test]
fn rejects_unsupported_profiles_and_preserves_safe_optional_masks() {
	for (offset, value, expected) in [
		(
			INCOMPATIBLE_FEATURES,
			SEALED_FEATURE,
			Unsupported::IncompatibleFeatures(SEALED_FEATURE),
		),
		(VOLUME_FLAGS, 0, Unsupported::StatusFlags(0)),
		(SNAPSHOT_COUNT, 1, Unsupported::SnapshotOrRevert),
		(VOLUME_GROUP, 1, Unsupported::VolumeGroup),
	] {
		let mut fixture = Fixture::native();
		fixture.set_u64(VOLUME_SUPERBLOCK, offset, value);
		assert_eq!(format_failure(fixture), FormatError::Unsupported(expected));
	}
	let mut fixture = Fixture::native();
	let volume = fixture.0.get_mut(&VOLUME_SUPERBLOCK).unwrap();
	write(volume, VOLUME_ROLE, SYSTEM_ROLE.to_le_bytes());
	update_checksum(volume);
	assert_eq!(
		format_failure(fixture),
		FormatError::Unsupported(Unsupported::Role(SYSTEM_ROLE))
	);

	let mut fixture = Fixture::native();
	fixture.set_u64(VOLUME_SUPERBLOCK, OPTIONAL_FEATURES, UNKNOWN_FEATURE);
	fixture.set_u64(VOLUME_SUPERBLOCK, READ_ONLY_FEATURES, UNKNOWN_FEATURE);
	let volume = open(fixture)
		.volume(VOLUME_ID, LookupOptions::default())
		.unwrap()
		.unwrap();
	assert_eq!(volume.superblock.features.optional, UNKNOWN_FEATURE);
	assert_eq!(
		volume.superblock.features.read_only_compatible,
		UNKNOWN_FEATURE
	);
}

#[test]
fn rejects_invalid_volume_labels_allocation_and_tree_declarations() {
	let mut fixture = Fixture::native();
	let volume = fixture.0.get_mut(&VOLUME_SUPERBLOCK).unwrap();
	volume[VOLUME_NAME..][..MAX_NAME_BYTES].fill(b'a');
	update_checksum(volume);
	assert_eq!(format_failure(fixture), FormatError::InvalidName);

	let mut fixture = Fixture::native();
	let volume = fixture.0.get_mut(&VOLUME_SUPERBLOCK).unwrap();
	volume[VOLUME_NAME] = u8::MAX;
	update_checksum(volume);
	assert_eq!(format_failure(fixture), FormatError::InvalidName);

	let mut fixture = Fixture::native();
	fixture.set_u64(VOLUME_SUPERBLOCK, QUOTA_OFFSET, 1);
	assert_eq!(format_failure(fixture), FormatError::InvalidAllocation);

	let mut fixture = Fixture::native();
	fixture.set_u64(VOLUME_SUPERBLOCK, VOLUME_MAP, NATIVE_EXTENT_REF.0);
	assert_eq!(format_failure(fixture), FormatError::InvalidTreeReference);

	let mut fixture = Fixture::native();
	fixture.set_u64(VOLUME_SUPERBLOCK, VOLUME_MAP, DATA_RING_START);
	assert!(matches!(
		open(fixture).volumes(LookupOptions::default()),
		Err(Error::ObjectMap {
			reason: apfs_container::ObjectMapError::Address,
			..
		})
	));
}

fn open(fixture: Fixture) -> Container<Fixture> {
	Container::open(fixture, OpenOptions::default()).unwrap()
}

fn format_failure(fixture: Fixture) -> FormatError {
	match open(fixture).volumes(LookupOptions::default()) {
		Err(Error::Volume {
			id: VOLUME_ID,
			reason: VolumeError::Format(error),
		}) => error,
		other => panic!("expected volume format failure, got {other:?}"),
	}
}

fn two_volumes(uuid: [u8; 16]) -> Fixture {
	let mut fixture = Fixture::native();
	fixture.set_u32(LATEST_NXSB, NXSB_MAX_VOLUMES, OTHER_SLOT + 1);
	fixture.set_u64(LATEST_NXSB, OTHER_NXSB_ENTRY, OTHER_ID.0);
	let root = fixture.0.get_mut(&LATEST_OMAP_ROOT).unwrap();
	write(root, NODE_RECORD_COUNT, 2u32.to_le_bytes());
	write(root, NODE_FREE_START, (2 * KEY_BYTES as u16).to_le_bytes());
	let free = ROOT_FOOTER - 2 * VALUE_BYTES - FIRST_KEY - 2 * KEY_BYTES;
	write(root, NODE_FREE_LENGTH, (free as u16).to_le_bytes());
	write(root, SECOND_SLOT, (KEY_BYTES as u16).to_le_bytes());
	write(
		root,
		SECOND_SLOT + size_of::<u16>(),
		(2 * VALUE_BYTES as u16).to_le_bytes(),
	);
	write(root, FIRST_KEY + KEY_BYTES, OTHER_ID.0.to_le_bytes());
	write(
		root,
		FIRST_KEY + KEY_BYTES + size_of::<u64>(),
		LATEST_XID.0.to_le_bytes(),
	);
	let value = ROOT_FOOTER - 2 * VALUE_BYTES;
	write(
		root,
		value + VALUE_SIZE_FIELD,
		(BLOCK_BYTES as u32).to_le_bytes(),
	);
	write(
		root,
		value + VALUE_ADDRESS_FIELD,
		OTHER_VOLUME.to_le_bytes(),
	);
	write(root, ROOT_KEYS, 2u64.to_le_bytes());
	update_checksum(root);

	let mut volume = fixture.0[&VOLUME_SUPERBLOCK];
	write(&mut volume, OBJECT_ID_OFFSET, OTHER_ID.0.to_le_bytes());
	write(&mut volume, VOLUME_INDEX, OTHER_SLOT.to_le_bytes());
	write(&mut volume, VOLUME_UUID, uuid);
	write(&mut volume, VOLUME_ROLE, DATA_ROLE.to_le_bytes());
	write(&mut volume, VOLUME_MAP, 180u64.to_le_bytes());
	write(&mut volume, VOLUME_ROOT, OTHER_ROOT.0.to_le_bytes());
	write(&mut volume, VOLUME_EXTENTS, 181u64.to_le_bytes());
	write(&mut volume, VOLUME_SNAPSHOTS, 182u64.to_le_bytes());
	volume[VOLUME_NAME..][..MAX_NAME_BYTES].fill(0);
	volume[VOLUME_NAME..][..OTHER_NAME.len()].copy_from_slice(OTHER_NAME.as_bytes());
	update_checksum(&mut volume);
	fixture.0.insert(OTHER_VOLUME, volume);
	fixture
}

fn write<const N: usize>(bytes: &mut [u8], offset: usize, value: [u8; N]) {
	bytes[offset..][..N].copy_from_slice(&value);
}
