//! Exact checkpoint selection coverage for A-CONT-02 and A-CONT-03.

use apfs_container::{
	Container, Corruption, Diagnostic, Error, Limit, LookupOptions, OpenOptions, Unsupported,
};
use apfs_format::{
	object::{ObjectId, TransactionId},
	superblock::{BLOCK_SIZE_PREFIX_BYTES, BlockAddress},
};

use super::{
	BLOCK_BYTES, DATA_RING_START, EARLY_NXSB, EARLY_OMAP, EARLY_XID, Fixture,
	LAST_DESCRIPTOR_BLOCK, LATEST_FIRST_DATA, LATEST_MAP, LATEST_NXSB, LATEST_OMAP, LATEST_XID,
	MAP_FLAGS_OFFSET, VOLUME_SUPERBLOCK,
};

const VOLUME_ID: ObjectId = ObjectId(1026);
const SPACE_MANAGER_ID: ObjectId = ObjectId(1024);
const ABSENT_XID: TransactionId = TransactionId(LATEST_XID.0 + 1);
const UNSUPPORTED_MAP_FLAGS: u32 = (1 << 7) | 1;
// Bootstrap prefix and full block, then all descriptor slots except the last one.
const PARTIAL_SCAN_BYTES: u64 =
	BLOCK_SIZE_PREFIX_BYTES as u64 + LAST_DESCRIPTOR_BLOCK * BLOCK_BYTES as u64;

#[test]
fn selects_each_native_checkpoint_with_its_own_object_map() {
	let options = OpenOptions::default();
	let early = Container::open_at(Fixture::native(), options, EARLY_XID).unwrap();
	let latest = Container::open_at(Fixture::native(), options, LATEST_XID).unwrap();
	let lookup = LookupOptions::default();

	assert_eq!(early.superblock().object.transaction, EARLY_XID);
	assert_eq!(early.descriptor(), BlockAddress(EARLY_NXSB));
	assert_eq!(early.superblock().object_map, BlockAddress(EARLY_OMAP));
	assert_eq!(
		early.ephemeral_mapping(SPACE_MANAGER_ID).unwrap().physical,
		BlockAddress(DATA_RING_START)
	);
	assert!(early.diagnostics().is_empty());
	assert!(early.volumes(lookup).unwrap().is_empty());
	assert!(
		early
			.lookup_virtual_mapping(VOLUME_ID, EARLY_XID, lookup)
			.unwrap()
			.is_none()
	);

	assert_eq!(latest.superblock().object.transaction, LATEST_XID);
	assert_eq!(latest.descriptor(), BlockAddress(LATEST_NXSB));
	assert_eq!(latest.superblock().object_map, BlockAddress(LATEST_OMAP));
	assert_eq!(
		latest.ephemeral_mapping(SPACE_MANAGER_ID).unwrap().physical,
		BlockAddress(LATEST_FIRST_DATA)
	);
	let volume = latest.volume(VOLUME_ID, lookup).unwrap().unwrap();
	assert_eq!(volume.checkpoint, LATEST_XID);
	assert_eq!(volume.mapping.address, BlockAddress(VOLUME_SUPERBLOCK));
}

#[test]
fn rejects_an_absent_xid_even_if_the_bootstrap_advertises_it() {
	let options = OpenOptions::default();
	assert!(matches!(
		Container::open_at(Fixture::native(), options, ABSENT_XID),
		Err(Error::CheckpointNotFound { transaction: ABSENT_XID, diagnostics })
			if diagnostics.is_empty()
	));

	let mut fixture = Fixture::native();
	fixture.0.insert(LATEST_NXSB, [0; BLOCK_BYTES]);
	assert!(matches!(
		Container::open_at(fixture, options, LATEST_XID),
		Err(Error::CheckpointNotFound { transaction: LATEST_XID, diagnostics })
			if diagnostics.is_empty()
	));
}

#[test]
fn rejects_a_torn_requested_checkpoint_without_rolling_back() {
	let options = OpenOptions::default();
	for torn in [LATEST_MAP, LATEST_FIRST_DATA] {
		let mut fixture = Fixture::native();
		fixture.0.get_mut(&torn).unwrap()[BLOCK_BYTES - 1] ^= 1;
		assert!(matches!(
			Container::open_at(fixture, options, LATEST_XID),
			Err(Error::CandidateCorruption(damage))
				if damage.descriptor == BlockAddress(LATEST_NXSB)
					&& damage.transaction == Some(LATEST_XID)
					&& damage.reason == Corruption::Format(apfs_format::Error::InvalidChecksum)
		));
	}
}

#[test]
fn does_not_trust_a_descriptor_xid_when_its_checksum_fails() {
	let mut fixture = Fixture::native();
	fixture.0.get_mut(&LATEST_NXSB).unwrap()[BLOCK_BYTES - 1] ^= 1;

	assert!(matches!(
		Container::open_at(fixture, OpenOptions::default(), LATEST_XID),
		Err(Error::CheckpointNotFound { transaction: LATEST_XID, diagnostics })
			if matches!(diagnostics.as_slice(), [Diagnostic::Rejected(damage)]
				if damage.descriptor == BlockAddress(LATEST_NXSB)
					&& damage.transaction.is_none()
					&& damage.reason == Corruption::Format(apfs_format::Error::InvalidChecksum))
	));
}

#[test]
fn only_duplicate_descriptors_for_the_requested_xid_are_ambiguous() {
	let duplicate = || {
		let mut fixture = Fixture::native();
		fixture
			.0
			.insert(LAST_DESCRIPTOR_BLOCK, fixture.0[&EARLY_NXSB]);
		fixture
	};
	let options = OpenOptions::default();

	assert!(matches!(
		Container::open_at(duplicate(), options, EARLY_XID),
		Err(Error::AmbiguousTransaction(EARLY_XID))
	));
	let latest = Container::open_at(duplicate(), options, LATEST_XID).unwrap();
	assert_eq!(latest.descriptor(), BlockAddress(LATEST_NXSB));
}

#[test]
fn exhausts_the_scan_budget_before_declaring_presence_or_absence() {
	let options = OpenOptions {
		max_read_bytes: PARTIAL_SCAN_BYTES,
		..OpenOptions::default()
	};
	for transaction in [EARLY_XID, ABSENT_XID] {
		assert!(matches!(
			Container::open_at(Fixture::native(), options, transaction),
			Err(Error::Limit(Limit::ReadBytes))
		));
	}
}

#[test]
fn preserves_requested_checkpoint_errors_without_opening_other_payloads() {
	let options = OpenOptions::default();
	let mut fixture = Fixture::native();
	fixture.set_u32(LATEST_MAP, MAP_FLAGS_OFFSET, UNSUPPORTED_MAP_FLAGS);
	assert!(matches!(
		Container::open_at(fixture, options, LATEST_XID),
		Err(Error::Unsupported {
			descriptor: BlockAddress(LATEST_NXSB),
			transaction: LATEST_XID,
			reason: Unsupported::CheckpointMapFlags(UNSUPPORTED_MAP_FLAGS),
		})
	));

	let without_latest_payload = || {
		let mut fixture = Fixture::native();
		fixture.0.remove(&LATEST_FIRST_DATA);
		fixture
	};
	assert!(matches!(
		Container::open_at(without_latest_payload(), options, LATEST_XID),
		Err(Error::Read {
			source: LATEST_FIRST_DATA,
			..
		})
	));
	let early = Container::open_at(without_latest_payload(), options, EARLY_XID).unwrap();
	assert_eq!(early.descriptor(), BlockAddress(EARLY_NXSB));
}
