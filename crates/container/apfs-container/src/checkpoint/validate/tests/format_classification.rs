use core::convert::Infallible;

use super::super::{
	Candidate, Corruption, Error, FormatError, KIND_MASK, Map, Superblock, TransactionId,
	Unsupported, classify_map_error, classify_superblock_error,
};
use super::LATEST_DESCRIPTOR;

const CANDIDATE: Candidate = Candidate {
	address: LATEST_DESCRIPTOR,
	xid: TransactionId(2),
};
const MAP_EXTENSION_FLAG: u32 = 1 << 7;

#[test]
fn superblock_type_refusal_preserves_expected_kind_and_descriptor_identity() {
	let other_storage = (Superblock::OBJECT_TYPE & KIND_MASK) | (Map::OBJECT_TYPE & !KIND_MASK);
	assert_unsupported(
		classify_superblock_error(CANDIDATE, FormatError::UnexpectedObjectType(other_storage)),
		Unsupported::SuperblockObjectType(other_storage),
	);
	for error in [
		FormatError::UnexpectedObjectType(Superblock::OBJECT_TYPE),
		FormatError::UnexpectedObjectType(Map::OBJECT_TYPE),
		FormatError::UnsupportedCheckpointFlags(MAP_EXTENSION_FLAG),
		FormatError::InvalidChecksum,
	] {
		assert_corruption(classify_superblock_error(CANDIDATE, error), error);
	}
}

#[test]
fn map_type_and_flag_refusals_preserve_kind_flags_and_descriptor_identity() {
	let other_storage = (Map::OBJECT_TYPE & KIND_MASK) | (Superblock::OBJECT_TYPE & !KIND_MASK);
	assert_unsupported(
		classify_map_error(CANDIDATE, FormatError::UnexpectedObjectType(other_storage)),
		Unsupported::CheckpointMapType(other_storage),
	);
	assert_unsupported(
		classify_map_error(
			CANDIDATE,
			FormatError::UnsupportedCheckpointFlags(MAP_EXTENSION_FLAG),
		),
		Unsupported::CheckpointMapFlags(MAP_EXTENSION_FLAG),
	);
	for error in [
		FormatError::UnexpectedObjectType(Map::OBJECT_TYPE),
		FormatError::UnexpectedObjectType(Superblock::OBJECT_TYPE),
		FormatError::InvalidCheckpoint,
	] {
		assert_corruption(classify_map_error(CANDIDATE, error), error);
	}
}

fn assert_unsupported(observed: Error<Infallible>, expected: Unsupported) {
	let Error::Unsupported {
		descriptor,
		transaction,
		reason,
	} = observed
	else {
		panic!("expected unsupported {expected:?}, got {observed:?}");
	};
	assert_eq!(
		(descriptor, transaction, reason),
		(CANDIDATE.address, CANDIDATE.xid, expected)
	);
}

fn assert_corruption(observed: Error<Infallible>, expected: FormatError) {
	let Error::CandidateCorruption(damage) = observed else {
		panic!("expected candidate corruption {expected:?}, got {observed:?}");
	};
	assert_eq!(damage.descriptor, CANDIDATE.address);
	assert_eq!(damage.transaction, Some(CANDIDATE.xid));
	assert_eq!(damage.reason, Corruption::Format(expected));
}
