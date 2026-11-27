use super::{
	BlockAddress, ByteOffset, Candidate, Corruption, DEVICE_BYTES, EARLY, Error, LATEST_DESCRIPTOR,
	NativeBlocks, Superblock, Vec, native_mappings,
};

#[test]
fn payload_identity_mismatch_stops_at_its_first_read() {
	const OTHER_SUBTYPE: u32 = 1;
	let (checkpoint, rings, mappings) = native_mappings();
	let native = mappings[0];
	let candidate = Candidate {
		address: LATEST_DESCRIPTOR,
		xid: checkpoint.object.transaction,
	};
	let early = Superblock::decode(EARLY, DEVICE_BYTES).unwrap();
	let older_candidate = Candidate {
		xid: early.object.transaction,
		..candidate
	};

	let mut other_id = native;
	other_id.id = checkpoint.next_object;
	let mut other_type = native;
	other_type.object_type = mappings
		.iter()
		.find(|mapping| mapping.object_type != native.object_type)
		.unwrap()
		.object_type;
	let mut other_subtype = native;
	other_subtype.subtype = OTHER_SUBTYPE;
	assert_ne!(older_candidate.xid, candidate.xid);
	assert_ne!(other_id.id, native.id);
	assert_ne!(other_subtype.subtype, native.subtype);

	for (candidate, expected_mapping) in [
		(older_candidate, native),
		(candidate, other_id),
		(candidate, other_type),
		(candidate, other_subtype),
	] {
		let source = NativeBlocks::new(DEVICE_BYTES);
		let result = source.discovery(2).validate_payloads(
			&[expected_mapping],
			&checkpoint,
			&rings,
			candidate,
			&mut Vec::new(),
		);
		assert_candidate_corruption(result, candidate, Corruption::Object);
		assert_eq!(*source.reads.borrow(), [native.physical]);
	}
}

#[test]
fn physical_object_map_must_be_outside_bootstrap_and_checkpoint_rings() {
	const BOOTSTRAP_ADDRESS: BlockAddress = BlockAddress(0);
	let (mut checkpoint, rings, mappings) = native_mappings();
	let candidate = Candidate {
		address: LATEST_DESCRIPTOR,
		xid: checkpoint.object.transaction,
	};

	for reserved in [BOOTSTRAP_ADDRESS, rings.descriptor, rings.data] {
		checkpoint.object_map = reserved;
		let source = NativeBlocks::new(DEVICE_BYTES);
		let result = source.discovery(mappings.len() + 1).validate_payloads(
			&mappings,
			&checkpoint,
			&rings,
			candidate,
			&mut Vec::new(),
		);
		assert_candidate_corruption(result, candidate, Corruption::Ring);
		assert!(
			source
				.reads
				.borrow()
				.iter()
				.copied()
				.eq(mappings.iter().map(|mapping| mapping.physical))
		);
	}
}

fn assert_candidate_corruption(
	result: Result<(), Error<ByteOffset>>,
	candidate: Candidate,
	reason: Corruption,
) {
	assert!(
		matches!(
			result,
			Err(Error::CandidateCorruption(ref damage))
				if damage.descriptor == candidate.address
					&& damage.transaction == Some(candidate.xid)
					&& damage.reason == reason
		),
		"expected {reason:?}, got {result:?}"
	);
}
