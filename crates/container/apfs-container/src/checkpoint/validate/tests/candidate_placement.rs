use super::super::{FormatError, validate_candidate_rings};
use super::{
	AreaLocation, BLOCK_BYTES, BOOTSTRAP, BlockAddress, ByteOffset, Candidate, Corruption,
	DEVICE_BYTES, Discovery, EARLY, Error, LARGER_BOOTSTRAP, LARGER_DEVICE_BYTES, LATEST,
	LATEST_DESCRIPTOR, LATEST_MAP, Map, Probe, ReadAt, RefCell, Rings, Superblock, Vec,
};
use crate::OpenOptions;

const LATEST_MAP_ADDRESS: BlockAddress = BlockAddress(3);
const FOLLOWING_MAP_ADDRESS: BlockAddress = BlockAddress(LATEST_MAP_ADDRESS.0 + 1);
const FOLLOWING_DESCRIPTOR: BlockAddress = BlockAddress(LATEST_DESCRIPTOR.0 + 1);

#[test]
fn candidate_ring_requires_a_map_consistent_cursors_and_the_terminal_address() {
	let native = Superblock::decode(LATEST, DEVICE_BYTES).unwrap();
	let rings = Rings::from_bootstrap(&native).unwrap();
	assert_eq!(
		validate_candidate_rings(&native, &rings, LATEST_DESCRIPTOR),
		Ok(())
	);

	let mut wrapped = native.clone();
	for area in [&mut wrapped.descriptors, &mut wrapped.data] {
		area.index = area.blocks - 1;
		area.next = area.length - 1;
	}
	assert_eq!(
		validate_candidate_rings(&wrapped, &rings, rings.descriptor),
		Ok(())
	);

	const NXSB_ONLY_LENGTH: u32 = 1;
	let mut nxsb_only = native.clone();
	nxsb_only.descriptors.length = NXSB_ONLY_LENGTH;
	nxsb_only.descriptors.next =
		(nxsb_only.descriptors.index + NXSB_ONLY_LENGTH) % nxsb_only.descriptors.blocks;
	let nxsb_only_address =
		BlockAddress(rings.descriptor.0 + u64::from(nxsb_only.descriptors.index));

	assert_ne!(native.descriptors.next, native.descriptors.index);
	let mut wrong_descriptor_cursor = native.clone();
	wrong_descriptor_cursor.descriptors.next = native.descriptors.index;
	assert_ne!(native.data.next, native.data.index);
	let mut wrong_data_cursor = native.clone();
	wrong_data_cursor.data.next = native.data.index;

	for (checkpoint, address) in [
		(&nxsb_only, nxsb_only_address),
		(&wrong_descriptor_cursor, LATEST_DESCRIPTOR),
		(&wrong_data_cursor, LATEST_DESCRIPTOR),
		(&native, FOLLOWING_DESCRIPTOR),
	] {
		assert_eq!(
			validate_candidate_rings(checkpoint, &rings, address),
			Err(Corruption::Ring)
		);
	}
}

#[test]
fn candidate_transaction_and_terminal_slot_are_checked_before_map_reads() {
	let bootstrap = Superblock::decode(BOOTSTRAP, DEVICE_BYTES).unwrap();
	let rings = Rings::from_bootstrap(&bootstrap).unwrap();
	let early = Superblock::decode(EARLY, DEVICE_BYTES).unwrap();
	let latest = Superblock::decode(LATEST, DEVICE_BYTES).unwrap();
	assert_ne!(early.object.transaction, latest.object.transaction);
	for (address, xid, expected) in [
		(
			LATEST_DESCRIPTOR,
			early.object.transaction,
			Corruption::Identity,
		),
		(
			FOLLOWING_DESCRIPTOR,
			latest.object.transaction,
			Corruption::Ring,
		),
	] {
		let candidate = Candidate { address, xid };
		let source = RetainedBlock::new(address, LATEST);
		let result =
			source
				.discovery()
				.read_candidate(&bootstrap, &rings, candidate, &mut Vec::new());
		assert_candidate_corruption(result, candidate, expected);
		assert_eq!(*source.reads.borrow(), [address]);
	}
}

#[test]
fn candidate_declared_extent_must_fit_the_source_view() {
	let bootstrap = Superblock::decode(BOOTSTRAP, DEVICE_BYTES).unwrap();
	let larger = Superblock::decode(LARGER_BOOTSTRAP, LARGER_DEVICE_BYTES).unwrap();
	assert_eq!(
		larger.geometry.block_bytes(),
		bootstrap.geometry.block_bytes()
	);
	assert!(larger.geometry.block_count() > bootstrap.geometry.block_count());
	let candidate = Candidate {
		address: LATEST_DESCRIPTOR,
		xid: larger.object.transaction,
	};
	let rings = Rings::from_bootstrap(&bootstrap).unwrap();
	let source = RetainedBlock::new(candidate.address, LARGER_BOOTSTRAP);
	let result = source
		.discovery()
		.read_candidate(&bootstrap, &rings, candidate, &mut Vec::new());

	assert_candidate_corruption(
		result,
		candidate,
		Corruption::Format(FormatError::InvalidGeometry),
	);
	assert_eq!(*source.reads.borrow(), [candidate.address]);
}

#[test]
fn fragmented_areas_cannot_define_contiguous_checkpoint_rings() {
	let bootstrap = Superblock::decode(BOOTSTRAP, DEVICE_BYTES).unwrap();
	let rings = Rings::from_bootstrap(&bootstrap).unwrap();
	let mut descriptor_tree = bootstrap.clone();
	descriptor_tree.descriptors.location = AreaLocation::FragmentTree(rings.descriptor);
	let mut data_tree = bootstrap;
	data_tree.data.location = AreaLocation::FragmentTree(rings.data);

	for checkpoint in [descriptor_tree, data_tree] {
		assert!(matches!(
			Rings::from_bootstrap(&checkpoint),
			Err(Corruption::Ring)
		));
	}
}

#[test]
fn checkpoint_map_must_match_its_slot_and_terminate_the_declared_sequence() {
	let native = Superblock::decode(LATEST, DEVICE_BYTES).unwrap();
	let rings = Rings::from_bootstrap(&native).unwrap();
	let candidate = Candidate {
		address: LATEST_DESCRIPTOR,
		xid: native.object.transaction,
	};
	let source = RetainedBlock::new(LATEST_MAP_ADDRESS, LATEST_MAP);
	let decoded = Map::decode(LATEST_MAP, native.geometry).unwrap();
	assert!(decoded.is_last());
	assert_eq!(native.descriptors.length, 2);
	let mut scratch = Vec::new();
	let mappings = source
		.discovery()
		.read_maps(&native, &rings, candidate, &mut scratch)
		.unwrap();
	assert!(mappings.into_iter().eq(decoded.mappings()));
	assert_eq!(*source.reads.borrow(), [LATEST_MAP_ADDRESS]);

	// Reuse the complete native map unchanged. These two declarations disagree
	// with its recorded physical OID or its terminal marker, respectively.
	let mut shifted = native.clone();
	shifted.descriptors.index += 1;
	shifted.descriptors.next += 1;
	let mut extended = native;
	extended.descriptors.length += 1;
	extended.descriptors.next += 1;
	let candidate = Candidate {
		address: FOLLOWING_DESCRIPTOR,
		..candidate
	};
	for (checkpoint, address) in [
		(shifted, FOLLOWING_MAP_ADDRESS),
		(extended, LATEST_MAP_ADDRESS),
	] {
		let source = RetainedBlock::new(address, LATEST_MAP);
		let result = source
			.discovery()
			.read_maps(&checkpoint, &rings, candidate, &mut scratch);
		assert_candidate_corruption(result, candidate, Corruption::Object);
		assert_eq!(*source.reads.borrow(), [address]);
	}
}

struct RetainedBlock {
	address: BlockAddress,
	bytes: &'static [u8],
	reads: RefCell<Vec<BlockAddress>>,
}

impl RetainedBlock {
	fn new(address: BlockAddress, bytes: &'static [u8]) -> Self {
		Self {
			address,
			bytes,
			reads: RefCell::new(Vec::new()),
		}
	}

	fn discovery(&self) -> Discovery<'_, Self> {
		Discovery {
			// Leave room for a second read so budget exhaustion cannot mask
			// an incorrect placement or map-ordering check.
			probe: Probe::new(self, BLOCK_BYTES, (2 * BLOCK_BYTES) as u64),
			max_mappings: OpenOptions::default().max_mappings,
		}
	}
}

impl ReadAt for RetainedBlock {
	type Error = ByteOffset;

	fn len(&self) -> u64 {
		DEVICE_BYTES
	}

	fn read_exact_at(&self, offset: ByteOffset, out: &mut [u8]) -> Result<(), Self::Error> {
		let address = BlockAddress(offset.0 / BLOCK_BYTES as u64);
		self.reads.borrow_mut().push(address);
		if address != self.address
			|| !offset.0.is_multiple_of(BLOCK_BYTES as u64)
			|| out.len() != BLOCK_BYTES
		{
			return Err(offset);
		}
		out.copy_from_slice(self.bytes);
		Ok(())
	}
}

fn assert_candidate_corruption<T: core::fmt::Debug>(
	result: Result<T, Error<ByteOffset>>,
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
