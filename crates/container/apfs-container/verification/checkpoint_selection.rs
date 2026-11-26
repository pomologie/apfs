use super::{
	BLOCK_BYTES, CHECKSUM_BYTES, DATA_RING_START, EARLY_XID, Fixture, LAST_DESCRIPTOR_BLOCK,
	LATEST_FIRST_DATA, LATEST_XID, MAP_FLAGS_OFFSET, MOVED_EARLY_MAP, MOVED_EARLY_NXSB,
	WRAPPED_NXSB, XID_OFFSET,
};
use apfs_container::{Container, Corruption, Damage, Diagnostic, Error, OpenOptions, Unsupported};
use apfs_core::ByteOffset;
use apfs_format::{object::TransactionId, superblock::BlockAddress};

const UNKNOWN_MAP_FLAG: u32 = 1 << 31;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
	Complete,
	AbsentDescriptor,
	TornDescriptor,
	BlankMap,
	MismatchedMap,
	UnsupportedMap,
	UnreadablePayload,
}

impl State {
	const ALL: [Self; 7] = [
		Self::Complete,
		Self::AbsentDescriptor,
		Self::TornDescriptor,
		Self::BlankMap,
		Self::MismatchedMap,
		Self::UnsupportedMap,
		Self::UnreadablePayload,
	];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Candidate {
	xid: TransactionId,
	descriptor: u64,
	map: u64,
	payload: u64,
}

const EARLY: Candidate = Candidate {
	xid: EARLY_XID,
	descriptor: MOVED_EARLY_NXSB,
	map: MOVED_EARLY_MAP,
	payload: DATA_RING_START,
};
const LATEST: Candidate = Candidate {
	xid: LATEST_XID,
	descriptor: WRAPPED_NXSB,
	map: LAST_DESCRIPTOR_BLOCK,
	payload: LATEST_FIRST_DATA,
};

impl Candidate {
	fn set_state(self, fixture: &mut Fixture, other: Self, state: State) {
		match state {
			State::Complete => (),
			State::AbsentDescriptor => {
				fixture.0.insert(self.descriptor, [0; BLOCK_BYTES]);
			}
			State::TornDescriptor => {
				let bytes = fixture.0.get_mut(&self.descriptor).unwrap();
				bytes[CHECKSUM_BYTES - 1] ^= 1;
			}
			State::BlankMap => {
				fixture.0.insert(self.map, [0; BLOCK_BYTES]);
			}
			State::MismatchedMap => fixture.set_u64(self.map, XID_OFFSET, other.xid.0),
			State::UnsupportedMap => fixture.set_u32(self.map, MAP_FLAGS_OFFSET, UNKNOWN_MAP_FLAG),
			State::UnreadablePayload => {
				assert!(fixture.0.remove(&self.payload).is_some());
			}
		}
	}

	fn expected(self, state: State) -> Outcome {
		let descriptor = BlockAddress(self.descriptor);
		let reject = |reason| {
			Outcome::Rejected(Rejection {
				descriptor,
				transaction: Some(self.xid),
				reason,
			})
		};
		match state {
			State::Complete => Outcome::Selected(descriptor, self.xid),
			State::AbsentDescriptor | State::TornDescriptor => Outcome::NoCheckpoint,
			State::BlankMap => reject(Corruption::Format(apfs_format::Error::InvalidChecksum)),
			State::MismatchedMap => reject(Corruption::Object),
			State::UnsupportedMap => Outcome::Unsupported(
				descriptor,
				self.xid,
				Unsupported::CheckpointMapFlags(UNKNOWN_MAP_FLAG),
			),
			State::UnreadablePayload => {
				Outcome::Read(ByteOffset(self.payload * BLOCK_BYTES as u64), self.payload)
			}
		}
	}
}

#[derive(Debug, Eq, PartialEq)]
struct Rejection {
	descriptor: BlockAddress,
	transaction: Option<TransactionId>,
	reason: Corruption,
}

impl From<Damage> for Rejection {
	fn from(damage: Damage) -> Self {
		Self {
			descriptor: damage.descriptor,
			transaction: damage.transaction,
			reason: damage.reason,
		}
	}
}

#[derive(Debug, Eq, PartialEq)]
enum Outcome {
	Selected(BlockAddress, TransactionId),
	NoCheckpoint,
	NotFound(TransactionId),
	Rejected(Rejection),
	Unsupported(BlockAddress, TransactionId, Unsupported),
	Read(ByteOffset, u64),
}

#[derive(Debug, Eq, PartialEq)]
enum Warning {
	Rejected(Rejection),
	NewerBootstrap(TransactionId, TransactionId),
}

fn expected(early: State, latest: State, at: Option<Candidate>) -> (Outcome, Vec<Warning>) {
	// A torn descriptor yields scan evidence even on an exact request. The
	// fixture puts the wrapped latest descriptor before the earlier one on disk.
	let mut warnings: Vec<_> = [(LATEST, latest), (EARLY, early)]
		.into_iter()
		.filter(|(_, state)| *state == State::TornDescriptor)
		.map(|(candidate, _)| {
			Warning::Rejected(Rejection {
				descriptor: BlockAddress(candidate.descriptor),
				transaction: None,
				reason: Corruption::Format(apfs_format::Error::InvalidChecksum),
			})
		})
		.collect();

	let outcome = if let Some(candidate) = at {
		let state = if candidate == EARLY { early } else { latest };
		match candidate.expected(state) {
			Outcome::NoCheckpoint => Outcome::NotFound(candidate.xid),
			result => result,
		}
	} else {
		// Only proven corruption or absence permits fallback. Once the newest
		// candidate is usable or selection is inconclusive, the old state cannot
		// affect the outcome.
		let newest = LATEST.expected(latest);
		match newest {
			Outcome::NoCheckpoint | Outcome::Rejected(_) => {
				if let Outcome::Rejected(damage) = newest {
					warnings.push(Warning::Rejected(damage));
				}
				match EARLY.expected(early) {
					result @ Outcome::Selected(..) => {
						warnings.push(Warning::NewerBootstrap(LATEST.xid, EARLY.xid));
						result
					}
					Outcome::Rejected(damage) => {
						warnings.push(Warning::Rejected(damage));
						Outcome::NoCheckpoint
					}
					result => result,
				}
			}
			result => result,
		}
	};
	if matches!(
		outcome,
		Outcome::Read(..) | Outcome::Unsupported(..) | Outcome::Rejected(..)
	) {
		warnings.clear();
	}
	(outcome, warnings)
}

fn observed(result: Result<Container<Fixture>, Error<u64>>) -> (Outcome, Vec<Warning>) {
	let (outcome, warnings) = match result {
		Ok(container) => (
			Outcome::Selected(
				container.descriptor(),
				container.superblock().object.transaction,
			),
			container.diagnostics().to_vec(),
		),
		Err(Error::NoCheckpoint { diagnostics }) => (Outcome::NoCheckpoint, diagnostics),
		Err(Error::CheckpointNotFound {
			transaction,
			diagnostics,
		}) => (Outcome::NotFound(transaction), diagnostics),
		Err(Error::CandidateCorruption(damage)) => (Outcome::Rejected(damage.into()), Vec::new()),
		Err(Error::Unsupported {
			descriptor,
			transaction,
			reason,
		}) => (
			Outcome::Unsupported(descriptor, transaction, reason),
			Vec::new(),
		),
		Err(Error::Read { offset, source }) => (Outcome::Read(offset, source), Vec::new()),
		Err(other) => panic!("unexpected checkpoint error: {other:?}"),
	};
	let warnings = warnings
		.into_iter()
		.map(|warning| match warning {
			Diagnostic::Rejected(damage) => Warning::Rejected(damage.into()),
			Diagnostic::NewerBootstrap {
				advertised,
				selected,
			} => Warning::NewerBootstrap(advertised, selected),
			other => panic!("unexpected checkpoint diagnostic: {other:?}"),
		})
		.collect();
	(outcome, warnings)
}

#[test]
fn wrapped_selection_matches_reference_model() {
	println!();
	for early in State::ALL {
		for latest in State::ALL {
			for at in [None, Some(EARLY), Some(LATEST)] {
				let mut fixture = Fixture::wrapped_descriptors();
				EARLY.set_state(&mut fixture, LATEST, early);
				LATEST.set_state(&mut fixture, EARLY, latest);
				let options = OpenOptions::default();
				let result = match at {
					Some(candidate) => Container::open_at(fixture, options, candidate.xid),
					None => Container::open(fixture, options),
				};
				assert_eq!(
					observed(result),
					expected(early, latest, at),
					"earlier={early:?}, latest={latest:?}, exact={:?}",
					at.map(|candidate| candidate.xid),
				);
				let request = at.map_or_else(
					|| "automatic".into(),
					|candidate| candidate.xid.0.to_string(),
				);
				println!("APFS checkpoint model {early:?} {latest:?} {request}");
			}
		}
	}
}
