//! A-V02 decision oracle for two descriptor positions and three possible XIDs.

extern crate std;

use apfs_core::ByteOffset;
use apfs_format::checkpoint::Map;
use std::string::String;

use super::{
	BlockAddress, Candidate, Corruption, Damage, Diagnostic, Error, Mapping, Scan, Selected,
	Superblock, TransactionId, Unsupported, Vec, resolve_candidates,
};

const XIDS: [TransactionId; 3] = [TransactionId(1), TransactionId(2), TransactionId(3)];
const ADVERTISED: TransactionId = XIDS[2];
const POSITIONS: [BlockAddress; 2] = [BlockAddress(2), BlockAddress(4)];
const PAYLOAD_BLOCK_BASE: u64 = 9;
const DEVICE_BLOCK_BYTES: u32 = 4096;
const DEVICE_BYTES: u64 = 64 << 20;
const SUPERBLOCK: &[u8] = include_bytes!("../../tests/fixtures/native-block-4.bin");
const MAP: &[u8] = include_bytes!("../../tests/fixtures/native-block-3.bin");
const UNSUPPORTED_MAP: Unsupported = Unsupported::CheckpointMapFlags(1 << 31);
const OUTCOME_TRANSCRIPT: &str = "APFS_CHECKPOINT_DECISION_OUTCOMES";

type CandidateResult = Result<(Superblock, Vec<Mapping>), Error<BlockAddress>>;

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

#[derive(Clone, Copy, Debug)]
struct Slot {
	address: BlockAddress,
	xid: TransactionId,
	state: State,
}

impl Slot {
	fn damage(self) -> Damage {
		let (transaction, reason) = match self.state {
			State::TornDescriptor => (
				None,
				Corruption::Format(apfs_format::Error::InvalidChecksum),
			),
			State::BlankMap => (
				Some(self.xid),
				Corruption::Format(apfs_format::Error::InvalidChecksum),
			),
			State::MismatchedMap => (Some(self.xid), Corruption::Object),
			_ => unreachable!("only corrupt states have damage"),
		};
		Damage {
			descriptor: self.address,
			transaction,
			reason,
		}
	}

	fn unreadable_payload(self) -> (ByteOffset, BlockAddress) {
		let payload = BlockAddress(PAYLOAD_BLOCK_BASE + self.address.0);
		(
			ByteOffset(payload.0 * u64::from(DEVICE_BLOCK_BYTES)),
			payload,
		)
	}

	fn verify(self, superblock: &Superblock, mappings: &[Mapping]) -> CandidateResult {
		match self.state {
			State::Complete => {
				let mut accepted = superblock.clone();
				accepted.object.transaction = self.xid;
				Ok((accepted, mappings.to_vec()))
			}
			State::BlankMap | State::MismatchedMap => {
				Err(Error::CandidateCorruption(self.damage()))
			}
			State::UnsupportedMap => Err(Error::Unsupported {
				descriptor: self.address,
				transaction: self.xid,
				reason: UNSUPPORTED_MAP,
			}),
			State::UnreadablePayload => {
				let (offset, source) = self.unreadable_payload();
				Err(Error::Read { offset, source })
			}
			State::AbsentDescriptor | State::TornDescriptor => {
				unreachable!("unverified descriptor was tried")
			}
		}
	}
}

#[derive(Debug, Eq, PartialEq)]
enum Outcome {
	Selected(BlockAddress, TransactionId, Vec<Diagnostic>),
	Absent(Option<TransactionId>, Vec<Diagnostic>),
	Ambiguous(TransactionId),
	Corrupt(Damage),
	Unsupported(BlockAddress, TransactionId, Unsupported),
	Unreadable(ByteOffset, BlockAddress),
}

fn observe(result: Result<Selected, Error<BlockAddress>>, mappings: &[Mapping]) -> Outcome {
	match result {
		Ok(selected) => {
			assert_eq!(selected.mappings, mappings);
			Outcome::Selected(
				selected.descriptor,
				selected.selected.object.transaction,
				selected.diagnostics,
			)
		}
		Err(Error::NoCheckpoint { diagnostics }) => Outcome::Absent(None, diagnostics),
		Err(Error::CheckpointNotFound {
			transaction,
			diagnostics,
		}) => Outcome::Absent(Some(transaction), diagnostics),
		Err(Error::AmbiguousTransaction(xid)) => Outcome::Ambiguous(xid),
		Err(Error::CandidateCorruption(damage)) => Outcome::Corrupt(damage),
		Err(Error::Unsupported {
			descriptor,
			transaction,
			reason,
		}) => Outcome::Unsupported(descriptor, transaction, reason),
		Err(Error::Read { offset, source }) => Outcome::Unreadable(offset, source),
		Err(error) => panic!("unexpected checkpoint decision: {error:?}"),
	}
}

fn transaction_field(transaction: Option<TransactionId>) -> String {
	transaction.map_or_else(|| String::from("-"), |xid| std::format!("{}", xid.0))
}

fn damage_field(damage: &Damage) -> String {
	let reason = match damage.reason {
		Corruption::Format(apfs_format::Error::InvalidChecksum) => "invalid-checksum",
		Corruption::Object => "object",
		_ => panic!("unexpected typed decision damage: {damage:?}"),
	};
	std::format!(
		"{}:{}:{reason}",
		damage.descriptor.0,
		transaction_field(damage.transaction)
	)
}

fn fields(values: impl Iterator<Item = String>) -> String {
	let values: Vec<_> = values.collect();
	if values.is_empty() {
		String::from("-")
	} else {
		values.join(",")
	}
}

fn outcome_fields(outcome: &Outcome) -> (String, &[Diagnostic]) {
	match outcome {
		Outcome::Selected(address, xid, diagnostics) => (
			std::format!("selected {} {}", address.0, xid.0),
			diagnostics,
		),
		Outcome::Absent(request, diagnostics) => (
			std::format!("absent {}", transaction_field(*request)),
			diagnostics,
		),
		Outcome::Ambiguous(xid) => (std::format!("ambiguous {}", xid.0), &[]),
		Outcome::Corrupt(damage) => (std::format!("corrupt {}", damage_field(damage)), &[]),
		Outcome::Unsupported(address, xid, Unsupported::CheckpointMapFlags(flags)) => (
			std::format!(
				"unsupported {} {} checkpoint-map-flags {flags}",
				address.0,
				xid.0
			),
			&[],
		),
		Outcome::Unsupported(..) => panic!("unexpected typed decision outcome: {outcome:?}"),
		Outcome::Unreadable(offset, source) => {
			(std::format!("unreadable {} {}", offset.0, source.0), &[])
		}
	}
}

fn print_observation(case: &str, outcome: &Outcome, attempts: &[BlockAddress]) {
	let (result, diagnostics) = outcome_fields(outcome);
	let attempts = fields(attempts.iter().map(|address| std::format!("{}", address.0)));
	let diagnostics = fields(diagnostics.iter().map(|diagnostic| match diagnostic {
		Diagnostic::Rejected(damage) => std::format!("rejected:{}", damage_field(damage)),
		Diagnostic::NewerBootstrap {
			advertised,
			selected,
		} => std::format!("newer-bootstrap:{}:{}", advertised.0, selected.0),
	}));
	std::println!("APFS checkpoint outcome {case} | {result} | {attempts} | {diagnostics}");
}

fn expected(slots: [Slot; 2], request: Option<TransactionId>) -> (Outcome, Vec<BlockAddress>) {
	// Classify which XIDs would decide the outcome, then take the maximum.
	// Recovery attempts above that boundary are derived separately.
	let at_xid = |xid| {
		slots.into_iter().filter(move |slot| {
			slot.xid == xid
				&& request.is_none_or(|requested| requested == xid)
				&& !matches!(slot.state, State::AbsentDescriptor | State::TornDescriptor)
		})
	};
	let cannot_fall_back = |slot: Slot| {
		request.is_some() || !matches!(slot.state, State::BlankMap | State::MismatchedMap)
	};
	let decisive = XIDS
		.into_iter()
		.rev()
		.find(|&xid| at_xid(xid).count() > 1 || at_xid(xid).any(cannot_fall_back));
	let recoverable = XIDS
		.into_iter()
		.rev()
		.filter(|&xid| decisive.is_none_or(|cutoff| xid > cutoff))
		.flat_map(at_xid);
	let mut attempts: Vec<_> = recoverable.clone().map(|slot| slot.address).collect();
	let mut diagnostics: Vec<_> = slots
		.into_iter()
		.filter(|slot| slot.state == State::TornDescriptor)
		.chain(recoverable)
		.map(|slot| Diagnostic::Rejected(slot.damage()))
		.collect();

	let outcome = match decisive {
		None => Outcome::Absent(request, diagnostics),
		Some(xid) if at_xid(xid).count() > 1 => Outcome::Ambiguous(xid),
		Some(xid) => {
			let chosen = at_xid(xid).next().unwrap();
			attempts.push(chosen.address);
			match chosen.state {
				State::Complete => {
					if request.is_none() && xid < ADVERTISED {
						diagnostics.push(Diagnostic::NewerBootstrap {
							advertised: ADVERTISED,
							selected: xid,
						});
					}
					Outcome::Selected(chosen.address, xid, diagnostics)
				}
				State::BlankMap | State::MismatchedMap => Outcome::Corrupt(chosen.damage()),
				State::UnsupportedMap => Outcome::Unsupported(chosen.address, xid, UNSUPPORTED_MAP),
				State::UnreadablePayload => {
					let (offset, source) = chosen.unreadable_payload();
					Outcome::Unreadable(offset, source)
				}
				State::AbsentDescriptor | State::TornDescriptor => {
					unreachable!("unverified descriptor was decisive")
				}
			}
		}
	};
	(outcome, attempts)
}

#[test]
fn typed_checkpoint_decisions_match_a_decisive_xid_model() {
	let superblock = Superblock::decode(SUPERBLOCK, DEVICE_BYTES).unwrap();
	let mappings: Vec<_> = Map::decode(MAP, superblock.geometry)
		.unwrap()
		.mappings()
		.collect();
	let emit_outcomes = std::env::var_os(OUTCOME_TRANSCRIPT).is_some();
	std::println!();
	for first_xid in XIDS {
		for second_xid in XIDS {
			for first_state in State::ALL {
				for second_state in State::ALL {
					let slots = [
						Slot {
							address: POSITIONS[0],
							xid: first_xid,
							state: first_state,
						},
						Slot {
							address: POSITIONS[1],
							xid: second_xid,
							state: second_state,
						},
					];
					for request in core::iter::once(None).chain(XIDS.map(Some)) {
						let (outcome, attempts) =
							check_case(slots, request, &superblock, &mappings);
						let request = request.map_or_else(
							|| String::from("automatic"),
							|xid| std::format!("{}", xid.0),
						);
						let case = std::format!(
							"{} {first_state:?} {} {second_state:?} {request}",
							first_xid.0,
							second_xid.0
						);
						std::println!("APFS checkpoint decision {case}");
						if emit_outcomes {
							print_observation(&case, &outcome, &attempts);
						}
					}
				}
			}
		}
	}
}

fn check_case(
	slots: [Slot; 2],
	request: Option<TransactionId>,
	superblock: &Superblock,
	mappings: &[Mapping],
) -> (Outcome, Vec<BlockAddress>) {
	let mut scan = Scan {
		candidates: Vec::new(),
		diagnostics: Vec::new(),
	};
	for slot in slots {
		match slot.state {
			State::AbsentDescriptor => (),
			State::TornDescriptor => scan.diagnostics.push(Diagnostic::Rejected(slot.damage())),
			_ if request.is_none_or(|xid| xid == slot.xid) => scan.candidates.push(Candidate {
				address: slot.address,
				xid: slot.xid,
			}),
			_ => (),
		}
	}
	let mut attempts = Vec::new();
	let result = resolve_candidates(scan, ADVERTISED, request, |candidate| {
		attempts.push(candidate.address);
		let slot = slots
			.into_iter()
			.find(|slot| slot.address == candidate.address)
			.unwrap();
		assert_eq!(slot.xid, candidate.xid);
		slot.verify(superblock, mappings)
	});
	let actual = (observe(result, mappings), attempts);
	assert_eq!(
		actual,
		expected(slots, request),
		"{slots:?}, exact {request:?}"
	);
	actual
}
