#![cfg(target_os = "macos")]

use std::{fs, fs::File};

use apfs_mounted::{
	Directory, EntryName,
	lease::{Lease, LeaseAttempt, LeaseMode},
	metadata::{self, AccessModificationTimes, Timestamp},
	publication::{
		EntryObservation, RenameEvidence, RenameOutcome, exclusive_rename, inventory,
		sync_directories,
	},
	source::PinnedSource,
	writer::PrivateWriter,
};

const PAYLOAD: &[u8] = b"descriptor-scoped test payload";
const EARLY_UNIX_SECONDS: i64 = 1_700_000_000;
const FINAL_TIME_NANOS: i64 = 42;

#[test]
fn holds_a_private_verified_file_through_exclusive_publication() {
	let scratch = tempfile::tempdir().unwrap();
	fs::write(scratch.path().join("source"), PAYLOAD).unwrap();
	let root = Directory::from_file(File::open(scratch.path()).unwrap()).unwrap();
	let stage = root
		.create_private_directory(&EntryName::new(b"stage").unwrap())
		.unwrap();
	assert!(
		metadata::set_empty_acl_on_fresh_directory(&stage)
			.unwrap()
			.has_no_acl_entries()
	);
	let LeaseAttempt::Acquired(lease) = Lease::try_acquire(&stage, LeaseMode::Exclusive).unwrap()
	else {
		panic!("private fixture directory was already locked");
	};

	let source_name = EntryName::new(b"source").unwrap();
	let source = PinnedSource::open(&root, &source_name).unwrap();
	let private_name = EntryName::new(b"payload").unwrap();
	let public_name = EntryName::new(b"published").unwrap();
	let mut copy = [0; PAYLOAD.len()];
	source.read_exact_at(0, &mut copy).unwrap();
	let mut writer = PrivateWriter::create(&stage, &private_name, copy.len() as u64).unwrap();
	writer.write_next(&copy).unwrap();
	let closed = writer.flush_and_close().unwrap();
	let mut verified = [0; PAYLOAD.len()];
	closed
		.open_read_back()
		.unwrap()
		.read_exact_at(0, &mut verified)
		.unwrap();
	assert_eq!(verified, copy);
	let final_time = Timestamp::new(EARLY_UNIX_SECONDS, FINAL_TIME_NANOS).unwrap();
	let final_times = AccessModificationTimes {
		access: final_time,
		modification: final_time,
	};
	let ready = closed.apply_times(final_times).unwrap();
	ready.revalidate().unwrap();
	lease.revalidate().unwrap();
	assert_eq!(
		metadata::stat(ready.event_handle()).unwrap().times,
		final_times
	);

	let evidence = exclusive_rename(
		&stage,
		&private_name,
		&root,
		&public_name,
		ready.event_handle(),
		ready.identity(),
	);
	let RenameOutcome::Renamed(RenameEvidence::Confirmed { target }) = evidence else {
		panic!("unexpected rename evidence: {evidence:?}");
	};
	assert_eq!(&target, ready.identity());
	let barriers = sync_directories(&stage, &root);
	barriers.source.unwrap();
	barriers.destination.unwrap();
	assert!(matches!(
		inventory(&stage, &private_name),
		EntryObservation::Absent
	));
	let published = PinnedSource::open(&root, &public_name).unwrap();
	published.read_exact_at(0, &mut verified).unwrap();
	assert_eq!(verified, PAYLOAD);
	source.validate().unwrap();
	lease.release().unwrap();
}
