#![cfg(target_os = "macos")]

use std::{fs, fs::File, os::unix::fs::PermissionsExt};

use apfs_mounted::{
	Directory, EntryName,
	lease::{Lease, LeaseAttempt, LeaseMode},
	metadata::{self, AccessModificationTimes, Timestamp},
	publication::{
		EntryObservation, RenameAttempt, RenameEvidence, attempt_exclusive_rename, inventory,
		sync_directories,
	},
	source::{PinnedSource, SourceError},
	writer::{BirthTimePolicy, InitialFlags, MetadataCheckPhase, PrivateWriter, WriterError},
};

const PAYLOAD: &[u8] = b"descriptor-scoped test payload";
const PRIVATE_MODE: u32 = 0o600;
const EARLY_UNIX_SECONDS: i64 = 1_700_000_000;
const FINAL_TIME_NANOS: i64 = 42;

#[test]
fn holds_a_private_verified_file_through_exclusive_publication() {
	let scratch = tempfile::tempdir().unwrap();
	let source_path = scratch.path().join("source");
	fs::write(&source_path, PAYLOAD).unwrap();
	fs::set_permissions(&source_path, fs::Permissions::from_mode(PRIVATE_MODE)).unwrap();
	let root = Directory::from_file(File::open(scratch.path()).unwrap()).unwrap();
	let LeaseAttempt::Acquired(root_lease) =
		Lease::try_acquire(&root, LeaseMode::Exclusive).unwrap()
	else {
		panic!("fixture root was already locked");
	};
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
	let source = PinnedSource::open_leased(&root, &source_name, &root_lease, |_, observed| {
		let flags = observed.object_flags();
		if u32::from(observed.mode) != PRIVATE_MODE
			|| observed.owner != rustix::process::geteuid().as_raw()
			|| observed.link_count != 1
			|| flags.is_dataless()
			|| flags.is_firmlink()
		{
			return Err(SourceError::AdmissionRefused);
		}
		Ok(())
	})
	.unwrap();
	let metadata = source.with_metadata(|view| view.stat()).unwrap();
	assert_eq!(metadata.length, PAYLOAD.len() as u64);
	let private_name = EntryName::new(b"payload").unwrap();
	let public_name = EntryName::new(b"published").unwrap();
	let mut copy = [0; PAYLOAD.len()];
	source.read_exact_at(0, &mut copy).unwrap();
	source.revalidate().unwrap();
	let mut writer = PrivateWriter::create_with_initial_flags(
		&stage,
		&private_name,
		copy.len() as u64,
		InitialFlags::RequireZero,
	)
	.unwrap();
	writer.write_next(&copy).unwrap();
	let closed = writer.flush_and_close().unwrap();
	let mut verified = [0; PAYLOAD.len()];
	let reader = closed.open_read_back().unwrap();
	reader.read_exact_at(0, &mut verified).unwrap();
	reader.revalidate().unwrap();
	assert_eq!(verified, copy);
	let before = reader.with_metadata(|view| view.stat()).unwrap();
	let final_time = Timestamp::new(EARLY_UNIX_SECONDS, FINAL_TIME_NANOS).unwrap();
	let final_times = AccessModificationTimes {
		access: final_time,
		modification: before.times.modification,
	};
	let mut phases = Vec::new();
	let ready = closed
		.apply_times_checked(final_times, BirthTimePolicy::Preserve, |phase, view| {
			lease
				.revalidate()
				.map_err(|error| WriterError::MetadataRefused(Box::new(error)))?;
			let observed = view.stat()?;
			assert_eq!(observed.birth, before.birth);
			if phase != MetadataCheckPhase::BeforeUpdate {
				assert_eq!(observed.times, final_times);
			}
			phases.push(phase);
			Ok(())
		})
		.unwrap();
	assert_eq!(
		phases,
		[
			MetadataCheckPhase::BeforeUpdate,
			MetadataCheckPhase::AfterUpdate,
			MetadataCheckPhase::AfterBarrier,
		]
	);
	ready.revalidate().unwrap();
	lease.revalidate().unwrap();
	assert_eq!(
		metadata::stat(ready.event_handle()).unwrap().times,
		final_times
	);

	let attempt = attempt_exclusive_rename(
		&stage,
		&private_name,
		&root,
		&public_name,
		ready.event_handle(),
		ready.identity(),
	);
	let RenameAttempt::Renamed(renamed) = attempt else {
		panic!("unexpected rename outcome: {attempt:?}");
	};
	let barriers = sync_directories(&stage, &root);
	barriers.source.unwrap();
	barriers.destination.unwrap();
	let evidence = renamed.observe();
	let RenameEvidence::Confirmed { target } = evidence else {
		panic!("unexpected rename evidence: {evidence:?}");
	};
	assert_eq!(&target, ready.identity());
	assert!(matches!(
		inventory(&stage, &private_name),
		EntryObservation::Absent
	));
	let published = PinnedSource::open(&root, &public_name).unwrap();
	published.read_exact_at(0, &mut verified).unwrap();
	assert_eq!(verified, PAYLOAD);
	source.validate().unwrap();
	lease.release().unwrap();
	root_lease.release().unwrap();
}
