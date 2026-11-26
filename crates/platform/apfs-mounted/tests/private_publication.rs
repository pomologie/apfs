#![cfg(target_os = "macos")]

use std::{fs, fs::File, os::unix::fs::PermissionsExt};

use apfs_mounted::{
	Directory, EntryName,
	lease::{Lease, LeaseAttempt, LeaseMode},
	metadata::{self, AccessModificationTimes, MAX_EXTENDED_SECURITY_BYTES, Timestamp},
	publication::{
		EntryObservation, EntrySnapshotError, EntrySpelling, RenameAttempt, RenameEvidence,
		attempt_exclusive_rename, inventory, pin_entry, sync_directories,
	},
	source::{PinnedSource, SourceError},
	writer::{BirthTimePolicy, InitialFlags, MetadataCheckPhase, PrivateWriter, WriterError},
};

const PAYLOAD: &[u8] = b"descriptor-scoped test payload";
const PRIVATE_MODE: u32 = 0o600;
const READ_ONLY_MODE: u32 = 0o400;
const PUBLIC_NAME: &str = "published";
const PRIVATE_DIRECTORY_NAME: &str = "stage";
const PRIVATE_PAYLOAD_NAME: &str = "payload";
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
		.create_private_directory(&EntryName::new(PRIVATE_DIRECTORY_NAME.as_bytes()).unwrap())
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
	let private_name = EntryName::new(PRIVATE_PAYLOAD_NAME.as_bytes()).unwrap();
	let public_name = EntryName::new(PUBLIC_NAME.as_bytes()).unwrap();
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
	let (snapshot, no_acl) = renamed
		.with_observation(EntrySpelling::Lookup, |observed, view| {
			assert_eq!(observed.metadata, view.stat()?);
			Ok(view
				.extended_security(MAX_EXTENDED_SECURITY_BYTES)?
				.has_no_acl_entries())
		})
		.unwrap();
	assert_eq!(snapshot.identity, target);
	assert_eq!(snapshot.extent(), PAYLOAD.len() as u64);
	assert_eq!(snapshot.change_stamp(), snapshot.metadata.change);
	assert!(no_acl);
	let former_source = scratch
		.path()
		.join(PRIVATE_DIRECTORY_NAME)
		.join(PRIVATE_PAYLOAD_NAME);
	assert!(matches!(
		renamed.with_observation(EntrySpelling::Lookup, |_, _| {
			fs::write(&former_source, []).unwrap();
			Ok(())
		}),
		Err(EntrySnapshotError::FormerSourcePresent)
	));
	fs::remove_file(&former_source).unwrap();
	assert!(matches!(
		inventory(&stage, &private_name),
		EntryObservation::Absent
	));
	let published_times = ready
		.with_held_metadata(|view| {
			assert!(
				view.extended_security(MAX_EXTENDED_SECURITY_BYTES)?
					.has_no_acl_entries()
			);
			Ok(view.stat()?.times)
		})
		.unwrap();
	assert_eq!(published_times, final_times);
	assert!(matches!(
		renamed.observe(),
		RenameEvidence::Confirmed { .. }
	));
	assert!(matches!(
		ready.with_held_metadata(|_| {
			fs::set_permissions(
				scratch.path().join(PUBLIC_NAME),
				fs::Permissions::from_mode(READ_ONLY_MODE),
			)
			.unwrap();
			Ok(())
		}),
		Err(WriterError::NotPrivate)
	));
	assert!(matches!(
		ready.with_held_metadata::<()>(|_| panic!("changed file reached metadata query")),
		Err(WriterError::NotPrivate)
	));
	let published = PinnedSource::open(&root, &public_name).unwrap();
	published.read_exact_at(0, &mut verified).unwrap();
	assert_eq!(verified, PAYLOAD);
	source.validate().unwrap();
	lease.release().unwrap();
	root_lease.release().unwrap();
}

#[test]
fn event_observation_reports_one_binding_and_rejects_metadata_changes() {
	let scratch = tempfile::tempdir().unwrap();
	let path = scratch.path().join(PUBLIC_NAME);
	fs::write(&path, PAYLOAD).unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_MODE)).unwrap();
	let directory = Directory::from_file(File::open(scratch.path()).unwrap()).unwrap();
	let name = EntryName::new(PUBLIC_NAME.as_bytes()).unwrap();
	let entry = pin_entry(&directory, &name).unwrap().unwrap();
	let (snapshot, stat) = entry
		.with_observation(EntrySpelling::Exact, |_, view| view.stat())
		.unwrap();
	assert_eq!(snapshot.identity, *entry.identity());
	assert_eq!(snapshot.metadata, stat);
	assert_eq!(snapshot.extent(), PAYLOAD.len() as u64);
	let alias = EntryName::new(PUBLIC_NAME.to_ascii_uppercase().as_bytes()).unwrap();
	if let Some(alias) = pin_entry(&directory, &alias).unwrap() {
		let (lookup, ()) = alias
			.with_observation(EntrySpelling::Lookup, |_, _| Ok(()))
			.unwrap();
		assert_eq!(lookup, snapshot);
		assert!(matches!(
			alias.with_observation::<()>(EntrySpelling::Exact, |_, _| panic!(
				"wrong spelling reached metadata queries"
			)),
			Err(EntrySnapshotError::SpellingMismatch)
		));
	}
	assert!(matches!(
		entry.with_observation(EntrySpelling::Exact, |_, _| {
			fs::set_permissions(&path, fs::Permissions::from_mode(READ_ONLY_MODE)).unwrap();
			Ok(())
		}),
		Err(EntrySnapshotError::Changed)
	));
	fs::remove_file(&path).unwrap();
	assert!(matches!(
		entry.with_observation::<()>(EntrySpelling::Exact, |_, _| panic!(
			"unbound entry reached metadata queries"
		)),
		Err(EntrySnapshotError::Changed)
	));
}
