#![cfg(target_os = "macos")]

use std::{
	cell::Cell,
	fs::{self, File, Permissions},
	os::unix::fs::PermissionsExt as _,
	path::Path,
};

use apfs_mounted::{
	Directory, EntryName,
	lease::{Lease, LeaseAttempt, LeaseMode},
	metadata::MAX_EXTENDED_SECURITY_BYTES,
	publication::pin_entry,
	recovery::ReopenedStage,
	source::{MAX_READ_BYTES, SourceError},
	volume::observe_mount,
};

const STAGE: &str = "stage";
const STAGE_ALIAS: &str = "STAGE";
const PAYLOAD: &[u8] = b"private stage after reopening";
const EXTENT: u64 = PAYLOAD.len() as u64;
const PRIVATE_MODE: u16 = 0o600;
const WRONG_MODE: u16 = 0o400;

fn directory(path: &Path) -> Directory {
	let dir = Directory::from_file(File::open(path).unwrap()).unwrap();
	assert!(observe_mount(&dir).unwrap().is_apfs());
	dir
}

fn exclusive(dir: &Directory) -> Lease {
	let LeaseAttempt::Acquired(lease) = Lease::try_acquire(dir, LeaseMode::Exclusive).unwrap()
	else {
		panic!("fixture directory is busy");
	};
	lease
}

fn set_mode(path: &Path, mode: u16) {
	fs::set_permissions(path, Permissions::from_mode(u32::from(mode))).unwrap();
}

#[test]
fn reopens_stage_from_fresh_observations_and_reads_exactly() {
	let scratch = tempfile::tempdir().unwrap();
	let path = scratch.path().join(STAGE);
	fs::write(&path, PAYLOAD).unwrap();
	set_mode(&path, PRIVATE_MODE);
	let name = EntryName::new(STAGE.as_bytes()).unwrap();
	let expected = {
		let original = directory(scratch.path());
		*pin_entry(&original, &name).unwrap().unwrap().identity()
	};
	let fresh = directory(scratch.path());
	let lease = exclusive(&fresh);
	let anchor = pin_entry(&fresh, &name).unwrap().unwrap();
	let reader = ReopenedStage::open(&anchor, &lease, EXTENT, |candidate| {
		let named = candidate.metadata();
		assert_eq!(*candidate.identity(), expected);
		assert_eq!(named.owner, rustix::process::geteuid().as_raw());
		assert_eq!(named.flags, 0);
		assert_eq!(named.mode, PRIVATE_MODE);
		let acl = candidate
			.extended_security(MAX_EXTENDED_SECURITY_BYTES)
			.map_err(SourceError::Metadata)?;
		assert!(acl.has_no_acl_entries());
		Ok(())
	})
	.unwrap();
	let initial = reader.initial_metadata();
	assert_eq!(initial.length, EXTENT);
	let mut buffer = [0; PAYLOAD.len()];
	reader.read_exact_at(0, &mut buffer).unwrap();
	assert_eq!(buffer, PAYLOAD);
	assert!(matches!(
		reader.read_exact_at(EXTENT, &mut [0]),
		Err(SourceError::Range { .. })
	));
	assert!(matches!(
		reader.read_exact_at(0, &mut vec![0; MAX_READ_BYTES + 1]),
		Err(SourceError::RequestTooLarge { .. })
	));
	reader.confirm_eof().unwrap();
	let after = reader.with_metadata(|view| view.stat()).unwrap();
	assert_eq!(after.length, EXTENT);
	assert_eq!(after.times.modification.seconds(), initial.modified.seconds);
	assert_eq!(
		after.times.modification.nanoseconds(),
		i64::from(initial.modified.nanoseconds)
	);
}

#[test]
fn owned_reader_outlives_its_constructor_and_revalidates_its_name() {
	let scratch = tempfile::tempdir().unwrap();
	let path = scratch.path().join(STAGE);
	fs::write(&path, PAYLOAD).unwrap();
	set_mode(&path, PRIVATE_MODE);
	let dir = directory(scratch.path());
	let lease = exclusive(&dir);
	let reader = {
		let name = EntryName::new(STAGE.as_bytes()).unwrap();
		ReopenedStage::open_named(&dir, name, &lease, EXTENT, |candidate| {
			assert_eq!(candidate.metadata().mode, PRIVATE_MODE);
			let acl = candidate
				.extended_security(MAX_EXTENDED_SECURITY_BYTES)
				.map_err(SourceError::Metadata)?;
			assert!(acl.has_no_acl_entries());
			Ok(())
		})
		.unwrap()
	};
	let mut buffer = [0; PAYLOAD.len()];
	reader.read_exact_at(0, &mut buffer).unwrap();
	assert_eq!(buffer, PAYLOAD);
	reader.confirm_eof().unwrap();
	assert_eq!(
		reader.with_metadata(|view| view.stat()).unwrap().length,
		EXTENT
	);
	let (snapshot, extended) = reader
		.with_observation(|snapshot, view| {
			assert_eq!(snapshot.metadata, view.stat()?);
			view.extended_security(MAX_EXTENDED_SECURITY_BYTES)
		})
		.unwrap();
	assert_eq!(snapshot.extent(), EXTENT);
	assert!(extended.has_no_acl_entries());
	fs::rename(&path, scratch.path().join("renamed")).unwrap();
	fs::write(&path, PAYLOAD).unwrap();
	assert!(matches!(reader.confirm_eof(), Err(SourceError::Changed)));
	assert!(matches!(
		reader.with_metadata(|view| view.stat()),
		Err(SourceError::Changed)
	));
	assert!(matches!(
		reader.with_observation::<()>(|_, _| panic!("replaced inode reached observation")),
		Err(SourceError::Changed)
	));
}

#[test]
fn owned_reader_rejects_metadata_changed_during_a_coherent_observation() {
	let scratch = tempfile::tempdir().unwrap();
	let path = scratch.path().join(STAGE);
	fs::write(&path, PAYLOAD).unwrap();
	set_mode(&path, PRIVATE_MODE);
	let dir = directory(scratch.path());
	let lease = exclusive(&dir);
	let name = EntryName::new(STAGE.as_bytes()).unwrap();
	let reader = ReopenedStage::open_named(&dir, name, &lease, EXTENT, |_| Ok(())).unwrap();
	assert!(matches!(
		reader.with_observation(|_, _| {
			set_mode(&path, WRONG_MODE);
			Ok(())
		}),
		Err(SourceError::Changed)
	));
}

#[test]
fn owned_reader_distinguishes_missing_name_wrong_lease_and_lookup_alias() {
	let scratch = tempfile::tempdir().unwrap();
	let dir = directory(scratch.path());
	let lease = exclusive(&dir);
	let stage_name = || EntryName::new(STAGE.as_bytes()).unwrap();
	assert!(matches!(
		ReopenedStage::open_named(&dir, stage_name(), &lease, EXTENT, |_| panic!(
			"absent name reached admission"
		)),
		Err(SourceError::Missing)
	));
	let other = tempfile::tempdir().unwrap();
	let wrong_lease = exclusive(&directory(other.path()));
	assert!(matches!(
		ReopenedStage::open_named(&dir, stage_name(), &wrong_lease, EXTENT, |_| panic!(
			"wrong lease reached admission"
		)),
		Err(SourceError::LeaseMismatch)
	));
	fs::write(scratch.path().join(STAGE), PAYLOAD).unwrap();
	let alias = EntryName::new(STAGE_ALIAS.as_bytes()).unwrap();
	let result = ReopenedStage::open_named(&dir, alias, &lease, EXTENT, |_| {
		panic!("spelling alias reached admission")
	});
	if scratch.path().join(STAGE_ALIAS).try_exists().unwrap() {
		assert!(matches!(result, Err(SourceError::Changed)));
	} else {
		assert!(matches!(result, Err(SourceError::Missing)));
	}
}

#[test]
fn refuses_wrong_lease_extent_and_policy_before_readable_admission() {
	let scratch = tempfile::tempdir().unwrap();
	let path = scratch.path().join(STAGE);
	fs::write(&path, PAYLOAD).unwrap();
	set_mode(&path, WRONG_MODE);
	let here = directory(scratch.path());
	let lease = exclusive(&here);
	let other = tempfile::tempdir().unwrap();
	let wrong_lease = exclusive(&directory(other.path()));
	let name = EntryName::new(STAGE.as_bytes()).unwrap();
	let anchor = pin_entry(&here, &name).unwrap().unwrap();
	assert!(matches!(
		ReopenedStage::open(&anchor, &wrong_lease, EXTENT, |_| panic!(
			"wrong lease reached admission"
		)),
		Err(SourceError::LeaseMismatch)
	));
	assert!(matches!(
		ReopenedStage::open(&anchor, &lease, EXTENT + 1, |_| panic!(
			"wrong extent reached admission"
		)),
		Err(SourceError::Changed)
	));
	let admitted = Cell::new(false);
	assert!(matches!(
		ReopenedStage::open(&anchor, &lease, EXTENT, |candidate| {
			let observed = candidate.metadata();
			admitted.set(true);
			assert_eq!(observed.mode, WRONG_MODE);
			Err(SourceError::AdmissionRefused)
		}),
		Err(SourceError::AdmissionRefused)
	));
	assert!(admitted.get());
	fs::hard_link(&path, scratch.path().join("second-link")).unwrap();
	assert!(matches!(
		ReopenedStage::open(&anchor, &lease, EXTENT, |_| panic!(
			"multiply linked stage reached admission"
		)),
		Err(SourceError::Unsupported)
	));
}

#[test]
fn refuses_a_lookup_that_does_not_match_stored_spelling() {
	let scratch = tempfile::tempdir().unwrap();
	fs::write(scratch.path().join(STAGE), PAYLOAD).unwrap();
	let dir = directory(scratch.path());
	let lease = exclusive(&dir);
	let alias = EntryName::new(STAGE_ALIAS.as_bytes()).unwrap();
	let observed = pin_entry(&dir, &alias).unwrap();
	if scratch.path().join(STAGE_ALIAS).try_exists().unwrap() {
		let anchor = observed.expect("the case-insensitive lookup must resolve");
		assert!(matches!(
			ReopenedStage::open(&anchor, &lease, EXTENT, |_| panic!(
				"spelling alias reached admission"
			)),
			Err(SourceError::Changed)
		));
	} else {
		assert!(observed.is_none());
	}
}

#[test]
fn rejects_changes_after_admission_and_after_readable_open() {
	let scratch = tempfile::tempdir().unwrap();
	let path = scratch.path().join(STAGE);
	fs::write(&path, PAYLOAD).unwrap();
	set_mode(&path, PRIVATE_MODE);
	let dir = directory(scratch.path());
	let lease = exclusive(&dir);
	let name = EntryName::new(STAGE.as_bytes()).unwrap();
	let anchor = pin_entry(&dir, &name).unwrap().unwrap();
	assert!(matches!(
		ReopenedStage::open(&anchor, &lease, EXTENT, |_| {
			set_mode(&path, WRONG_MODE);
			Ok(())
		}),
		Err(SourceError::Changed)
	));
	set_mode(&path, PRIVATE_MODE);
	let reader = ReopenedStage::open(&anchor, &lease, EXTENT, |_| Ok(())).unwrap();
	fs::rename(&path, scratch.path().join("renamed")).unwrap();
	fs::write(&path, PAYLOAD).unwrap();
	assert!(matches!(reader.confirm_eof(), Err(SourceError::Changed)));
	assert!(matches!(
		reader.read_exact_at(0, &mut [0]),
		Err(SourceError::Changed)
	));
	assert!(matches!(
		ReopenedStage::open(&anchor, &lease, EXTENT, |_| panic!(
			"substituted inode reached admission"
		)),
		Err(SourceError::Changed)
	));
}
