use std::{cell::Cell, fs, fs::File, os::unix::fs::symlink, path::Path};

use crate::writer::BarrierKind;

use super::*;

const STAGE_NAME: &[u8] = b"stage";
const TARGET_NAME: &[u8] = b"target";
const STAGE_CONTENT: &[u8] = b"verified stage";
const INCUMBENT_CONTENT: &[u8] = b"keep incumbent";

struct Fixture {
	directory: tempfile::TempDir,
	source: Directory,
	destination: Directory,
	stage_name: EntryName,
	target_name: EntryName,
	held: File,
	identity: ObjectIdentity,
}

impl Fixture {
	fn new() -> Self {
		let directory = tempfile::tempdir().unwrap();
		let root = directory.path();
		fs::create_dir(root.join("source")).unwrap();
		fs::create_dir(root.join("destination")).unwrap();
		fs::write(root.join("source/stage"), STAGE_CONTENT).unwrap();
		let source = Directory::from_file(File::open(root.join("source")).unwrap()).unwrap();
		let destination =
			Directory::from_file(File::open(root.join("destination")).unwrap()).unwrap();
		let stage_name = EntryName::new(STAGE_NAME).unwrap();
		let target_name = EntryName::new(TARGET_NAME).unwrap();
		let held = source.open_file(&stage_name).unwrap();
		let identity = ObjectIdentity::held(&held).unwrap();
		Self {
			directory,
			source,
			destination,
			stage_name,
			target_name,
			held,
			identity,
		}
	}

	fn root(&self) -> &Path {
		self.directory.path()
	}

	fn rename(&self) -> RenameOutcome {
		exclusive_rename(
			&self.source,
			&self.stage_name,
			&self.destination,
			&self.target_name,
			&self.held,
			&self.identity,
		)
	}

	fn attempt(&self) -> RenameAttempt<'_> {
		attempt_exclusive_rename(
			&self.source,
			&self.stage_name,
			&self.destination,
			&self.target_name,
			&self.held,
			&self.identity,
		)
	}
}

#[test]
fn confirms_rename_of_the_held_inode_and_reports_both_barriers() {
	let fixture = Fixture::new();
	let anchor = pin_entry(&fixture.source, &fixture.stage_name)
		.unwrap()
		.unwrap();
	assert_eq!(anchor.identity(), &fixture.identity);
	assert!(
		pin_entry(&fixture.destination, &fixture.target_name)
			.unwrap()
			.is_none()
	);
	assert!(matches!(
		fixture.rename(),
		RenameOutcome::Renamed(RenameEvidence::Confirmed { target }) if target == fixture.identity
	));
	assert!(anchor.revalidate().is_err());
	let barriers = sync_directories(&fixture.source, &fixture.destination);
	barriers.source.unwrap();
	barriers.destination.unwrap();
	assert!(matches!(
		inventory(&fixture.source, &fixture.stage_name),
		EntryObservation::Absent
	));
	let anchor = pin_entry(&fixture.destination, &fixture.target_name)
		.unwrap()
		.unwrap();
	assert_eq!(anchor.identity(), &fixture.identity);
	anchor.revalidate().unwrap();
	assert_eq!(
		fs::read(fixture.root().join("destination/target")).unwrap(),
		STAGE_CONTENT
	);
}

#[test]
fn refuses_a_rebound_stage_name_before_rename() {
	let fixture = Fixture::new();
	let stage = fixture.root().join("source/stage");
	let former_stage = fixture.root().join("source/former");
	fs::rename(&stage, &former_stage).unwrap();
	fs::write(&stage, INCUMBENT_CONTENT).unwrap();
	assert!(matches!(
		fixture.rename(),
		RenameOutcome::NotAttempted(RenameRejection::SourceName(_))
	));
	assert!(matches!(
		fixture.attempt(),
		RenameAttempt::NotAttempted(RenameRejection::SourceName(_))
	));
	assert_eq!(fs::read(stage).unwrap(), INCUMBENT_CONTENT);
	assert_eq!(fs::read(former_stage).unwrap(), STAGE_CONTENT);
	assert!(matches!(
		inventory(&fixture.destination, &fixture.target_name),
		EntryObservation::Absent
	));
}

#[test]
fn occupied_public_names_and_case_aliases_are_conflicts() {
	let fixture = Fixture::new();
	let target = fixture.root().join("destination/target");
	fs::write(&target, INCUMBENT_CONTENT).unwrap();
	assert!(matches!(fixture.rename(), RenameOutcome::Conflict));
	assert!(matches!(fixture.attempt(), RenameAttempt::Conflict));
	assert_eq!(fs::read(&target).unwrap(), INCUMBENT_CONTENT);
	assert_eq!(
		fs::read(fixture.root().join("source/stage")).unwrap(),
		STAGE_CONTENT
	);

	let alias_path = fixture.root().join("destination/TARGET");
	let alias = EntryName::new(b"TARGET").unwrap();
	let case_alias_is_occupied = alias_path.try_exists().unwrap();
	let result = exclusive_rename(
		&fixture.source,
		&fixture.stage_name,
		&fixture.destination,
		&alias,
		&fixture.held,
		&fixture.identity,
	);
	if case_alias_is_occupied {
		assert!(matches!(result, RenameOutcome::Conflict));
		assert_eq!(
			fs::read(fixture.root().join("source/stage")).unwrap(),
			STAGE_CONTENT
		);
	} else {
		assert!(matches!(
			result,
			RenameOutcome::Renamed(RenameEvidence::Confirmed { .. })
		));
		assert_eq!(fs::read(alias_path).unwrap(), STAGE_CONTENT);
	}
	assert_eq!(fs::read(target).unwrap(), INCUMBENT_CONTENT);
}

#[test]
fn native_flags_refuse_a_late_symlink_without_touching_its_referent() {
	let fixture = Fixture::new();
	let target = fixture.root().join("destination/target");
	let referent = fixture.root().join("destination/referent");
	fs::write(&referent, INCUMBENT_CONTENT).unwrap();
	assert!(matches!(
		inventory(&fixture.destination, &fixture.target_name),
		EntryObservation::Absent
	));
	symlink("referent", &target).unwrap();

	let result = rename_native(
		&fixture.source,
		&fixture.stage_name,
		&fixture.destination,
		&fixture.target_name,
	);
	assert!(matches!(result, Err(Errno::LOOP | Errno::EXIST)));
	assert!(fs::symlink_metadata(target).unwrap().is_symlink());
	assert_eq!(fs::read(referent).unwrap(), INCUMBENT_CONTENT);
	assert_eq!(
		fs::read(fixture.root().join("source/stage")).unwrap(),
		STAGE_CONTENT
	);
}

#[test]
fn rename_status_preserves_uncertainty_and_incomplete_postconditions() {
	let fixture = Fixture::new();
	let conflict = classify_rename(Err(Errno::EXIST), || panic!("unexpected rename success"));
	assert!(matches!(conflict, RenameAttempt::Conflict));
	let uncertain = classify_rename(Err(Errno::IO), || panic!("unexpected rename success"));
	assert!(
		matches!(uncertain, RenameAttempt::Uncertain(error) if error.raw_os_error() == Some(libc::EIO))
	);

	let RenameAttempt::Renamed(renamed) = fixture.attempt() else {
		panic!("expected successful exclusive rename");
	};
	fs::write(fixture.root().join("source/stage"), INCUMBENT_CONTENT).unwrap();
	let barriers = sync_directories(&fixture.source, &fixture.destination);
	barriers.source.unwrap();
	barriers.destination.unwrap();
	let incomplete = renamed.observe();
	assert!(matches!(
		incomplete,
		RenameEvidence::Incomplete {
			held: Ok(()),
			former_source: EntryObservation::Present(identity),
			destination: EntryObservation::Present(target),
		} if identity != fixture.identity && target == fixture.identity
	));
}

#[test]
fn same_directory_promotion_uses_one_barrier_before_observing() {
	let fixture = Fixture::new();
	let attempt = attempt_exclusive_rename(
		&fixture.source,
		&fixture.stage_name,
		&fixture.source,
		&fixture.target_name,
		&fixture.held,
		&fixture.identity,
	);
	let RenameAttempt::Renamed(renamed) = attempt else {
		panic!("unexpected promotion outcome: {attempt:?}");
	};
	sync_directory(&fixture.source).unwrap();
	assert!(matches!(
		renamed.observe(),
		RenameEvidence::Confirmed { target } if target == fixture.identity
	));
}

#[test]
fn the_second_barrier_runs_even_when_the_first_fails() {
	let attempted = Cell::new(false);
	let result = sync_both(
		|| {
			Err(BarrierError {
				kind: BarrierKind::Directory,
				error: io::Error::from_raw_os_error(libc::EIO),
			})
		},
		|| {
			attempted.set(true);
			Ok(())
		},
	);
	assert!(attempted.get());
	assert!(result.source.is_err());
	assert!(result.destination.is_ok());
}
