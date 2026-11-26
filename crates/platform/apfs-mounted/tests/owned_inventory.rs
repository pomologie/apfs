#![cfg(target_os = "macos")]

use std::{fs, fs::File, os::unix::fs::symlink};

use apfs_mounted::{
	Directory, EntryName,
	identity::IdentityError,
	publication::{EntrySnapshotError, EntrySpelling, OwnedEventEntry},
};

const ENTRY: &str = "receipt";
const ORIGINAL: &str = "original";
const MOVED: &str = "moved";
const PAYLOAD: &[u8] = b"private inventory sample";
const OTHER_PAYLOAD: &[u8] = b"different inode";

#[test]
fn refuses_to_anchor_a_symlink_without_reporting_absence() {
	let scratch = tempfile::tempdir().unwrap();
	fs::write(scratch.path().join(ORIGINAL), PAYLOAD).unwrap();
	symlink(ORIGINAL, scratch.path().join(ENTRY)).unwrap();
	let directory = Directory::from_file(File::open(scratch.path()).unwrap()).unwrap();
	let name = EntryName::new(ENTRY.as_bytes()).unwrap();
	assert!(OwnedEventEntry::open_named(&directory, name).is_err());
}

#[test]
fn owns_the_component_and_directory_and_survives_replacement_of_the_original_path() {
	let scratch = tempfile::tempdir().unwrap();
	let original = scratch.path().join(ORIGINAL);
	let moved = scratch.path().join(MOVED);
	fs::create_dir(&original).unwrap();
	fs::write(original.join(ENTRY), PAYLOAD).unwrap();
	let entry = {
		let directory = Directory::from_file(File::open(&original).unwrap()).unwrap();
		let name = EntryName::new(ENTRY.as_bytes()).unwrap();
		OwnedEventEntry::open_named(&directory, name)
			.unwrap()
			.unwrap()
	};
	assert_eq!(entry.name().as_bytes(), ENTRY.as_bytes());

	fs::rename(&original, &moved).unwrap();
	fs::create_dir(&original).unwrap();
	fs::write(original.join(ENTRY), OTHER_PAYLOAD).unwrap();
	entry.revalidate().unwrap();
	let (snapshot, stat) = entry
		.with_observation(EntrySpelling::Exact, |_, view| view.stat())
		.unwrap();
	assert_eq!(snapshot.identity, *entry.identity());
	assert_eq!(snapshot.metadata, stat);
	assert_eq!(snapshot.extent(), PAYLOAD.len() as u64);
}

#[test]
fn distinguishes_absence_and_rejects_a_name_rebound_during_observation() {
	let scratch = tempfile::tempdir().unwrap();
	let path = scratch.path().join(ENTRY);
	let directory = Directory::from_file(File::open(scratch.path()).unwrap()).unwrap();
	let open =
		|| OwnedEventEntry::open_named(&directory, EntryName::new(ENTRY.as_bytes()).unwrap());
	assert!(open().unwrap().is_none());
	fs::write(&path, PAYLOAD).unwrap();
	let entry = open().unwrap().unwrap();
	let observed = entry.with_observation(EntrySpelling::Exact, |_, _| {
		fs::rename(&path, scratch.path().join(MOVED)).unwrap();
		fs::write(&path, OTHER_PAYLOAD).unwrap();
		Ok(())
	});
	assert!(matches!(observed, Err(EntrySnapshotError::Changed)));
	assert!(matches!(entry.revalidate(), Err(IdentityError::Changed)));
	assert_ne!(open().unwrap().unwrap().identity(), entry.identity());
}
