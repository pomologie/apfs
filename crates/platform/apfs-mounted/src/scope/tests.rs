use std::{fs, io::Read, os::unix::fs::symlink};

use super::*;

#[test]
fn rejects_reserved_or_separated_names_and_preserves_components() {
	for name in [b"".as_slice(), b".", b"..", b"x/y", b"\0"] {
		assert_eq!(EntryName::new(name), Err(InvalidEntryName));
	}
	assert!(EntryName::new(&[b'x'; MAX_ENTRY_NAME_BYTES + 1]).is_err());
	let raw = b"z\\\xff";
	assert_eq!(EntryName::new(raw).unwrap().as_bytes(), raw);
}

#[test]
fn keeps_operations_relative_after_the_original_parent_is_renamed() {
	let temp = tempfile::tempdir().unwrap();
	let original = temp.path().join("original");
	let renamed = temp.path().join("renamed");
	fs::create_dir(&original).unwrap();
	let held = Directory::from_file(File::open(&original).unwrap()).unwrap();
	fs::write(original.join("Document"), b"held source").unwrap();
	fs::rename(&original, &renamed).unwrap();
	fs::create_dir(&original).unwrap();
	fs::write(original.join("Document"), b"different root").unwrap();
	let name = EntryName::new(b"Document").unwrap();
	let event = held.open_event(&name).unwrap();
	assert_eq!(stored_name(&event).unwrap(), name);
	assert_eq!(fstat(&event).unwrap().st_size, b"held source".len() as i64);
	let mut contents = Vec::new();
	held.open_file(&name)
		.unwrap()
		.read_to_end(&mut contents)
		.unwrap();
	assert_eq!(contents, b"held source");
}

#[test]
fn refuses_final_symlinks_and_existing_private_entries() {
	let temp = tempfile::tempdir().unwrap();
	let held = Directory::from_file(File::open(temp.path()).unwrap()).unwrap();
	let name = EntryName::new(b"private").unwrap();
	let directory = held.create_private_directory(&name).unwrap();
	assert_eq!(
		Mode::from_raw_mode(fstat(&directory).unwrap().st_mode),
		PRIVATE_DIRECTORY
	);
	assert!(matches!(
		held.create_private_directory(&name),
		Err(DirectoryCreateError::Existing)
	));
	symlink("private", temp.path().join("alias")).unwrap();
	let alias = EntryName::new(b"alias").unwrap();
	assert!(held.open_directory(&alias).is_err());
	assert!(held.open_file(&alias).is_err());
	assert!(held.open_event(&alias).is_err());
}
