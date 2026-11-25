use std::{fs, io, os::unix::fs::symlink, path::Path, process::Command};

use super::{
	MAX_INTERRUPTED_RETRIES, MAX_READ_BYTES, PinnedSource, SourceError, read_exact_loop,
	retry_interrupted,
};
use crate::{Directory, EntryName};

const NAME: &str = "source.bin";
const PAYLOAD: &[u8] = b"pinned read witness";

fn directory(path: &Path) -> Directory {
	Directory::from_file(fs::File::open(path).unwrap()).unwrap()
}

#[test]
fn exact_reads_stay_bound_after_the_original_root_path_moves() {
	let scratch = tempfile::tempdir().unwrap();
	let root_path = scratch.path().join("root");
	fs::create_dir(&root_path).unwrap();
	fs::write(root_path.join(NAME), PAYLOAD).unwrap();
	let root = directory(&root_path);
	let name = EntryName::new(NAME.as_bytes()).unwrap();
	let source = PinnedSource::open(&root, &name).unwrap();
	fs::rename(&root_path, scratch.path().join("moved")).unwrap();
	assert_eq!(source.len(), PAYLOAD.len() as u64);
	assert_eq!(source.metadata().length, PAYLOAD.len() as u64);
	let mut buffer = [0; PAYLOAD.len()];
	source.read_exact_at(0, &mut buffer).unwrap();
	assert_eq!(buffer, PAYLOAD);
	source.read_exact_at(source.len(), &mut []).unwrap();
	source.revalidate().unwrap();
	assert!(matches!(
		source.read_exact_at(source.len(), &mut [0]),
		Err(SourceError::Range { .. })
	));
	assert!(matches!(
		source.read_exact_at(0, &mut vec![0; MAX_READ_BYTES + 1]),
		Err(SourceError::RequestTooLarge { .. })
	));
}

#[test]
fn rejects_a_name_rebound_even_to_identical_bytes() {
	let scratch = tempfile::tempdir().unwrap();
	let path = scratch.path().join(NAME);
	fs::write(&path, PAYLOAD).unwrap();
	let root = directory(scratch.path());
	let name = EntryName::new(NAME.as_bytes()).unwrap();
	let source = PinnedSource::open(&root, &name).unwrap();
	fs::rename(&path, scratch.path().join("old.bin")).unwrap();
	fs::write(&path, PAYLOAD).unwrap();
	assert!(matches!(
		source.read_exact_at(0, &mut [0]),
		Err(SourceError::Changed)
	));
}

#[test]
fn detects_truncation_of_the_held_inode() {
	let scratch = tempfile::tempdir().unwrap();
	let path = scratch.path().join(NAME);
	fs::write(&path, PAYLOAD).unwrap();
	let root = directory(scratch.path());
	let name = EntryName::new(NAME.as_bytes()).unwrap();
	let source = PinnedSource::open(&root, &name).unwrap();
	fs::OpenOptions::new()
		.write(true)
		.open(path)
		.unwrap()
		.set_len(1)
		.unwrap();
	assert!(matches!(source.validate(), Err(SourceError::Changed)));
}

#[test]
fn refuses_missing_names_symlinks_and_fifos() {
	let scratch = tempfile::tempdir().unwrap();
	let path = scratch.path().join(NAME);
	let root = directory(scratch.path());
	let name = EntryName::new(NAME.as_bytes()).unwrap();
	assert!(matches!(
		PinnedSource::open(&root, &name),
		Err(SourceError::Missing)
	));
	let target = scratch.path().join("other.bin");
	fs::write(&target, PAYLOAD).unwrap();
	symlink(&target, &path).unwrap();
	assert!(matches!(
		PinnedSource::open(&root, &name),
		Err(SourceError::Unsupported)
	));
	fs::remove_file(&path).unwrap();
	assert!(
		Command::new("/usr/bin/mkfifo")
			.arg(&path)
			.status()
			.unwrap()
			.success()
	);
	assert!(matches!(
		PinnedSource::open(&root, &name),
		Err(SourceError::Unsupported)
	));
}

#[test]
fn positioned_loop_advances_on_short_progress_and_reports_eof() {
	let mut buffer = [0; 3];
	let mut positions = Vec::new();
	read_exact_loop(5, &mut buffer, |offset, unread| {
		positions.push(offset);
		unread[0] = b'a';
		Ok(1)
	})
	.unwrap();
	assert_eq!(positions, [5, 6, 7]);
	assert_eq!(buffer, *b"aaa");
	assert_eq!(
		read_exact_loop(0, &mut buffer, |_, _| Ok(0))
			.unwrap_err()
			.kind(),
		io::ErrorKind::UnexpectedEof
	);
}

#[test]
fn positioned_interruption_retries_are_bounded() {
	let mut attempts = 0;
	let failed = retry_interrupted(|| -> io::Result<()> {
		attempts += 1;
		Err(io::ErrorKind::Interrupted.into())
	});
	assert_eq!(failed.unwrap_err().kind(), io::ErrorKind::Interrupted);
	assert_eq!(attempts, MAX_INTERRUPTED_RETRIES + 1);
}
