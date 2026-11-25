use std::{
	cell::Cell,
	fs::{self, File, Permissions},
	io,
	os::unix::fs::{MetadataExt, PermissionsExt},
};

use crate::metadata::Timestamp;

use super::*;

const STAGE: &str = "stage";
const FORMER_STAGE: &str = "former-stage";
const OWNER_DIRECTORY_MODE: u32 = 0o700;
const POSIX_MODE_MASK: u32 = 0o7777;

struct Scratch(tempfile::TempDir);

impl Scratch {
	fn new() -> Self {
		let directory = tempfile::Builder::new()
			.permissions(Permissions::from_mode(OWNER_DIRECTORY_MODE))
			.tempdir()
			.unwrap();
		Self(directory)
	}

	fn directory(&self) -> Directory {
		Directory::from_file(File::open(self.0.path()).unwrap()).unwrap()
	}

	fn path(&self, name: &str) -> std::path::PathBuf {
		self.0.path().join(name)
	}
}

#[test]
fn writes_closes_reopens_and_applies_exact_metadata() {
	let scratch = Scratch::new();
	let directory = scratch.directory();
	let name = EntryName::new(STAGE.as_bytes()).unwrap();
	let payload = b"stage payload";
	let extent = payload.len() as u64;
	let mut writer = PrivateWriter::create(&directory, &name, extent).unwrap();
	let identity = *writer.identity();
	assert!(matches!(
		writer.write_next(b""),
		Err(WriterError::InvalidRange)
	));
	writer.write_next(&payload[..5]).unwrap();
	writer.write_next(&payload[5..]).unwrap();
	assert_eq!(writer.position(), extent);
	assert!(matches!(
		writer.write_next(b"extra"),
		Err(WriterError::InvalidRange)
	));
	let file = writer.flush_and_close().unwrap();
	assert_eq!(*file.identity(), identity);
	{
		let reader = file.open_read_back().unwrap();
		let mut observed = [0; b"stage payload".len()];
		assert!(matches!(
			reader.read_exact_at(extent, &mut [0]),
			Err(WriterError::InvalidRange)
		));
		reader.read_exact_at(0, &mut observed).unwrap();
		assert_eq!(&observed, payload);
		reader.revalidate().unwrap();
	}
	let times = AccessModificationTimes {
		access: Timestamp::new(1_700_000_000, 41).unwrap(),
		modification: Timestamp::new(1_700_000_001, 57).unwrap(),
	};
	let ready = file.apply_times(times).unwrap();
	let final_identity = *ready.identity();
	assert_eq!(final_identity.mount(), identity.mount());
	assert_eq!(final_identity.inode(), identity.inode());
	assert_eq!(final_identity.generation(), identity.generation());
	assert_eq!(
		final_identity.birth().seconds(),
		times.modification.seconds()
	);
	assert_eq!(
		i64::from(final_identity.birth().nanoseconds()),
		times.modification.nanoseconds()
	);
	assert_eq!(ready.times(), times);
	ready.revalidate().unwrap();
	let independent = fs::metadata(scratch.path(STAGE)).unwrap();
	assert_eq!(independent.atime(), times.access.seconds());
	assert_eq!(independent.atime_nsec(), times.access.nanoseconds());
	assert_eq!(independent.mtime(), times.modification.seconds());
	assert_eq!(independent.mtime_nsec(), times.modification.nanoseconds());
	assert_eq!(
		independent.mode() & POSIX_MODE_MASK,
		u32::from(observation::PRIVATE_MODE.bits())
	);
	sync_directory(&directory).unwrap();
}

#[test]
fn preserves_an_incumbent_and_refuses_a_rebound_name() {
	let scratch = Scratch::new();
	let directory = scratch.directory();
	let name = EntryName::new(STAGE.as_bytes()).unwrap();
	let stage = scratch.path(STAGE);
	let mut writer = PrivateWriter::create(&directory, &name, 1).unwrap();
	assert!(matches!(
		PrivateWriter::create(&directory, &name, 1),
		Err(WriterError::Occupied)
	));
	writer.write_next(b"a").unwrap();
	let closed = writer.flush_and_close().unwrap();
	let reader = closed.open_read_back().unwrap();
	fs::rename(&stage, scratch.path(FORMER_STAGE)).unwrap();
	fs::write(&stage, b"b").unwrap();
	assert!(reader.revalidate().is_err());
	assert!(closed.open_read_back().is_err());
	assert_eq!(fs::read(&stage).unwrap(), b"b");
	assert_eq!(fs::read(scratch.path(FORMER_STAGE)).unwrap(), b"a");
}

#[test]
fn retires_a_writer_on_uncertain_progress_and_bounds_eintr() {
	let scratch = Scratch::new();
	let directory = scratch.directory();
	let name = EntryName::new(STAGE.as_bytes()).unwrap();
	let mut writer = PrivateWriter::create(&directory, &name, 2).unwrap();
	let mut calls = 0;
	let result = writer.write_next_with(b"xy", |file, bytes, offset| {
		calls += 1;
		if calls == 1 {
			file.write_at(&bytes[..1], offset)
		} else {
			Err(io::ErrorKind::Interrupted.into())
		}
	});
	assert!(
		matches!(result, Err(WriterError::Write(error)) if error.kind() == io::ErrorKind::Interrupted)
	);
	assert_eq!(calls, MAX_WRITE_INTERRUPTS + 2);
	assert!(matches!(writer.write_next(b"y"), Err(WriterError::Retired)));
	assert_eq!(fs::read(scratch.path(STAGE)).unwrap(), b"x");
}

#[test]
fn propagates_checked_close_and_barrier_failures_without_removing_entries() {
	let scratch = Scratch::new();
	let directory = scratch.directory();
	let name = EntryName::new(STAGE.as_bytes()).unwrap();
	let writer = PrivateWriter::create(&directory, &name, 0).unwrap();
	let close_called = Cell::new(false);
	let barrier_failed = writer.finish_with(
		|_| {
			Err(BarrierError {
				kind: BarrierKind::FullFile,
				error: io::ErrorKind::Other.into(),
			})
		},
		|file| {
			close_called.set(true);
			drop(file);
			Ok(())
		},
	);
	assert!(matches!(
		barrier_failed,
		Err(WriterError::Barrier(BarrierError {
			kind: BarrierKind::FullFile,
			..
		}))
	));
	assert!(!close_called.get());
	assert!(scratch.path(STAGE).exists());
	let later_name = EntryName::new(FORMER_STAGE.as_bytes()).unwrap();
	let later_writer = PrivateWriter::create(&directory, &later_name, 0).unwrap();
	let close_failed = later_writer.finish_with(
		|_| Ok(()),
		|file| {
			drop(file);
			Err(WriterError::Close(io::ErrorKind::Other.into()))
		},
	);
	assert!(matches!(close_failed, Err(WriterError::Close(_))));
	assert!(scratch.path(FORMER_STAGE).exists());
}
