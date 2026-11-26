use std::{
	cell::{Cell, RefCell},
	fs::{self, File, Permissions},
	io,
	os::unix::fs::{MetadataExt, PermissionsExt},
};

use crate::{
	Directory, EntryName,
	metadata::{MAX_EXTENDED_SECURITY_BYTES, Timestamp, XattrVisibility},
};

use super::*;

const STAGE: &str = "stage";
const FORMER_STAGE: &str = "former-stage";
const OWNER_DIRECTORY_MODE: u32 = 0o700;
const POSIX_MODE_MASK: u32 = 0o7777;
const SAMPLE_XATTR_BUDGET: usize = 4096;
const METADATA_REFUSAL: &str = "fixture refused metadata";

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
fn strict_writer_keeps_identity_and_exposes_bounded_held_metadata() {
	let scratch = Scratch::new();
	let directory = scratch.directory();
	let name = EntryName::new(STAGE.as_bytes()).unwrap();
	let mut writer =
		PrivateWriter::create_with_initial_flags(&directory, &name, 1, InitialFlags::RequireZero)
			.unwrap();
	let identity = *writer.identity();
	let metadata = writer.with_metadata(|view| view.stat()).unwrap();
	assert_eq!(metadata.length, 0);
	assert_eq!(metadata.object_flags().raw(), 0);
	writer.write_next(b"a").unwrap();

	let closed = writer.flush_and_close().unwrap();
	let before = closed.with_metadata(|view| view.stat()).unwrap();
	assert_eq!(before.length, 1);
	let reader = closed.open_read_back().unwrap();
	let (acl, fork, names, compression_names) = reader
		.with_metadata(|view| {
			Ok((
				view.extended_security(MAX_EXTENDED_SECURITY_BYTES)?,
				view.resource_fork()?,
				view.list_xattrs(XattrVisibility::Visible, SAMPLE_XATTR_BUDGET)?,
				view.list_xattrs(XattrVisibility::IncludingCompression, SAMPLE_XATTR_BUDGET)?,
			))
		})
		.unwrap();
	assert!(acl.has_no_acl_entries());
	assert!(fork.confirmed_absent());
	assert!(names.iter().all(|name| compression_names.contains(name)));
	let mut output = [0];
	reader.read_exact_at(0, &mut output).unwrap();
	reader.revalidate().unwrap();
	assert_eq!(&output, b"a");

	let ready = closed
		.apply_times_with_birth_policy(before.times, BirthTimePolicy::Preserve)
		.unwrap();
	assert_eq!(*ready.identity(), identity);
	assert_eq!(
		ready.with_metadata(|view| view.stat()).unwrap().times,
		before.times
	);
	ready.revalidate().unwrap();
}

#[test]
fn caller_can_require_zero_initial_flags_and_unchanged_birth_time() {
	let nonzero = ObjectFlags::from_raw(libc::UF_HIDDEN);
	assert!(matches!(
		InitialFlags::RequireZero.check(nonzero),
		Err(WriterError::UnexpectedInitialFlags { actual }) if actual == nonzero
	));
	InitialFlags::AllowStable.check(nonzero).unwrap();

	let scratch = Scratch::new();
	let directory = scratch.directory();
	let name = EntryName::new(STAGE.as_bytes()).unwrap();
	let file = PrivateWriter::create(&directory, &name, 0)
		.unwrap()
		.flush_and_close()
		.unwrap();
	let original = *file.identity();
	let earlier = Timestamp::new(original.birth().seconds() - 1, 0).unwrap();
	let result = file.apply_times_with_birth_policy(
		AccessModificationTimes {
			access: earlier,
			modification: earlier,
		},
		BirthTimePolicy::Preserve,
	);
	assert!(matches!(
		result,
		Err(WriterError::TimesAppliedButUnverified(error)) if matches!(*error, WriterError::Changed)
	));
	let retained = ObjectIdentity::named(&directory, &name).unwrap().unwrap();
	assert_eq!(retained.inode(), original.inode());
	assert_eq!(retained.birth().seconds(), earlier.seconds());
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
	let metadata = reader.with_metadata(|view| {
		let observed = view.stat()?;
		fs::rename(&stage, scratch.path(FORMER_STAGE)).unwrap();
		fs::write(&stage, b"b").unwrap();
		Ok(observed)
	});
	assert!(metadata.is_err());
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

#[test]
fn reports_a_completed_barrier_with_incomplete_live_evidence() {
	let scratch = Scratch::new();
	let directory = scratch.directory();
	let name = EntryName::new(STAGE.as_bytes()).unwrap();
	let writer = PrivateWriter::create(&directory, &name, 0).unwrap();
	let checked_close_called = Cell::new(false);
	let result = writer.finish_with(
		|_| {
			fs::rename(scratch.path(STAGE), scratch.path(FORMER_STAGE)).unwrap();
			Ok(())
		},
		|_| {
			checked_close_called.set(true);
			Ok(())
		},
	);
	assert!(matches!(
		result,
		Err(WriterError::BarrierPassedButUnverified(_))
	));
	assert!(!checked_close_called.get());
	assert!(scratch.path(FORMER_STAGE).exists());
}

#[test]
fn timestamp_metadata_checks_bracket_the_update_and_barrier() {
	#[derive(Debug, PartialEq, Eq)]
	enum Event {
		Check(MetadataCheckPhase),
		Barrier,
	}

	let scratch = Scratch::new();
	let directory = scratch.directory();
	let name = EntryName::new(STAGE.as_bytes()).unwrap();
	let closed = PrivateWriter::create(&directory, &name, 0)
		.unwrap()
		.flush_and_close()
		.unwrap();
	let original = closed.with_metadata(|view| view.stat()).unwrap();
	let requested = later_times(original.times);
	let events = RefCell::new(Vec::new());
	let ready = closed
		.apply_times_checked_with(
			requested,
			BirthTimePolicy::Preserve,
			|phase, view| {
				events.borrow_mut().push(Event::Check(phase));
				let before_update = phase == MetadataCheckPhase::BeforeUpdate;
				let expected = if before_update {
					original.times
				} else {
					requested
				};
				assert_eq!(view.stat()?.times, expected);
				Ok(())
			},
			|file| {
				events.borrow_mut().push(Event::Barrier);
				full_file_sync(file)
			},
		)
		.unwrap();
	assert_eq!(
		events.into_inner(),
		[
			Event::Check(MetadataCheckPhase::BeforeUpdate),
			Event::Check(MetadataCheckPhase::AfterUpdate),
			Event::Barrier,
			Event::Check(MetadataCheckPhase::AfterBarrier),
		]
	);
	assert_eq!(ready.times(), requested);
}

#[test]
fn timestamp_metadata_refusals_preserve_the_phase_of_the_effect() {
	for refused in [
		MetadataCheckPhase::BeforeUpdate,
		MetadataCheckPhase::AfterUpdate,
		MetadataCheckPhase::AfterBarrier,
	] {
		let scratch = Scratch::new();
		let directory = scratch.directory();
		let name = EntryName::new(STAGE.as_bytes()).unwrap();
		let closed = PrivateWriter::create(&directory, &name, 0)
			.unwrap()
			.flush_and_close()
			.unwrap();
		let original = closed.with_metadata(|view| view.stat()).unwrap().times;
		let requested = later_times(original);
		let result =
			closed.apply_times_checked(requested, BirthTimePolicy::Preserve, |phase, _| {
				if phase == refused {
					return Err(WriterError::MetadataRefused(Box::new(io::Error::other(
						METADATA_REFUSAL,
					))));
				}
				Ok(())
			});
		let held = File::open(scratch.path(STAGE)).unwrap();
		let observed = crate::metadata::stat(&held).unwrap().times;
		if refused == MetadataCheckPhase::BeforeUpdate {
			assert!(matches!(result, Err(WriterError::MetadataRefused(_))));
			assert_eq!(observed, original);
		} else {
			assert!(matches!(
				result,
				Err(WriterError::TimesAppliedButUnverified(error))
					if matches!(*error, WriterError::MetadataRefused(_))
			));
			assert_eq!(observed, requested);
		}
	}
}

#[test]
fn seal_checks_bracket_barrier_and_preserve_existing_metadata() {
	#[derive(Debug, PartialEq, Eq)]
	enum Event {
		Check(SealCheckPhase),
		Barrier,
	}

	let scratch = Scratch::new();
	let directory = scratch.directory();
	let name = EntryName::new(STAGE.as_bytes()).unwrap();
	let mut writer = PrivateWriter::create(&directory, &name, 1).unwrap();
	writer.write_next(b"a").unwrap();
	let closed = writer.flush_and_close().unwrap();
	let identity = *closed.identity();
	let mut output = [0];
	closed
		.open_read_back()
		.unwrap()
		.read_exact_at(0, &mut output)
		.unwrap();
	assert_eq!(&output, b"a");
	let before = closed.with_metadata(|view| view.stat()).unwrap();
	let events = RefCell::new(Vec::new());
	let ready = closed
		.seal_checked_with(
			|phase, view| {
				events.borrow_mut().push(Event::Check(phase));
				assert_eq!(view.stat()?, before);
				Ok(())
			},
			|file| {
				events.borrow_mut().push(Event::Barrier);
				full_file_sync(file)
			},
		)
		.unwrap();
	assert_eq!(
		events.into_inner(),
		[
			Event::Check(SealCheckPhase::BeforeBarrier),
			Event::Barrier,
			Event::Check(SealCheckPhase::AfterBarrier),
		]
	);
	assert_eq!(*ready.identity(), identity);
	assert_eq!(ready.times(), before.times);
	assert_eq!(ready.with_metadata(|view| view.stat()).unwrap(), before);
}

#[test]
fn seal_refusals_distinguish_a_successful_barrier_and_retain_metadata() {
	for refused in [SealCheckPhase::BeforeBarrier, SealCheckPhase::AfterBarrier] {
		let scratch = Scratch::new();
		let directory = scratch.directory();
		let name = EntryName::new(STAGE.as_bytes()).unwrap();
		let closed = PrivateWriter::create(&directory, &name, 0)
			.unwrap()
			.flush_and_close()
			.unwrap();
		let before = closed.with_metadata(|view| view.stat()).unwrap();
		let result = closed.seal_checked(|phase, _| {
			if phase == refused {
				return Err(WriterError::MetadataRefused(Box::new(io::Error::other(
					METADATA_REFUSAL,
				))));
			}
			Ok(())
		});
		let held = File::open(scratch.path(STAGE)).unwrap();
		assert_eq!(crate::metadata::stat(&held).unwrap(), before);
		match refused {
			SealCheckPhase::BeforeBarrier => {
				assert!(matches!(result, Err(WriterError::MetadataRefused(_))));
			}
			SealCheckPhase::AfterBarrier => {
				assert!(matches!(
					result,
					Err(WriterError::BarrierPassedButUnverified(error))
						if matches!(*error, WriterError::MetadataRefused(_))
				));
			}
		}
	}
}

fn later_times(times: AccessModificationTimes) -> AccessModificationTimes {
	AccessModificationTimes {
		access: times.access,
		modification: Timestamp::new(times.modification.seconds() + 1, 0).unwrap(),
	}
}
