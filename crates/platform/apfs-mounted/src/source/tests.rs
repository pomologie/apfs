use std::{
	fs, io,
	os::unix::fs::{PermissionsExt as _, symlink},
	path::Path,
	process::Command,
};

use super::{
	MAX_INTERRUPTED_RETRIES, MAX_READ_BYTES, PinnedSource, SourceError, read_exact_loop,
	retry_interrupted,
};
use crate::{
	Directory, EntryName,
	lease::{Lease, LeaseAttempt, LeaseMode},
	metadata::{MAX_EXTENDED_SECURITY_BYTES, ObservationError, XattrVisibility},
};

const NAME: &str = "source.bin";
const PAYLOAD: &[u8] = b"pinned read witness";
const NO_MODE_BITS: u32 = 0;
const MAX_TEST_XATTR_BYTES: usize = 4096;
const TEST_XATTR_NAME: &std::ffi::CStr = c"org.pomologie.source-test";
const TEST_XATTR_VALUE: &str = "bound";

fn directory(path: &Path) -> Directory {
	Directory::from_file(fs::File::open(path).unwrap()).unwrap()
}

fn acquired(attempt: LeaseAttempt) -> Lease {
	match attempt {
		LeaseAttempt::Acquired(lease) => lease,
		LeaseAttempt::Busy => panic!("fresh fixture lease is busy"),
	}
}

#[test]
fn refusal_runs_before_a_readable_open() {
	let scratch = tempfile::tempdir().unwrap();
	let path = scratch.path().join(NAME);
	fs::write(&path, PAYLOAD).unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(NO_MODE_BITS)).unwrap();
	let root = directory(scratch.path());
	let name = EntryName::new(NAME.as_bytes()).unwrap();
	let lease = acquired(Lease::try_acquire(&root, LeaseMode::Shared).unwrap());
	assert!(matches!(
		PinnedSource::open_leased(&root, &name, &lease, |identity, metadata| {
			assert_eq!(identity.mount(), lease.identity().mount());
			assert_eq!(u32::from(metadata.mode), NO_MODE_BITS);
			assert_eq!(metadata.link_count, 1);
			Err(SourceError::AdmissionRefused)
		}),
		Err(SourceError::AdmissionRefused)
	));
	if rustix::process::geteuid().as_raw() != 0 {
		assert_eq!(
			fs::File::open(path).unwrap_err().kind(),
			io::ErrorKind::PermissionDenied
		);
	}
}

#[test]
fn rechecks_policy_observation_before_opening_a_rebound_selection() {
	let scratch = tempfile::tempdir().unwrap();
	let path = scratch.path().join(NAME);
	fs::write(&path, PAYLOAD).unwrap();
	let root = directory(scratch.path());
	let lease = acquired(Lease::try_acquire(&root, LeaseMode::Shared).unwrap());
	let name = EntryName::new(NAME.as_bytes()).unwrap();
	let outcome = PinnedSource::open_leased(&root, &name, &lease, |_, _| {
		fs::rename(&path, scratch.path().join("former")).unwrap();
		fs::write(&path, PAYLOAD).unwrap();
		fs::set_permissions(&path, fs::Permissions::from_mode(NO_MODE_BITS)).unwrap();
		Ok(())
	});
	assert!(matches!(outcome, Err(SourceError::Changed)));
}

#[test]
fn binds_to_the_selected_directory_and_its_named_lease() {
	let scratch = tempfile::tempdir().unwrap();
	let parent = directory(scratch.path());
	let root_name = EntryName::new(b"root").unwrap();
	let root_path = scratch.path().join("root");
	fs::create_dir(&root_path).unwrap();
	fs::write(root_path.join(NAME), PAYLOAD).unwrap();
	let root = directory(&root_path);
	let name = EntryName::new(NAME.as_bytes()).unwrap();
	let wrong_lease = acquired(Lease::try_acquire(&parent, LeaseMode::Shared).unwrap());
	assert!(matches!(
		PinnedSource::open_leased(&root, &name, &wrong_lease, |_, _| {
			panic!("a lease on the wrong directory reached admission")
		}),
		Err(SourceError::LeaseMismatch)
	));
	let lease =
		acquired(Lease::try_acquire_named(&parent, &root_name, LeaseMode::Exclusive).unwrap());
	let source = PinnedSource::open_leased(&root, &name, &lease, |_, _| Ok(())).unwrap();
	source.revalidate().unwrap();
	fs::rename(&root_path, scratch.path().join("moved")).unwrap();
	assert!(matches!(
		source.read_exact_at(0, &mut [0]),
		Err(SourceError::Lease(_))
	));
}

#[test]
fn metadata_queries_are_bounded_and_recheck_the_selected_name() {
	let scratch = tempfile::tempdir().unwrap();
	let path = scratch.path().join(NAME);
	fs::write(&path, PAYLOAD).unwrap();
	assert!(
		Command::new("/usr/bin/xattr")
			.args(["-w", TEST_XATTR_NAME.to_str().unwrap(), TEST_XATTR_VALUE])
			.arg(&path)
			.status()
			.unwrap()
			.success()
	);
	let root = directory(scratch.path());
	let lease = acquired(Lease::try_acquire(&root, LeaseMode::Shared).unwrap());
	let name = EntryName::new(NAME.as_bytes()).unwrap();
	let source = PinnedSource::open_leased(&root, &name, &lease, |_, _| Ok(())).unwrap();
	source
		.with_metadata(|view| {
			assert_eq!(view.stat()?.length, source.len());
			assert_eq!(
				view.stat()?.object_flags(),
				source.metadata().object_flags()
			);
			let _ = view.extended_security(MAX_EXTENDED_SECURITY_BYTES)?;
			let _ = view.resource_fork()?;
			let names =
				view.list_xattrs(XattrVisibility::IncludingCompression, MAX_TEST_XATTR_BYTES)?;
			assert!(names.iter().any(|name| name.as_c_str() == TEST_XATTR_NAME));
			assert_eq!(
				view.read_xattr(
					TEST_XATTR_NAME,
					XattrVisibility::IncludingCompression,
					TEST_XATTR_VALUE.len()
				)?
				.as_deref(),
				Some(TEST_XATTR_VALUE.as_bytes())
			);
			Ok(())
		})
		.unwrap();
	assert!(matches!(
		source.with_metadata(|view| view.list_xattrs(XattrVisibility::IncludingCompression, 0)),
		Err(SourceError::Metadata(ObservationError::Limit {
			limit: 0,
			..
		}))
	));
	assert!(matches!(
		source.with_metadata(|view| {
			fs::rename(&path, scratch.path().join("former")).unwrap();
			view.stat()
		}),
		Err(SourceError::Changed)
	));
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
