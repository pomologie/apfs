use std::{fs as host, os::unix::fs::symlink, path::Path};

use super::*;

const CHILD: &str = "job";
const MOVED: &str = "moved";
const OTHER_PID_BIT: u32 = 1;

fn directory(path: &Path) -> Directory {
	Directory::from_file(host::File::open(path).unwrap()).unwrap()
}

fn acquired(attempt: Result<LeaseAttempt, LeaseError>) -> Lease {
	let LeaseAttempt::Acquired(lease) = attempt.unwrap() else {
		panic!("expected acquired directory lease");
	};
	lease
}

#[test]
fn shared_and_exclusive_acquisitions_use_independent_descriptions() {
	let temporary = tempfile::tempdir().unwrap();
	let directory = directory(temporary.path());
	let first = acquired(Lease::try_acquire(&directory, LeaseMode::Shared));
	let second = acquired(Lease::try_acquire(&directory, LeaseMode::Shared));
	assert_eq!(first.mode(), LeaseMode::Shared);
	assert!(
		rustix::io::fcntl_getfd(&first.file)
			.unwrap()
			.contains(rustix::io::FdFlags::CLOEXEC)
	);
	first.revalidate().unwrap();
	second.revalidate().unwrap();
	fs::flock(&directory, FlockOperation::Unlock).unwrap();
	assert!(matches!(
		Lease::try_acquire(&directory, LeaseMode::Exclusive),
		Ok(LeaseAttempt::Busy)
	));
	first.release().unwrap();
	assert!(matches!(
		Lease::try_acquire(&directory, LeaseMode::Exclusive),
		Ok(LeaseAttempt::Busy)
	));
	drop(second);

	let exclusive = acquired(Lease::try_acquire(&directory, LeaseMode::Exclusive));
	assert_eq!(exclusive.mode(), LeaseMode::Exclusive);
	assert!(matches!(
		Lease::try_acquire(&directory, LeaseMode::Shared),
		Ok(LeaseAttempt::Busy)
	));
	exclusive.release().unwrap();
	acquired(Lease::try_acquire(&directory, LeaseMode::Shared))
		.release()
		.unwrap();
}

#[test]
fn an_inherited_view_does_not_unlock_the_acquirers_description() {
	let temporary = tempfile::tempdir().unwrap();
	let directory = directory(temporary.path());
	let mut lease = acquired(Lease::try_acquire(&directory, LeaseMode::Exclusive));
	let fork_alias = rustix::io::dup(&lease.file).unwrap();
	// A second descriptor and a different recorded PID simulate the inherited
	// view without forking the multithreaded Rust test process.
	lease.process ^= OTHER_PID_BIT;
	assert!(matches!(lease.revalidate(), Err(LeaseError::WrongProcess)));
	assert!(matches!(lease.release(), Err(LeaseError::WrongProcess)));
	assert!(matches!(
		Lease::try_acquire(&directory, LeaseMode::Shared),
		Ok(LeaseAttempt::Busy)
	));
	drop(fork_alias);
	acquired(Lease::try_acquire(&directory, LeaseMode::Exclusive))
		.release()
		.unwrap();
}

#[test]
fn named_binding_detects_a_rebound_entry_and_refuses_a_symlink() {
	let temporary = tempfile::tempdir().unwrap();
	let child_path = temporary.path().join(CHILD);
	let moved_path = temporary.path().join(MOVED);
	host::create_dir(&child_path).unwrap();
	let child = directory(&child_path);
	let named = {
		let parent = directory(temporary.path());
		let name = EntryName::new(CHILD.as_bytes()).unwrap();
		acquired(Lease::try_acquire_named(&parent, &name, LeaseMode::Shared))
	};
	let held = acquired(Lease::try_acquire(&child, LeaseMode::Shared));
	drop(child);
	assert_eq!(named.identity(), held.identity());

	host::rename(&child_path, &moved_path).unwrap();
	host::create_dir(&child_path).unwrap();
	assert!(matches!(
		named.revalidate(),
		Err(LeaseError::Identity(IdentityError::Changed))
	));
	held.revalidate().unwrap();
	named.release().unwrap();
	held.release().unwrap();

	host::remove_dir(&child_path).unwrap();
	symlink(&moved_path, &child_path).unwrap();
	let parent = directory(temporary.path());
	let name = EntryName::new(CHILD.as_bytes()).unwrap();
	assert!(matches!(
		Lease::try_acquire_named(&parent, &name, LeaseMode::Exclusive),
		Err(LeaseError::Io(_))
	));
}
