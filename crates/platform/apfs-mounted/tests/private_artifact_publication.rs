#![cfg(target_os = "macos")]

use std::fs::File;

use apfs_mounted::{
	Directory, EntryName,
	lease::{Lease, LeaseAttempt, LeaseMode},
	metadata::{MAX_EXTENDED_SECURITY_BYTES, set_empty_acl_on_fresh_directory},
	publication::{
		EntrySpelling, OwnedEventEntry, RenameAttempt, attempt_exclusive_rename_checked,
	},
	writer::{InitialFlags, WriterError, sync_directory, write_private_artifact_checked},
};

const RECORDS_NAME: &[u8] = b"records";
const PENDING_NAME: &[u8] = b"receipt.pending";
const RECEIPT_NAME: &[u8] = b"receipt";
const RECEIPT_BYTES: &[u8] = b"synthetic immutable receipt";

#[test]
fn verifies_and_promotes_a_private_artifact_under_caller_ordering() {
	let scratch = tempfile::tempdir().unwrap();
	let root = Directory::from_file(File::open(scratch.path()).unwrap()).unwrap();
	let directory = root
		.create_private_directory(&EntryName::new(RECORDS_NAME).unwrap())
		.unwrap();
	set_empty_acl_on_fresh_directory(&directory).unwrap();
	let LeaseAttempt::Acquired(lease) =
		Lease::try_acquire(&directory, LeaseMode::Exclusive).unwrap()
	else {
		panic!("new records directory was already locked");
	};
	let pending = EntryName::new(PENDING_NAME).unwrap();
	let receipt = EntryName::new(RECEIPT_NAME).unwrap();
	let check_lease = || {
		lease
			.revalidate()
			.map_err(|error| WriterError::MetadataRefused(Box::new(error)))
	};
	let closed = write_private_artifact_checked(
		&directory,
		&pending,
		RECEIPT_BYTES,
		InitialFlags::RequireZero,
		check_lease,
		|_, view| {
			check_lease()?;
			if !view
				.extended_security(MAX_EXTENDED_SECURITY_BYTES)?
				.has_no_acl_entries()
			{
				return Err(WriterError::NotPrivate);
			}
			Ok(())
		},
	)
	.unwrap();
	assert!(
		OwnedEventEntry::open_named(&directory, receipt.clone())
			.unwrap()
			.is_none()
	);
	let attempt = attempt_exclusive_rename_checked(
		&directory,
		&pending,
		&directory,
		&receipt,
		closed.event_handle(),
		closed.identity(),
		check_lease,
	)
	.unwrap();
	let RenameAttempt::Renamed(renamed) = attempt else {
		panic!("unexpected receipt promotion: {attempt:?}");
	};
	sync_directory(&directory).unwrap();
	let (published, ()) = renamed
		.with_observation(EntrySpelling::Exact, |_, _| Ok(()))
		.unwrap();
	check_lease().unwrap();
	assert!(
		OwnedEventEntry::open_named(&directory, pending.clone())
			.unwrap()
			.is_none()
	);
	let observed = OwnedEventEntry::open_named(&directory, receipt)
		.unwrap()
		.unwrap();
	let (observed, ()) = observed
		.with_observation(EntrySpelling::Exact, |_, _| Ok(()))
		.unwrap();
	assert_eq!(observed, published);
	assert_eq!(&observed.identity, closed.identity());
	assert_eq!(observed.extent(), RECEIPT_BYTES.len() as u64);
	lease.release().unwrap();
}
