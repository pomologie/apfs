use std::{
	fs::{self, File},
	os::unix::fs::{MetadataExt, symlink},
	time::UNIX_EPOCH,
};

use super::*;

#[test]
fn matches_held_and_named_identity_through_a_rename_and_rejects_rebound_name() {
	let temp = tempfile::tempdir().unwrap();
	let original = temp.path().join("source");
	let renamed = temp.path().join("renamed");
	fs::write(&original, b"source fixture").unwrap();
	let file = File::open(&original).unwrap();
	let parent = Directory::from_file(File::open(temp.path()).unwrap()).unwrap();
	let original_name = EntryName::new(b"source").unwrap();
	let renamed_name = EntryName::new(b"renamed").unwrap();
	let identity = ObjectIdentity::held(&file).unwrap();
	let event = parent.open_event(&original_name).unwrap();
	assert_eq!(ObjectIdentity::held(&event).unwrap(), identity);
	let stat = fs::metadata(&original).unwrap();
	let birth = stat.created().unwrap().duration_since(UNIX_EPOCH).unwrap();
	assert_eq!(identity.inode().get(), stat.ino());
	assert_eq!(identity.device(), i32::try_from(stat.dev()).unwrap());
	assert_eq!(
		identity.birth().seconds(),
		i64::try_from(birth.as_secs()).unwrap()
	);
	assert_eq!(identity.birth().nanoseconds(), birth.subsec_nanos());
	assert_ne!(identity.physical_fsid(), [0; 2]);
	assert_eq!(
		identity.mount(),
		ObjectIdentity::held(&parent).unwrap().mount()
	);
	assert_eq!(
		ObjectIdentity::named(&parent, &original_name).unwrap(),
		Some(identity)
	);

	fs::rename(&original, &renamed).unwrap();
	identity.revalidate_held(&file).unwrap();
	identity.revalidate_named(&parent, &renamed_name).unwrap();
	assert_eq!(
		ObjectIdentity::named(&parent, &original_name).unwrap(),
		None
	);
	assert!(matches!(
		identity.revalidate_named(&parent, &original_name),
		Err(IdentityError::Changed),
	));
	fs::write(&original, b"replacement fixture").unwrap();
	identity.revalidate_held(&file).unwrap();
	assert!(matches!(
		identity.revalidate_named(&parent, &original_name),
		Err(IdentityError::Changed),
	));
}

#[test]
fn observes_a_dangling_symlink_without_following_the_payload() {
	let temp = tempfile::tempdir().unwrap();
	let link = temp.path().join("symbolic");
	symlink("missing-target", &link).unwrap();
	let parent = Directory::from_file(File::open(temp.path()).unwrap()).unwrap();
	let name = EntryName::new(b"symbolic").unwrap();
	let named = ObjectIdentity::named(&parent, &name).unwrap().unwrap();
	assert_eq!(
		named.inode().get(),
		fs::symlink_metadata(&link).unwrap().ino()
	);
	assert!(fs::metadata(&link).is_err());
}

#[test]
fn preserves_the_held_parent_after_reopening_its_original_path() {
	let temp = tempfile::tempdir().unwrap();
	let parent_path = temp.path().join("parent");
	let new_path = temp.path().join("moved");
	fs::create_dir(&parent_path).unwrap();
	fs::write(parent_path.join("source"), b"original child").unwrap();
	let parent = Directory::from_file(File::open(&parent_path).unwrap()).unwrap();
	let name = EntryName::new(b"source").unwrap();
	let root = ObjectIdentity::held(&parent).unwrap();
	let child = ObjectIdentity::named(&parent, &name).unwrap().unwrap();

	fs::rename(&parent_path, &new_path).unwrap();
	fs::create_dir(&parent_path).unwrap();
	fs::write(parent_path.join("source"), b"replacement child").unwrap();
	root.revalidate_held(&parent).unwrap();
	child.revalidate_named(&parent, &name).unwrap();
	let reopened = Directory::from_file(File::open(&parent_path).unwrap()).unwrap();
	assert!(matches!(
		root.revalidate_held(&reopened),
		Err(IdentityError::Changed)
	));
	assert!(matches!(
		child.revalidate_named(&reopened, &name),
		Err(IdentityError::Changed)
	));
}

#[test]
fn checks_stat_fields_and_matches_the_inode_returned_with_fsid() {
	let file = tempfile::tempfile().unwrap();
	let mut stat = rustix::fs::fstat(&file).unwrap();
	let real = native::held(file.as_fd()).unwrap();
	stat.st_gen = 0;
	let identity = ObjectIdentity::from_stat(&stat, real).unwrap();
	assert_eq!(identity.generation(), None);
	assert_eq!(identity.birth().seconds(), stat.st_birthtime);
	assert_eq!(
		i64::from(identity.birth().nanoseconds()),
		stat.st_birthtime_nsec
	);

	let mut after = stat;
	after.st_gen = 1;
	assert!(matches!(
		ObjectIdentity::checked(&stat, real, &after),
		Err(IdentityError::Changed)
	));
	let other_inode = NonZeroU64::new(real.inode.get().checked_add(1).unwrap()).unwrap();
	let wrong_file = native::RealIdentity {
		inode: other_inode,
		..real
	};
	assert!(matches!(
		ObjectIdentity::from_stat(&stat, wrong_file),
		Err(IdentityError::Changed)
	));
	let other_mount = native::RealIdentity {
		physical_fsid: [u32::MAX; 2],
		..real
	};
	let changed_mount = ObjectIdentity::from_stat(&stat, other_mount).unwrap();
	assert_ne!(changed_mount.mount(), identity.mount());
	assert!(matches!(
		identity.require(Some(changed_mount)),
		Err(IdentityError::Changed)
	));

	for device in [0, NO_DEVICE] {
		let mut invalid = stat;
		invalid.st_dev = device;
		assert!(matches!(
			ObjectIdentity::from_stat(&invalid, real),
			Err(IdentityError::Unavailable)
		));
	}
	for nanos in [-1, i64::from(NANOS_PER_SECOND)] {
		let mut invalid = stat;
		invalid.st_birthtime_nsec = nanos;
		assert!(matches!(
			ObjectIdentity::from_stat(&invalid, real),
			Err(IdentityError::Unavailable)
		));
	}
}
