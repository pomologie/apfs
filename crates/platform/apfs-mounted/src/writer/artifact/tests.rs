use std::{cell::Cell, fs, fs::File, io, path::Path};

use crate::ObjectIdentity;

use super::*;

const NAME: &str = "private-artifact";
const REBOUND_NAME: &str = "former-artifact";
const PAYLOAD: &[u8] = b"caller-encoded artifact";
const INCUMBENT: &[u8] = b"incumbent";
const REFUSAL: &str = "fixture denied the policy check";

fn location() -> (tempfile::TempDir, Directory, EntryName) {
	let scratch = tempfile::tempdir().unwrap();
	let directory = Directory::from_file(File::open(scratch.path()).unwrap()).unwrap();
	let name = EntryName::new(NAME.as_bytes()).unwrap();
	(scratch, directory, name)
}

#[test]
fn checks_a_multichunk_artifact_and_keeps_the_original_event_anchor() {
	struct CreationGuard<'scope> {
		path: &'scope Path,
		dropped_after_open: &'scope Cell<bool>,
	}

	impl Drop for CreationGuard<'_> {
		fn drop(&mut self) {
			self.dropped_after_open
				.set(matches!(fs::metadata(self.path), Ok(stat) if stat.len() == 0));
		}
	}

	let (scratch, directory, name) = location();
	let path = scratch.path().join(NAME);
	let dropped_after_open = Cell::new(false);
	let mut checks = Vec::new();
	let mut bytes = vec![1; MAX_PRIVATE_IO_BYTES + 3];
	bytes[MAX_PRIVATE_IO_BYTES] = 2;
	let length = bytes.len() as u64;
	let artifact = write_private_artifact_checked(
		&directory,
		&name,
		&bytes,
		InitialFlags::RequireZero,
		|| {
			assert!(!path.try_exists().unwrap());
			Ok(CreationGuard {
				path: &path,
				dropped_after_open: &dropped_after_open,
			})
		},
		|phase, metadata| {
			assert!(dropped_after_open.get());
			checks.push((phase, metadata.stat()?.length));
			Ok(())
		},
	)
	.unwrap();
	assert_eq!(
		checks,
		[
			(ArtifactCheckPhase::AfterCreate, 0),
			(ArtifactCheckPhase::BeforeBarrier, length),
			(ArtifactCheckPhase::BeforeReopen, length),
			(ArtifactCheckPhase::BeforeReadBack, length),
			(ArtifactCheckPhase::AfterReadBack, length),
		]
	);
	assert_eq!(artifact.len(), length);
	assert_eq!(
		ObjectIdentity::held(artifact.event_handle()).unwrap(),
		*artifact.identity()
	);
	assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn refusal_precedes_creation_and_exclusive_creation_preserves_the_incumbent() {
	let (scratch, directory, name) = location();
	let path = scratch.path().join(NAME);
	let refuse = || {
		Err::<(), _>(WriterError::CreationRefused(Box::new(io::Error::other(
			REFUSAL,
		))))
	};
	let check = |_: ArtifactCheckPhase, _: MetadataView<'_>| -> Result<(), WriterError> {
		panic!("uncreated file reached metadata checks")
	};
	let create = |authorize: fn() -> Result<(), WriterError>| {
		write_private_artifact_checked(
			&directory,
			&name,
			PAYLOAD,
			InitialFlags::RequireZero,
			authorize,
			check,
		)
	};
	assert!(matches!(
		create(refuse),
		Err(ArtifactError {
			phase: ArtifactPhase::Create,
			error: WriterError::CreationRefused(_)
		})
	));
	assert!(!path.try_exists().unwrap());
	fs::write(&path, INCUMBENT).unwrap();
	assert!(matches!(
		create(refuse),
		Err(ArtifactError {
			phase: ArtifactPhase::Create,
			error: WriterError::CreationRefused(_)
		})
	));
	assert!(matches!(
		create(|| Ok(())),
		Err(ArtifactError {
			phase: ArtifactPhase::Create,
			error: WriterError::Occupied
		})
	));
	assert_eq!(fs::read(path).unwrap(), INCUMBENT);
}

#[test]
fn phase_checks_keep_private_bytes_and_preserve_failure_evidence() {
	for refused in [
		ArtifactCheckPhase::AfterCreate,
		ArtifactCheckPhase::BeforeBarrier,
		ArtifactCheckPhase::BeforeReopen,
		ArtifactCheckPhase::BeforeReadBack,
		ArtifactCheckPhase::AfterReadBack,
	] {
		let (scratch, directory, name) = location();
		let result = write_private_artifact_checked(
			&directory,
			&name,
			PAYLOAD,
			InitialFlags::RequireZero,
			|| Ok(()),
			|phase, _| {
				if phase == refused {
					return Err(WriterError::MetadataRefused(Box::new(io::Error::other(
						REFUSAL,
					))));
				}
				Ok(())
			},
		);
		let error = result.unwrap_err();
		let bytes = fs::read(scratch.path().join(NAME)).unwrap();
		match refused {
			ArtifactCheckPhase::AfterCreate => {
				assert_eq!(error.phase, ArtifactPhase::Create);
				assert!(matches!(
					error.error,
					WriterError::CreatedButUnverified(cause) if matches!(*cause, WriterError::MetadataRefused(_))
				));
				assert!(bytes.is_empty());
			}
			ArtifactCheckPhase::BeforeBarrier => {
				assert_eq!(error.phase, ArtifactPhase::FlushAndClose);
				assert!(matches!(error.error, WriterError::MetadataRefused(_)));
				assert_eq!(bytes, PAYLOAD);
			}
			ArtifactCheckPhase::BeforeReopen => {
				assert_eq!(error.phase, ArtifactPhase::Reopen);
				assert!(matches!(error.error, WriterError::MetadataRefused(_)));
				assert_eq!(bytes, PAYLOAD);
			}
			ArtifactCheckPhase::BeforeReadBack | ArtifactCheckPhase::AfterReadBack => {
				assert_eq!(error.phase, ArtifactPhase::ReadBack);
				assert!(matches!(error.error, WriterError::MetadataRefused(_)));
				assert_eq!(bytes, PAYLOAD);
			}
		}
	}
}

#[test]
fn refuses_a_rebound_name_during_read_back_without_touching_either_entry() {
	let (scratch, directory, name) = location();
	let path = scratch.path().join(NAME);
	let rebound_path = scratch.path().join(REBOUND_NAME);
	let result = write_private_artifact_checked(
		&directory,
		&name,
		PAYLOAD,
		InitialFlags::RequireZero,
		|| Ok(()),
		|phase, _| {
			if phase == ArtifactCheckPhase::BeforeReadBack {
				fs::rename(&path, &rebound_path)?;
				fs::write(&path, PAYLOAD)?;
			}
			Ok(())
		},
	);
	assert!(matches!(
		result,
		Err(ArtifactError {
			phase: ArtifactPhase::ReadBack,
			error: WriterError::Identity(_)
		})
	));
	assert_eq!(fs::read(path).unwrap(), PAYLOAD);
	assert_eq!(fs::read(rebound_path).unwrap(), PAYLOAD);
}

#[test]
fn exact_read_back_reports_the_first_mismatching_offset() {
	let (_scratch, directory, name) = location();
	let mut bytes = vec![1; READ_BACK_CHUNK_BYTES + 3];
	let artifact = write_private_artifact_checked(
		&directory,
		&name,
		&bytes,
		InitialFlags::RequireZero,
		|| Ok(()),
		|_, _| Ok(()),
	)
	.unwrap();
	let mismatch = READ_BACK_CHUNK_BYTES + 1;
	bytes[mismatch] = 2;
	assert!(matches!(
		verify_bytes(&artifact.open_read_back().unwrap(), &bytes),
		Err(WriterError::ReadBackMismatch { offset }) if offset == mismatch as u64
	));
}
