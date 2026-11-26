//! Semantic parity of the single no_std engine across simulated and hosted sources.

use std::{
	cell::RefCell,
	fmt::Debug,
	fs::File,
	io::{self, Read, Seek, SeekFrom, Write},
};

use apfs_container::{Container, Error, LookupOptions, OpenOptions, probe_extent};
use apfs_core::{ByteOffset, ReadAt};
use apfs_format::{object::ObjectId, superblock::BlockAddress};

use super::{
	BLOCK_BYTES, DEVICE_BYTES, EARLY_NXSB, EARLY_XID, Fixture, LAST_DESCRIPTOR_BLOCK, LATEST_NXSB,
	LATEST_XID, MOVED_EARLY_MAP, VOLUME_SUPERBLOCK,
};

const NATIVE_VOLUME_ID: ObjectId = ObjectId(1026);
const NATIVE_VOLUME_NAME: &str = "Pomologie APFS Fixture";

#[derive(Debug)]
struct HostedSource {
	file: RefCell<File>,
	len: u64,
}

impl HostedSource {
	fn from_fixture(fixture: &Fixture) -> io::Result<Self> {
		let mut file = tempfile::tempfile()?;
		file.set_len(fixture.len())?;
		for (&address, bytes) in &fixture.0 {
			file.seek(SeekFrom::Start(address * BLOCK_BYTES as u64))?;
			file.write_all(bytes)?;
		}
		let len = file.metadata()?.len();
		Ok(Self {
			file: RefCell::new(file),
			len,
		})
	}
}

impl ReadAt for HostedSource {
	type Error = io::Error;

	fn len(&self) -> u64 {
		self.len
	}

	fn read_exact_at(&self, offset: ByteOffset, destination: &mut [u8]) -> io::Result<()> {
		let mut file = self.file.borrow_mut();
		file.seek(SeekFrom::Start(offset.0))?;
		file.read_exact(destination)
	}
}

#[test]
fn native_checkpoint_metadata_and_bytes_match_across_sources() {
	let fixture = Fixture::native();
	let native_volume = fixture.0[&VOLUME_SUPERBLOCK];
	let file = HostedSource::from_fixture(&fixture).unwrap();
	assert_eq!(probe_extent(&fixture).unwrap().unwrap().get(), DEVICE_BYTES);
	assert_eq!(probe_extent(&file).unwrap().unwrap().get(), DEVICE_BYTES);

	let memory = Container::open(fixture, OpenOptions::default()).unwrap();
	let hosted = Container::open(file, OpenOptions::default()).unwrap();
	assert_eq!(memory.descriptor(), BlockAddress(LATEST_NXSB));
	assert_eq!(memory.superblock().object.transaction, LATEST_XID);
	assert_eq!(hosted.descriptor(), memory.descriptor());
	assert_eq!(hosted.superblock(), memory.superblock());
	assert_eq!(hosted.mappings(), memory.mappings());
	assert_eq!(hosted.diagnostics(), memory.diagnostics());
	assert!(hosted.diagnostics().is_empty());

	let mut memory = memory
		.open_volume_objects(NATIVE_VOLUME_ID, LookupOptions::default())
		.unwrap()
		.unwrap();
	let mut hosted = hosted
		.open_volume_objects(NATIVE_VOLUME_ID, LookupOptions::default())
		.unwrap()
		.unwrap();
	assert_eq!(hosted.volume(), memory.volume());
	assert_eq!(hosted.volume().superblock.name.as_str(), NATIVE_VOLUME_NAME);
	assert_eq!(
		hosted.volume().mapping.address,
		BlockAddress(VOLUME_SUPERBLOCK)
	);

	let offset = ByteOffset(VOLUME_SUPERBLOCK * BLOCK_BYTES as u64);
	let mut memory_bytes = [0; BLOCK_BYTES];
	let mut hosted_bytes = [0; BLOCK_BYTES];
	memory.read_physical_at(offset, &mut memory_bytes).unwrap();
	hosted.read_physical_at(offset, &mut hosted_bytes).unwrap();
	assert_eq!(hosted_bytes, memory_bytes);
	assert_eq!(hosted_bytes, native_volume);

	fn assert_read_bounds(source: Result<(), Error<impl Debug>>) {
		assert!(matches!(
			source,
			Err(Error::ReadBounds {
				offset: ByteOffset(DEVICE_BYTES),
				bytes: 1
			})
		));
	}
	assert_read_bounds(memory.read_physical_at(ByteOffset(DEVICE_BYTES), &mut [0]));
	assert_read_bounds(hosted.read_physical_at(ByteOffset(DEVICE_BYTES), &mut [0]));
}

#[test]
fn checkpoint_refusals_match_across_sources() {
	fn no_checkpoint(
		result: Result<Container<impl Debug>, Error<impl Debug>>,
	) -> Vec<apfs_container::Diagnostic> {
		match result.unwrap_err() {
			Error::NoCheckpoint { diagnostics } => diagnostics,
			error => panic!("expected NoCheckpoint, got {error:?}"),
		}
	}

	let mut fixture = Fixture::wrapped_descriptors();
	for slot in [LAST_DESCRIPTOR_BLOCK, MOVED_EARLY_MAP] {
		fixture.0.insert(slot, [0; BLOCK_BYTES]);
	}
	let file = HostedSource::from_fixture(&fixture).unwrap();
	let options = OpenOptions::default();
	let memory = no_checkpoint(Container::open(fixture, options));
	let hosted = no_checkpoint(Container::open(file, options));
	assert_eq!(hosted, memory);
	assert_eq!(hosted.len(), 2);

	let mut fixture = Fixture::native();
	fixture.0.insert(EARLY_NXSB, [0; BLOCK_BYTES]);
	let file = HostedSource::from_fixture(&fixture).unwrap();
	let memory = Container::open_at(fixture, options, EARLY_XID);
	let hosted = Container::open_at(file, options, EARLY_XID);
	assert!(matches!(
		memory,
		Err(Error::CheckpointNotFound {
			transaction: EARLY_XID,
			..
		})
	));
	assert!(matches!(
		hosted,
		Err(Error::CheckpointNotFound {
			transaction: EARLY_XID,
			..
		})
	));
}
