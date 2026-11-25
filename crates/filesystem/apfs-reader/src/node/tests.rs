use apfs_format::{
	object::{ObjectId, TransactionId, checksum},
	superblock::Superblock,
};

use crate::{FileKind, InodeCount, InodeId, StreamSizes, record};

use super::*;

const NATIVE: &[u8; 4096] = include_bytes!("../../tests/fixtures/sonoma-populated-fsroot.bin");
const SOURCE_LENGTH: u64 = 64 << 20;
const NATIVE_SUPERBLOCK: &[u8] = include_bytes!("../../tests/fixtures/native-block-0.bin");
const ROOT_OID: ObjectId = ObjectId(1028);
const ROOT_XID: TransactionId = TransactionId(3);
const NATIVE_ENTRIES: usize = 30;
const NOTE_INODE: InodeId = InodeId::from_raw(20).unwrap();

fn decode(bytes: &[u8]) -> Result<Node<'_>, Error<()>> {
	let geometry = Superblock::decode(NATIVE_SUPERBLOCK, SOURCE_LENGTH)
		.unwrap()
		.geometry;
	Node::decode(
		bytes,
		Header::decode(bytes).unwrap(),
		geometry,
		None,
		TreeKind::Filesystem,
	)
}

#[test]
fn decodes_native_variable_leaf_and_inode_extended_fields() {
	let header = Header::decode(NATIVE).unwrap();
	assert_eq!(header.id, ROOT_OID);
	assert_eq!(header.transaction, ROOT_XID);
	let node = decode(NATIVE).unwrap();
	node.validate::<()>().unwrap();
	assert_eq!(node.len(), NATIVE_ENTRIES);
	let mut name_index = 0;
	let names = ["ALPHA.txt", "Empty", "Étude.txt", "Docs", "link"];
	for index in 0..node.len() {
		let slot = node.slot(index).unwrap();
		let key = Prefix::decode(slot.key).unwrap();
		if key == Prefix::directory(InodeId::ROOT) {
			let entry = record::directory::<()>(slot.key, slot.value, true).unwrap();
			assert_eq!(entry.name, names[name_index]);
			name_index += 1;
		}
		if key == Prefix::inode(NOTE_INODE) {
			let metadata = record::inode(NOTE_INODE, slot.key, slot.value).unwrap();
			assert_eq!(metadata.kind, FileKind::Regular);
			assert_eq!(metadata.count, InodeCount::Links(1));
			assert_eq!(
				metadata.stream,
				Some(StreamSizes {
					logical_bytes: 30,
					allocated_bytes: 4096,
					default_crypto_id: 0,
				})
			);
		}
	}
	assert_eq!(name_index, names.len());
}

#[test]
fn rejects_live_slots_with_overlapping_records() {
	let mut bytes = *NATIVE;
	bytes.copy_within(DATA..DATA + TOC_ENTRY_BYTES, DATA + TOC_ENTRY_BYTES);
	let sum = checksum(&bytes).unwrap();
	bytes[..U64_BYTES].copy_from_slice(&sum.to_le_bytes());

	let corrupt = decode(&bytes).unwrap().validate::<()>();
	assert!(matches!(
		corrupt,
		Err(Error::Corrupt(Corruption::OverlappingRecords))
	));
}

#[test]
fn rejects_a_table_that_claims_more_slots_than_its_region() {
	let mut bytes = *NATIVE;
	let too_many =
		u32::from(u16_at(&bytes, TABLE + U16_BYTES).unwrap()) / TOC_ENTRY_BYTES as u32 + 1;
	let total_keys = bytes.len() - FOOTER_BYTES + 24;
	bytes[COUNT..COUNT + size_of::<u32>()].copy_from_slice(&too_many.to_le_bytes());
	bytes[total_keys..total_keys + U64_BYTES].copy_from_slice(&u64::from(too_many).to_le_bytes());
	let sum = checksum(&bytes).unwrap();
	bytes[..U64_BYTES].copy_from_slice(&sum.to_le_bytes());

	assert!(matches!(
		decode(&bytes),
		Err(Error::Corrupt(Corruption::TableOfContents))
	));
}
