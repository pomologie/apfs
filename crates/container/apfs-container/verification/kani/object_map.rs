use apfs_format::{
	object::{ObjectId, TransactionId},
	object_map::{Key, Mapping, Record, Value},
	superblock::BlockAddress,
};

use super::{VirtualMapping, predecessor, visible_leaf_mapping};

const MAX_RECORDS: usize = 8;
const OBJECT_BYTES: u32 = 4096;

#[kani::proof]
#[kani::unwind(9)]
fn object_map_leaf_matches_visible_version_model() {
	let count: usize = kani::any();
	kani::assume(count <= MAX_RECORDS);
	let ids: [u64; MAX_RECORDS] = kani::any();
	let transactions: [u64; MAX_RECORDS] = kani::any();
	let deleted: [bool; MAX_RECORDS] = kani::any();
	let object: u64 = kani::any();
	let view: u64 = kani::any();
	let query = key(object, view);
	let key_at = |index| key(ids[index], transactions[index]);

	// A decoded node establishes strictly ordered, unique (OID, XID) keys.
	for index in 1..count {
		let prior = index - 1;
		kani::assume(
			ids[prior] < ids[index]
				|| (ids[prior] == ids[index] && transactions[prior] < transactions[index]),
		);
	}
	let index = predecessor(count, |index| Ok(key_at(index)), query).unwrap();
	let actual = index.and_then(|index| {
		assert!(index < count);
		let mapping = if deleted[index] {
			Mapping::Deleted
		} else {
			Mapping::Object {
				address: address(index),
				size: OBJECT_BYTES,
			}
		};
		visible_leaf_mapping(
			query.id,
			Record {
				key: key_at(index),
				value: Value::Mapping(mapping),
			},
		)
	});

	let mut visible: Option<(u64, usize, bool)> = None;
	let mut earlier_live = false;
	let mut future = false;
	// The model selects the maximum eligible XID directly. It neither searches
	// for a predecessor nor calls the production key comparator.
	for index in 0..count {
		if ids[index] != object {
			continue;
		}
		let transaction = transactions[index];
		future |= transaction > view;
		earlier_live |= transaction < view && !deleted[index];
		if transaction <= view && visible.is_none_or(|(prior, _, _)| prior < transaction) {
			visible = Some((transaction, index, deleted[index]));
		}
	}
	let expected = visible
		.filter(|&(_, _, deleted)| !deleted)
		.map(|(transaction, index, _)| VirtualMapping {
			id: ObjectId(object),
			transaction: TransactionId(transaction),
			address: address(index),
			size: OBJECT_BYTES,
		});
	assert!(
		actual == expected,
		"leaf lookup must match the newest visible mapping"
	);

	kani::cover!(count == 0 && actual.is_none(), "empty leaf");
	kani::cover!(
		count == MAX_RECORDS && future && actual.is_some(),
		"eight keys with a future version"
	);
	kani::cover!(
		future && visible.is_none(),
		"only future versions for the requested OID"
	);
	kani::cover!(
		earlier_live && visible.is_some_and(|(_, _, deleted)| deleted) && actual.is_none(),
		"visible tombstone suppresses an older live version"
	);
	kani::cover!(
		view == u64::MAX
			&& actual.is_some_and(|mapping| mapping.transaction == TransactionId(u64::MAX)),
		"inclusive lookup at the maximum XID"
	);
}

fn key(id: u64, transaction: u64) -> Key {
	Key {
		id: ObjectId(id),
		transaction: TransactionId(transaction),
	}
}

fn address(index: usize) -> BlockAddress {
	BlockAddress(index as u64 + 1)
}
