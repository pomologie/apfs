use super::{Error, Header, ObjectId, TransactionId};

// Independent field boundaries from the standard object header wire layout.
const CHECKSUM_END: usize = 8;
const OBJECT_ID_END: usize = 16;
const TRANSACTION_END: usize = 24;
const TYPE_END: usize = 28;
const HEADER_END: usize = 32;

#[kani::proof]
fn object_header_fields_match_wire_layout() {
	let expected = Header {
		checksum: kani::any(),
		id: ObjectId(kani::any()),
		transaction: TransactionId(kani::any()),
		object_type: kani::any(),
		subtype: kani::any(),
	};
	let wire = encode(expected);
	let len = kani::any::<usize>();
	kani::assume(len <= wire.len());
	let object = &wire[..len];
	let expected_type = if len < TYPE_END {
		Err(Error::Truncated)
	} else {
		Ok(expected.object_type)
	};
	let expected_header = if len < HEADER_END {
		Err(Error::Truncated)
	} else {
		Ok(expected)
	};
	assert!(Header::type_hint(object) == expected_type);
	assert!(Header::decode_fields(object) == expected_header);
	kani::cover!(len == TYPE_END - 1, "truncated type field");
	kani::cover!(len == TYPE_END, "complete type field and missing subtype");
	kani::cover!(len == HEADER_END - 1, "truncated subtype");
	kani::cover!(len == HEADER_END, "complete header");
}

fn encode(header: Header) -> [u8; HEADER_END] {
	let mut wire = [0; HEADER_END];
	wire[..CHECKSUM_END].copy_from_slice(&header.checksum.to_le_bytes());
	wire[CHECKSUM_END..OBJECT_ID_END].copy_from_slice(&header.id.0.to_le_bytes());
	wire[OBJECT_ID_END..TRANSACTION_END].copy_from_slice(&header.transaction.0.to_le_bytes());
	wire[TRANSACTION_END..TYPE_END].copy_from_slice(&header.object_type.to_le_bytes());
	wire[TYPE_END..].copy_from_slice(&header.subtype.to_le_bytes());
	wire
}
