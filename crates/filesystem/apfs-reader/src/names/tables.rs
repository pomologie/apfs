//! Layout of the generated, immutable Unicode 9 name data.

const SCALAR_BYTES: usize = size_of::<u32>();
const CLASS_BYTES: usize = size_of::<u8>();
const RANGE_BYTES: usize = 2 * SCALAR_BYTES;
const CLASS_RECORD_BYTES: usize = SCALAR_BYTES + CLASS_BYTES;
const MAPPING_SCALARS: usize = 3;
const MAPPING_RECORD_BYTES: usize = (1 + MAPPING_SCALARS) * SCALAR_BYTES;
const ABSENT_MAPPING_SCALAR: u32 = 0;

const ASSIGNED: &[[u8; RANGE_BYTES]] = records(include_bytes!("data/age.bin"));
const CLASSES: &[[u8; CLASS_RECORD_BYTES]] = records(include_bytes!("data/combining.bin"));
const DECOMPOSITION: &[[u8; MAPPING_RECORD_BYTES]] =
	records(include_bytes!("data/decomposition.bin"));
const CASEFOLD: &[[u8; MAPPING_RECORD_BYTES]] = records(include_bytes!("data/casefold.bin"));

pub(super) const STARTER_CLASS: u8 = 0;
pub(super) const MAX_FOLD_SCALARS: usize = MAPPING_SCALARS;

pub(super) fn assigned(scalar: char) -> bool {
	let scalar = u32::from(scalar);
	let end = ASSIGNED.partition_point(|range| read_scalar(range, 0) <= scalar);
	end.checked_sub(1)
		.is_some_and(|index| scalar <= read_scalar(&ASSIGNED[index], SCALAR_BYTES))
}

pub(super) fn combining_class(scalar: char) -> u8 {
	lookup(CLASSES, scalar).map_or(STARTER_CLASS, |record| record[SCALAR_BYTES])
}

pub(super) fn decomposition(scalar: char) -> Option<impl Iterator<Item = u32>> {
	mapping(DECOMPOSITION, scalar)
}

pub(super) fn full_fold(scalar: char) -> Option<impl Iterator<Item = u32>> {
	mapping(CASEFOLD, scalar)
}

fn mapping(data: &[[u8; MAPPING_RECORD_BYTES]], scalar: char) -> Option<impl Iterator<Item = u32>> {
	let record = lookup(data, scalar)?;
	let scalars: [u32; MAPPING_SCALARS] =
		core::array::from_fn(|index| read_scalar(record, (index + 1) * SCALAR_BYTES));
	Some(
		scalars
			.into_iter()
			.take_while(|&scalar| scalar != ABSENT_MAPPING_SCALAR),
	)
}

fn lookup<const WIDTH: usize>(data: &[[u8; WIDTH]], scalar: char) -> Option<&[u8; WIDTH]> {
	data.binary_search_by_key(&u32::from(scalar), |record| read_scalar(record, 0))
		.ok()
		.map(|index| &data[index])
}

fn read_scalar(record: &[u8], offset: usize) -> u32 {
	// Every call uses a fixed field of a width-checked generated record.
	u32::from_le_bytes(core::array::from_fn(|index| record[offset + index]))
}

const fn records<const WIDTH: usize>(bytes: &[u8]) -> &[[u8; WIDTH]] {
	let (records, remainder) = bytes.as_chunks::<WIDTH>();
	assert!(remainder.is_empty(), "partial APFS Unicode table record");
	records
}
