use core::mem::size_of;

use crate::Corruption;

pub(crate) fn bytes(data: &[u8], offset: usize, len: usize) -> Result<&[u8], Corruption> {
	data.get(offset..offset.checked_add(len).ok_or(Corruption::Truncated)?)
		.ok_or(Corruption::Truncated)
}

pub(crate) fn field<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], Corruption> {
	bytes(data, offset, N)?
		.try_into()
		.map_err(|_| Corruption::Truncated)
}

pub(crate) fn u16_at(data: &[u8], offset: usize) -> Result<u16, Corruption> {
	Ok(u16::from_le_bytes(field(data, offset)?))
}

pub(crate) fn u32_at(data: &[u8], offset: usize) -> Result<u32, Corruption> {
	Ok(u32::from_le_bytes(field(data, offset)?))
}

pub(crate) fn u64_at(data: &[u8], offset: usize) -> Result<u64, Corruption> {
	Ok(u64::from_le_bytes(field(data, offset)?))
}

pub(crate) const U16_BYTES: usize = size_of::<u16>();
pub(crate) const U64_BYTES: usize = size_of::<u64>();
