pub(crate) extern crate alloc;

use alloc::vec::Vec;

use crate::Error;

pub(super) fn push<T, E>(list: &mut Vec<T>, item: T) -> Result<(), Error<E>> {
	list.try_reserve(1).map_err(|_| Error::Allocation)?;
	list.push(item);
	Ok(())
}
