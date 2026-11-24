use alloc::vec::Vec;
use core::ops::Range;

use apfs_core::{ByteOffset, ReadAt};
use apfs_format::{
	object::{Header, ObjectId, TransactionId},
	object_map::{Key, Mapping, Node, ObjectMap, Record, Value},
	superblock::{Area, AreaLocation, BlockAddress},
};

use crate::{BLOCK_ZERO, Container, Error, Limit, ObjectMapError, OpenOptions, Probe, push};

mod volume;

use volume::VolumeMap;
pub use volume::VolumeObjects;

const INVALID_TRANSACTION: TransactionId = TransactionId(0);
const DEFAULT_MAX_NODES: u16 = 16;

/// Admission budgets for object and volume lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupOptions {
	/// Maximum B-tree nodes to visit on one path, including the root.
	pub max_nodes: u16,
	/// Maximum bytes in a single object or node.
	pub max_object_bytes: usize,
	/// Sum of bytes read by the operation, including all paths in volume enumeration.
	pub max_read_bytes: u64,
}

impl Default for LookupOptions {
	fn default() -> Self {
		Self {
			max_nodes: DEFAULT_MAX_NODES,
			max_object_bytes: crate::DEFAULT_MAX_OBJECT_BYTES,
			max_read_bytes: crate::DEFAULT_MAX_READ_BYTES,
		}
	}
}

/// A mapping in the namespace used to look it up, valid at the requested transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct VirtualMapping {
	/// Virtual object ID.
	pub id: ObjectId,
	/// Transaction which introduced this mapping.
	pub transaction: TransactionId,
	/// Starting physical block of the object.
	pub address: BlockAddress,
	/// Size of the complete checksummed object.
	pub size: u32,
}

/// A caller's expected kind and subtype for a standard virtual object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualType {
	/// Object kind, excluding flags and storage class.
	pub kind: u16,
	/// Type-specific subtype.
	pub subtype: u32,
}

/// Checked contents of an object in the selected container view.
#[derive(Debug)]
pub struct VirtualObject {
	/// Verified mapping into the container.
	pub mapping: VirtualMapping,
	/// Checksummed header with matching ID, XID and type.
	pub header: Header,
	bytes: Vec<u8>,
}

impl VirtualObject {
	/// Complete verified APFS object bytes.
	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		&self.bytes
	}
}

impl<S: ReadAt> Container<S> {
	/// Finds the newest container-namespace mapping for this OID at or before
	/// `transaction`. Absence includes a visible tombstone. Results describe
	/// the selected checkpoint's map and do not establish snapshot consistency.
	///
	/// # Errors
	/// Rejects transactions outside this view, unsupported maps, corrupt nodes,
	/// unsafe ranges, exhausted limits, and positional read failures.
	pub fn lookup_virtual_mapping(
		&self,
		id: ObjectId,
		transaction: TransactionId,
		options: LookupOptions,
	) -> Result<Option<VirtualMapping>, Error<S::Error>> {
		let mut lookup = Lookup::new(self, options);
		lookup.mapping(Key { id, transaction }, &mut Vec::new())
	}

	/// Resolves and checksums an object in the selected container namespace.
	/// Its header must match the mapping ID and XID and the requested virtual
	/// kind and subtype. Returns `None` for absent or deleted objects.
	///
	/// # Errors
	/// Returns mapping errors or a failed check of the mapped object's bytes,
	/// ID, XID, kind, subtype, or storage class.
	pub fn read_virtual_object(
		&self,
		id: ObjectId,
		expected: VirtualType,
		options: LookupOptions,
	) -> Result<Option<VirtualObject>, Error<S::Error>> {
		Lookup::new(self, options).read_virtual_object(id, expected)
	}
}

pub(super) struct Lookup<'source, S> {
	container: &'source Container<S>,
	probe: Probe<'source, S>,
	max_nodes: u16,
	volume_map: Option<VolumeMap>,
}

impl<'source, S: ReadAt> Lookup<'source, S> {
	pub(super) fn new(container: &'source Container<S>, options: LookupOptions) -> Self {
		Self {
			container,
			probe: Probe {
				source: container.source(),
				options: OpenOptions {
					max_object_bytes: options.max_object_bytes,
					..OpenOptions::default()
				},
				bytes_left: options.max_read_bytes,
			},
			max_nodes: options.max_nodes,
			volume_map: None,
		}
	}

	pub(super) fn read_virtual_object(
		&mut self,
		id: ObjectId,
		expected: VirtualType,
	) -> Result<Option<VirtualObject>, Error<S::Error>> {
		let mut bytes = Vec::new();
		let checkpoint = self.container.superblock();
		let key = Key {
			id,
			transaction: checkpoint.object.transaction,
		};
		let Some(mapping) = self.mapping(key, &mut bytes)? else {
			return Ok(None);
		};
		let blocks = u64::from(mapping.size / checkpoint.geometry.block_bytes());
		self.read(mapping.address, blocks, &mut bytes)?;
		let header =
			Header::decode(&bytes).map_err(|error| format_error(mapping.address, error))?;
		if header.id != id || header.transaction != mapping.transaction {
			return Err(map_error(mapping.address, ObjectMapError::Identity));
		}
		if header.object_type != u32::from(expected.kind) || header.subtype != expected.subtype {
			return Err(format_error(
				mapping.address,
				apfs_format::Error::UnexpectedObjectType(header.object_type),
			));
		}
		Ok(Some(VirtualObject {
			mapping,
			header,
			bytes,
		}))
	}
	fn mapping(
		&mut self,
		key: Key,
		bytes: &mut Vec<u8>,
	) -> Result<Option<VirtualMapping>, Error<S::Error>> {
		let checkpoint = self.container.superblock();
		let map_address = self
			.volume_map
			.map_or(checkpoint.object_map, |volume| volume.address);
		if key.transaction == INVALID_TRANSACTION || key.transaction > checkpoint.object.transaction
		{
			return Err(map_error(
				map_address,
				ObjectMapError::Transaction(key.transaction),
			));
		}
		let map = if let Some(volume) = self.volume_map {
			volume.map
		} else {
			self.read(map_address, 1, bytes)?;
			let map = ObjectMap::decode(bytes, checkpoint.geometry)
				.map_err(|error| format_error(map_address, error))?;
			verify_physical_header(map_address, map.header, checkpoint.object.transaction)?;
			map
		};

		let mut address = map.root;
		let mut upper_transaction = map.header.transaction;
		let mut route = None;
		let mut visited = Vec::new();
		loop {
			if visited.contains(&address) || address == map_address {
				return Err(map_error(address, ObjectMapError::Cycle));
			}
			if visited.len() >= usize::from(self.max_nodes) {
				return Err(Error::Limit(Limit::ObjectMapNodes));
			}
			push(&mut visited, address)?;
			self.read(address, 1, bytes)?;
			let node = Node::decode(bytes, checkpoint.geometry, route.is_none())
				.map_err(|error| format_error(address, error))?;
			verify_physical_header(address, node.header(), upper_transaction)?;
			if let Some(expected) = route {
				validate_route(address, &node, expected)?;
			}
			let Some((index, record)) =
				predecessor(&node, key).map_err(|error| format_error(address, error))?
			else {
				return Ok(None);
			};
			match record.value {
				Value::Child(child) => {
					let upper_key = if index + 1 < node.len() {
						let next = node
							.record(index + 1)
							.map_err(|error| format_error(address, error))?;
						Some(next.key)
					} else {
						route.and_then(|expected| expected.upper_key)
					};
					route = Some(Route {
						level: node.level() - 1,
						lower_key: record.key,
						upper_key,
					});
					address = child;
					upper_transaction = node.header().transaction;
				}
				Value::Mapping(Mapping::Object { address, size }) if key.id == record.key.id => {
					let blocks = u64::from(size / checkpoint.geometry.block_bytes());
					self.validate_range(address, blocks)?;
					if address_contains(address, blocks, map_address)
						|| visited
							.iter()
							.any(|node| address_contains(address, blocks, *node))
					{
						return Err(map_error(address, ObjectMapError::Address));
					}
					return Ok(Some(VirtualMapping {
						id: record.key.id,
						transaction: record.key.transaction,
						address,
						size,
					}));
				}
				Value::Mapping(_) => return Ok(None),
			}
		}
	}

	pub(super) fn validate_range(
		&self,
		address: BlockAddress,
		blocks: u64,
	) -> Result<Range<u64>, Error<S::Error>> {
		let checkpoint = self.container.superblock();
		let range = checkpoint
			.geometry
			.byte_range(address, blocks)
			.map_err(|error| format_error(address, error))?;
		if address == BLOCK_ZERO
			|| overlaps_area(address, blocks, checkpoint.descriptors)
			|| overlaps_area(address, blocks, checkpoint.data)
			|| self
				.volume_map
				.is_some_and(|volume| volume.overlaps_protected(address, blocks))
		{
			return Err(map_error(address, ObjectMapError::Address));
		}
		Ok(range)
	}

	fn read(
		&mut self,
		address: BlockAddress,
		blocks: u64,
		bytes: &mut Vec<u8>,
	) -> Result<(), Error<S::Error>> {
		let range = self.validate_range(address, blocks)?;
		let size = usize::try_from(range.end - range.start)
			.map_err(|_| Error::Limit(Limit::ObjectBytes))?;
		self.probe.buffer(size, bytes)?;
		self.probe.read_exact(ByteOffset(range.start), bytes)
	}
}

fn address_contains(start: BlockAddress, blocks: u64, target: BlockAddress) -> bool {
	// The caller established the geometry before comparing addresses.
	start.0 <= target.0 && target.0 < start.0 + blocks
}

#[derive(Clone, Copy)]
struct Route {
	level: u16,
	lower_key: Key,
	upper_key: Option<Key>,
}

fn validate_route<E>(
	address: BlockAddress,
	node: &Node<'_>,
	expected: Route,
) -> Result<(), Error<E>> {
	if node.level() != expected.level || node.is_empty() {
		return Err(map_error(address, ObjectMapError::Routing));
	}
	let first = node
		.record(0)
		.map_err(|error| format_error(address, error))?;
	let last = node
		.record(node.len() - 1)
		.map_err(|error| format_error(address, error))?;
	if first.key != expected.lower_key || expected.upper_key.is_some_and(|end| last.key >= end) {
		return Err(map_error(address, ObjectMapError::Routing));
	}
	Ok(())
}

fn predecessor(node: &Node<'_>, key: Key) -> Result<Option<(usize, Record)>, apfs_format::Error> {
	let (mut start, mut end) = (0, node.len());
	while start < end {
		let middle = start + (end - start) / 2;
		if node.record(middle)?.key <= key {
			start = middle + 1;
		} else {
			end = middle;
		}
	}
	start
		.checked_sub(1)
		.map(|index| node.record(index).map(|record| (index, record)))
		.transpose()
}

fn verify_physical_header<E>(
	address: BlockAddress,
	header: Header,
	maximum: TransactionId,
) -> Result<(), Error<E>> {
	if header.id != ObjectId(address.0)
		|| header.transaction == INVALID_TRANSACTION
		|| header.transaction > maximum
	{
		return Err(map_error(address, ObjectMapError::Identity));
	}
	Ok(())
}

fn overlaps_area(address: BlockAddress, blocks: u64, area: Area) -> bool {
	let AreaLocation::Contiguous(base) = area.location else {
		// Container admission already rejects fragmented areas.
		return true;
	};
	// Geometry admission bounded both end addresses.
	address.0 < base.0 + u64::from(area.blocks) && base.0 < address.0 + blocks
}

fn format_error<E>(address: BlockAddress, error: apfs_format::Error) -> Error<E> {
	map_error(address, ObjectMapError::Format(error))
}

fn map_error<E>(address: BlockAddress, reason: ObjectMapError) -> Error<E> {
	Error::ObjectMap { address, reason }
}
