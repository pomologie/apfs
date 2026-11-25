extern crate alloc;

use alloc::vec::Vec;
use core::ops::Range;

use apfs_container::VolumeObjects;
use apfs_core::{ByteOffset, ReadAt};
use apfs_format::{
	object::{Header, ObjectId, TransactionId},
	superblock::{BlockAddress, Geometry},
};

use crate::{
	Corruption, Error, Limit, TreeLimits, Unsupported,
	node::{Node, Slot, TreeInfo, TreeKind, child_id},
	volume::MAX_TREE_DEPTH,
	wire::{U64_BYTES, u32_at, u64_at},
};

const RECORD_KIND_SHIFT: u32 = 60;
const RECORD_ID_MASK: u64 = (1 << RECORD_KIND_SHIFT) - 1;
const PHYSICAL_EXTENT_RECORD: u64 = 2;
const EXTENT_KIND_NEW: u8 = 1;
const EXTENT_REFERENCE_BYTES: usize = 20;
const EXTENT_OWNER_OFFSET: usize = 8;
const EXTENT_REFCNT_OFFSET: usize = 16;
const UNSHARED_REFERENCE_COUNT: u32 = 1;
const ROOT_DEPTH: u16 = 1;

pub(crate) struct References<'view, 'source, S> {
	objects: &'view mut VolumeObjects<'source, S>,
	geometry: Geometry,
	depth_limit: u16,
	nodes_left: u16,
	records_left: u32,
	buffer: Vec<u8>,
}

#[derive(Clone, Copy)]
struct Route {
	info: TreeInfo,
	level: u16,
	lower: u64,
	upper: Option<u64>,
}

struct PhysicalExtent {
	end: u64,
	owner: ObjectId,
	count: u32,
	kind: u8,
}

impl<'view, 'source, S: ReadAt> References<'view, 'source, S> {
	pub(crate) fn new(
		objects: &'view mut VolumeObjects<'source, S>,
		geometry: Geometry,
		limits: TreeLimits,
	) -> Self {
		Self {
			objects,
			geometry,
			depth_limit: limits.max_depth.min(MAX_TREE_DEPTH),
			nodes_left: limits.max_nodes,
			records_left: limits.max_records,
			buffer: Vec::new(),
		}
	}

	pub(crate) fn verify(
		&mut self,
		blocks: Range<u64>,
		owner: ObjectId,
	) -> Result<(), Error<S::Error>> {
		let mut position = blocks.start;
		while position < blocks.end {
			let Some(reference) = self.covering(position)? else {
				return Err(Corruption::ExtentReference.into());
			};
			if reference.kind != EXTENT_KIND_NEW {
				return Err(Unsupported::ExtentReferenceKind(reference.kind).into());
			}
			if reference.count > UNSHARED_REFERENCE_COUNT {
				return Err(Unsupported::SharedData.into());
			}
			if reference.owner != owner {
				return Err(Corruption::ExtentReference.into());
			}
			position = reference.end;
		}
		Ok(())
	}

	fn covering(&mut self, target: u64) -> Result<Option<PhysicalExtent>, Error<S::Error>> {
		let metadata = &self.objects.volume().superblock;
		let mut address = metadata.trees.extent_references;
		let mut maximum_xid = metadata.object.transaction;
		let mut route = None;
		let mut visited = [BlockAddress(0); MAX_TREE_DEPTH as usize];
		for depth in ROOT_DEPTH..=self.depth_limit {
			let previous_depth = usize::from(depth - ROOT_DEPTH);
			if visited[..previous_depth].contains(&address) {
				return Err(Corruption::ReusedNode(ObjectId(address.0)).into());
			}
			visited[previous_depth] = address;
			self.read_node(address)?;
			let header = Header::decode(&self.buffer).map_err(Corruption::PhysicalNode)?;
			if header.id != ObjectId(address.0)
				|| header.transaction == TransactionId(0)
				|| header.transaction > maximum_xid
			{
				return Err(Corruption::ExtentReference.into());
			}

			let node = Node::decode(
				&self.buffer,
				header,
				self.geometry,
				route.map(|bound: Route| bound.info),
				TreeKind::ExtentReferences,
			)?;
			let end_depth = u32::from(depth) + u32::from(node.level);
			if end_depth > u32::from(self.depth_limit) {
				return Err(Error::Limit(Limit::Depth));
			}
			if u64::from(depth) > node.info().nodes {
				return Err(Corruption::Route.into());
			}
			let count = u32::try_from(node.len()).map_err(|_| Error::Limit(Limit::Records))?;
			self.records_left = self
				.records_left
				.checked_sub(count)
				.ok_or(Error::Limit(Limit::Records))?;
			node.validate()?;

			let upper = route.and_then(|bound| bound.upper);
			if let Some(parent) = route
				&& (node.level != parent.level
					|| record_address(node.slot(0)?.key)? != parent.lower)
			{
				return Err(Corruption::Route.into());
			}
			if node.level == 0 {
				return covering_leaf(&node, self.geometry, target, upper).map_err(Into::into);
			}
			let mut selected = None;
			let mut previous = None;
			for index in 0..node.len() {
				let slot = node.slot(index)?;
				let start = record_address(slot.key)?;
				if previous.is_some_and(|prior| start <= prior)
					|| upper.is_some_and(|upper| start >= upper)
				{
					return Err(Corruption::Route.into());
				}
				previous = Some(start);
				if start <= target {
					selected = Some((BlockAddress(child_id(slot.value)?.0), start, upper));
				} else if let Some(selected) = &mut selected
					&& selected.2 == upper
				{
					selected.2 = Some(start);
				}
			}
			let Some((child, lower, upper)) = selected else {
				return Ok(None);
			};
			address = child;
			route = Some(Route {
				info: node.info(),
				level: node.level - 1,
				lower,
				upper,
			});
			maximum_xid = header.transaction;
		}
		Err(Error::Limit(Limit::Depth))
	}

	fn read_node(&mut self, address: BlockAddress) -> Result<(), Error<S::Error>> {
		self.nodes_left = self
			.nodes_left
			.checked_sub(1)
			.ok_or(Error::Limit(Limit::Nodes))?;
		if address.0 == 0 {
			return Err(Corruption::ExtentReference.into());
		}
		let region = self
			.geometry
			.byte_range(address, 1)
			.map_err(Corruption::PhysicalNode)?;
		let bytes = self.geometry.block_bytes() as usize;
		if self.buffer.is_empty() {
			self.buffer
				.try_reserve_exact(bytes)
				.map_err(|_| Error::Allocation)?;
			self.buffer.resize(bytes, 0);
		}
		Ok(self
			.objects
			.read_physical_at(ByteOffset(region.start), &mut self.buffer)?)
	}
}

fn covering_leaf(
	node: &Node<'_>,
	geometry: Geometry,
	target: u64,
	upper: Option<u64>,
) -> Result<Option<PhysicalExtent>, Corruption> {
	let mut found = None;
	let mut previous_end = 0;
	for index in 0..node.len() {
		let slot = node.slot(index)?;
		let start = record_address(slot.key)?;
		let reference = extent(start, slot, geometry)?;
		if start < previous_end || upper.is_some_and(|bound| reference.end > bound) {
			return Err(Corruption::ExtentReference);
		}
		previous_end = reference.end;
		if (start..reference.end).contains(&target) {
			found = Some(reference);
		}
	}
	Ok(found)
}

fn record_address(key: &[u8]) -> Result<u64, Corruption> {
	let key_word = u64_at(key, 0)?;
	let address = key_word & RECORD_ID_MASK;
	if key.len() != U64_BYTES
		|| key_word >> RECORD_KIND_SHIFT != PHYSICAL_EXTENT_RECORD
		|| address == 0
	{
		return Err(Corruption::ExtentReference);
	}
	Ok(address)
}

fn extent(start: u64, slot: Slot<'_>, geometry: Geometry) -> Result<PhysicalExtent, Corruption> {
	if slot.value.len() != EXTENT_REFERENCE_BYTES {
		return Err(Corruption::ExtentReference);
	}
	let length_kind = u64_at(slot.value, 0)?;
	let kind = (length_kind >> RECORD_KIND_SHIFT) as u8;
	let length = length_kind & RECORD_ID_MASK;
	let count = u32_at(slot.value, EXTENT_REFCNT_OFFSET)?;
	if length == 0 || i32::try_from(count).is_err() || count == 0 {
		return Err(Corruption::ExtentReference);
	}
	geometry
		.byte_range(BlockAddress(start), length)
		.map_err(Corruption::PhysicalNode)?;
	Ok(PhysicalExtent {
		end: start + length,
		owner: ObjectId(u64_at(slot.value, EXTENT_OWNER_OFFSET)?),
		count,
		kind,
	})
}
