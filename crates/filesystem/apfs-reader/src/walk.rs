extern crate alloc;

use alloc::vec::Vec;

use apfs_container::{VirtualType, VolumeObjects};
use apfs_core::ReadAt;
use apfs_format::{object::ObjectId, superblock::Geometry};

use crate::{
	Corruption, Error, Limit, TreeLimits,
	node::{
		BTREE_NODE_KIND, BTREE_ROOT_KIND, FILESYSTEM_SUBTYPE, Node, Slot, TreeInfo, TreeKind,
		child_id,
	},
	record::Prefix,
	volume::MAX_TREE_DEPTH,
};

const ROOT_DEPTH: u16 = 1;

const ROOT_TYPE: VirtualType = VirtualType {
	kind: BTREE_ROOT_KIND,
	subtype: FILESYSTEM_SUBTYPE,
};
const CHILD_TYPE: VirtualType = VirtualType {
	kind: BTREE_NODE_KIND,
	subtype: FILESYSTEM_SUBTYPE,
};

pub(crate) fn scan<S: ReadAt>(
	objects: &mut VolumeObjects<'_, S>,
	geometry: Geometry,
	target: Prefix,
	limits: TreeLimits,
	visit: impl FnMut(Slot<'_>) -> Result<(), Error<S::Error>>,
) -> Result<(), Error<S::Error>> {
	let root = objects.volume().superblock.trees.root;
	let mut search = Search {
		objects,
		geometry,
		target,
		nodes: Vec::new(),
		limits,
		records_left: limits.max_records,
		visit,
	};
	search.node(root, ROOT_DEPTH, None)
}

struct Search<'query, 'source, S, F> {
	objects: &'query mut VolumeObjects<'source, S>,
	geometry: Geometry,
	target: Prefix,
	nodes: Vec<ObjectId>,
	limits: TreeLimits,
	records_left: u32,
	visit: F,
}

#[derive(Clone, Copy)]
struct Route<'parent> {
	info: TreeInfo,
	level: u16,
	key: &'parent [u8],
	upper: Option<Prefix>,
}

impl<S, F> Search<'_, '_, S, F>
where
	S: ReadAt,
	F: FnMut(Slot<'_>) -> Result<(), Error<S::Error>>,
{
	fn node(
		&mut self,
		id: ObjectId,
		depth: u16,
		route: Option<Route<'_>>,
	) -> Result<(), Error<S::Error>> {
		let depth_limit = self.limits.max_depth.min(MAX_TREE_DEPTH);
		if depth > depth_limit {
			return Err(Error::Limit(Limit::Depth));
		}
		if self.nodes.contains(&id) {
			return Err(Corruption::ReusedNode(id).into());
		}
		if self.nodes.len() >= usize::from(self.limits.max_nodes) {
			return Err(Error::Limit(Limit::Nodes));
		}
		self.nodes.try_reserve(1).map_err(|_| Error::Allocation)?;
		self.nodes.push(id);

		let expected = if route.is_some() {
			CHILD_TYPE
		} else {
			ROOT_TYPE
		};
		let object = self
			.objects
			.read_virtual_object(id, expected)?
			.ok_or(Corruption::MissingNode(id))?;
		let node = Node::decode(
			object.as_bytes(),
			object.header,
			self.geometry,
			route.map(|route| route.info),
			TreeKind::Filesystem,
		)?;
		if u32::from(depth) + u32::from(node.level) > u32::from(depth_limit) {
			return Err(Error::Limit(Limit::Depth));
		}
		if self.nodes.len() as u64 > node.info().nodes {
			return Err(Corruption::Route.into());
		}
		let records = u32::try_from(node.len()).map_err(|_| Error::Limit(Limit::Records))?;
		self.records_left = self
			.records_left
			.checked_sub(records)
			.ok_or(Error::Limit(Limit::Records))?;
		node.validate()?;
		if let Some(route) = route {
			let last = node.prefix(node.len() - 1)?;
			if node.level != route.level
				|| node.slot(0)?.key != route.key
				|| route.upper.is_some_and(|upper| last > upper)
			{
				return Err(Corruption::Route.into());
			}
		}

		if node.level == 0 {
			for index in 0..node.len() {
				let slot = node.slot(index)?;
				if Prefix::decode(slot.key)? == self.target {
					(self.visit)(slot)?;
				}
			}
			return Ok(());
		}

		for index in 0..node.len() {
			let slot = node.slot(index)?;
			if Prefix::decode(slot.key)? > self.target {
				break;
			}
			let upper = if index + 1 < node.len() {
				Some(node.prefix(index + 1)?)
			} else {
				route.and_then(|route| route.upper)
			};
			if upper.is_some_and(|key| key < self.target) {
				continue;
			}
			let child = Route {
				info: node.info(),
				level: node.level - 1,
				key: slot.key,
				upper,
			};
			self.node(child_id(slot.value)?, depth + 1, Some(child))?;
		}
		Ok(())
	}
}
