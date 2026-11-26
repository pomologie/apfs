//! Read-only inspection of an existing private stage under a fresh lease.

use crate::{
	EventHandle,
	identity::ObjectIdentity,
	lease::Lease,
	metadata::{ExtendedSecurity, MetadataView, ObservationError, extended_security},
	publication::EventEntry,
	source::{PinnedSource, SourceError, SourceMetadata},
};

/// Native observations available before a stage is opened for data.
pub struct StageAdmission<'entry> {
	identity: &'entry ObjectIdentity,
	metadata: SourceMetadata,
	event: &'entry EventHandle,
}

impl StageAdmission<'_> {
	/// Native identity observed from the selected name and event anchor.
	#[must_use]
	pub const fn identity(&self) -> &ObjectIdentity {
		self.identity
	}

	/// Native metadata observed before opening the file for data.
	#[must_use]
	pub const fn metadata(&self) -> SourceMetadata {
		self.metadata
	}

	/// Query extended security and ACL evidence through the event-only anchor.
	/// # Errors
	/// Returns the observation errors of [`extended_security`].
	pub fn extended_security(
		&self,
		max_bytes: usize,
	) -> Result<ExtendedSecurity, ObservationError> {
		extended_security(self.event, max_bytes)
	}
}

/// Independently opened stage data tied to a fresh event anchor and directory lease.
///
/// This reader supplies live observations for reconciliation. It carries no
/// evidence of checked writer closure or synchronization and provides no
/// mutation or publication methods.
pub struct ReopenedStage<'scope>(PinnedSource<'scope>);

impl<'scope> ReopenedStage<'scope> {
	/// Open an existing stage read-only after matching its anchor, exact stored
	/// name and expected length under the supplied lease.
	///
	/// The caller authorizes the directory and protects its ancestry. Compare
	/// the supplied native identity with all accepted recorded fields in
	/// `admit` and enforce the caller's owner, mode, flags and metadata profile
	/// there. The callback can query ACL evidence through the event-only handle.
	/// The companion requires a materialized, single-link regular file on the
	/// directory's mount. It disables materialization before observation and
	/// keeps the policy in effect through admission and the data open.
	///
	/// # Errors
	/// Reports missing, changed, unsupported, and unavailable observations
	/// separately, along with lease and thread policy failures. An admission
	/// error prevents the data open.
	pub fn open(
		anchor: &'scope EventEntry<'scope>,
		lease: &'scope Lease,
		expected_length: u64,
		admit: impl FnOnce(StageAdmission<'_>) -> Result<(), SourceError>,
	) -> Result<Self, SourceError> {
		let source = PinnedSource::open_anchored(anchor, lease, |identity, metadata| {
			if metadata.length != expected_length {
				return Err(SourceError::Changed);
			}
			let flags = metadata.object_flags();
			if metadata.link_count != 1 || flags.is_dataless() || flags.is_firmlink() {
				return Err(SourceError::Unsupported);
			}
			admit(StageAdmission {
				identity,
				metadata,
				event: anchor.handle(),
			})
		})?;
		Ok(Self(source))
	}

	/// Returns the initial native metadata, including pre-open access time.
	#[must_use]
	pub const fn initial_metadata(&self) -> SourceMetadata {
		self.0.metadata()
	}

	/// Query bounded metadata through the read-only data descriptor.
	///
	/// Access time is live and may advance during reads.
	///
	/// # Errors
	/// Reports observation, lease, identity, or materialization policy failures.
	pub fn with_metadata<T>(
		&self,
		observe: impl FnOnce(MetadataView<'_>) -> Result<T, ObservationError>,
	) -> Result<T, SourceError> {
		self.0.with_metadata(observe)
	}

	/// Read the exact range, bounded by the admitted length and the companion's
	/// single-request limit.
	///
	/// # Errors
	/// Reports range, short-read, I/O, observation, or thread policy failures.
	/// Discard the buffer after any error.
	pub fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), SourceError> {
		self.0.read_exact_at(offset, buffer)
	}

	/// Revalidate live state and probe for EOF at the expected length.
	///
	/// # Errors
	/// Reports changed or unavailable evidence, unexpected bytes beyond the
	/// expected length, and I/O or materialization policy failures.
	pub fn confirm_eof(&self) -> Result<(), SourceError> {
		self.0.revalidate()
	}
}
