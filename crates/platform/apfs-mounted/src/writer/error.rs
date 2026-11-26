use std::{error::Error, fmt, io};

use crate::{
	dataless::{ContentError, PolicyError, ScopeError, with_materialization_disabled},
	identity::IdentityError,
	metadata::{ApplyError, ObjectFlags, ObservationError},
};

use super::BarrierError;

/// Successful outcome observed before materialization scope restoration failed.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum LifecycleEffect {
	Created,
	Written { end: u64 },
	Closed,
	TimesApplied,
	Observed,
	Read,
}

/// Failure during private creation, transfer, independent read-back, or close.
#[derive(Debug)]
#[non_exhaustive]
pub enum WriterError {
	InvalidRange,
	Incomplete,
	Occupied,
	CreateUncertain(io::Error),
	CreatedButUnverified(Box<Self>),
	/// The full-file barrier returned success before live revalidation failed.
	/// A checked close has yet to be confirmed.
	BarrierPassedButUnverified(Box<Self>),
	ClosedButUnverified(Box<Self>),
	TimesAppliedButUnverified(Box<Self>),
	/// The caller required zero initial flags and the created entry had flags set.
	UnexpectedInitialFlags {
		actual: ObjectFlags,
	},
	Changed,
	NotPrivate,
	WrongProcess,
	Retired,
	Write(io::Error),
	Read(ContentError),
	UnexpectedEnd,
	UnexpectedDataAfterEnd,
	Barrier(BarrierError),
	Close(io::Error),
	Times(ApplyError),
	TimesMismatch,
	Identity(IdentityError),
	Metadata(ObservationError),
	/// The caller rejected metadata or another policy prerequisite in a scoped check.
	MetadataRefused(Box<dyn Error + Send + Sync>),
	Io(io::Error),
	Configure {
		error: PolicyError,
		restoration: Option<PolicyError>,
	},
	Restore {
		error: PolicyError,
		outcome: Result<LifecycleEffect, Box<Self>>,
	},
}

impl fmt::Display for WriterError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::InvalidRange => f.write_str("private file range is outside the admitted bounds"),
			Self::Incomplete => f.write_str("private file has not reached its declared extent"),
			Self::Occupied => f.write_str("private file name is occupied"),
			Self::CreateUncertain(error) => {
				write!(f, "exclusive creation was not confirmed ({error})")
			}
			Self::CreatedButUnverified(error) => write!(
				f,
				"the created private file could not be verified ({error})"
			),
			Self::BarrierPassedButUnverified(error) => {
				write!(
					f,
					"full-file synchronization succeeded but revalidation failed ({error})"
				)
			}
			Self::ClosedButUnverified(error) => {
				write!(f, "the closed private file could not be verified ({error})")
			}
			Self::TimesAppliedButUnverified(error) => write!(
				f,
				"applied timestamps could not be verified or synchronized ({error})"
			),
			Self::UnexpectedInitialFlags { actual } => {
				write!(
					f,
					"the created private file has BSD flags {:#x}",
					actual.raw()
				)
			}
			Self::Changed => {
				f.write_str("the private file's live name, identity, metadata or extent changed")
			}
			Self::NotPrivate => {
				f.write_str("the entry does not have the required private file attributes")
			}
			Self::WrongProcess => f.write_str("the private file belongs to a different process"),
			Self::Retired => f.write_str("the private writer is retired"),
			Self::Write(error) => write!(f, "positioned write failed ({error})"),
			Self::Read(error) => write!(f, "positioned read-back failed ({error})"),
			Self::UnexpectedEnd => {
				f.write_str("private read-back ended inside the declared extent")
			}
			Self::UnexpectedDataAfterEnd => {
				f.write_str("private read-back found data beyond the declared extent")
			}
			Self::Barrier(error) => fmt::Display::fmt(error, f),
			Self::Close(error) => write!(f, "checked close failed ({error})"),
			Self::Times(error) => write!(f, "timestamp application failed ({error})"),
			Self::TimesMismatch => {
				f.write_str("actual timestamps differ from the application request")
			}
			Self::Identity(error) => fmt::Display::fmt(error, f),
			Self::Metadata(error) => fmt::Display::fmt(error, f),
			Self::MetadataRefused(error) => {
				write!(f, "the caller refused stage metadata ({error})")
			}
			Self::Io(error) => fmt::Display::fmt(error, f),
			Self::Configure { error, restoration } => {
				write!(f, "could not disable materialization ({error})")?;
				if let Some(restoration) = restoration {
					write!(f, ", and policy rollback failed ({restoration})")?;
				}
				Ok(())
			}
			Self::Restore { error, outcome } => match outcome {
				Ok(effect) => write!(
					f,
					"materialization policy restoration failed after {effect:?} ({error})"
				),
				Err(operation) => write!(
					f,
					"materialization policy restoration failed ({error}) after operation error ({operation})"
				),
			},
		}
	}
}

impl Error for WriterError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			Self::CreateUncertain(error)
			| Self::Write(error)
			| Self::Close(error)
			| Self::Io(error) => Some(error),
			Self::CreatedButUnverified(error)
			| Self::BarrierPassedButUnverified(error)
			| Self::ClosedButUnverified(error)
			| Self::TimesAppliedButUnverified(error) => Some(error),
			Self::Read(error) => Some(error),
			Self::Barrier(error) => Some(error),
			Self::Times(error) => Some(error),
			Self::Identity(error) => Some(error),
			Self::Metadata(error) => Some(error),
			Self::MetadataRefused(error) => Some(error.as_ref()),
			Self::Configure { error, .. } | Self::Restore { error, .. } => Some(error),
			_ => None,
		}
	}
}

impl From<io::Error> for WriterError {
	fn from(error: io::Error) -> Self {
		Self::Io(error)
	}
}

impl From<rustix::io::Errno> for WriterError {
	fn from(error: rustix::io::Errno) -> Self {
		Self::Io(error.into())
	}
}

impl From<IdentityError> for WriterError {
	fn from(error: IdentityError) -> Self {
		Self::Identity(error)
	}
}

impl From<ObservationError> for WriterError {
	fn from(error: ObservationError) -> Self {
		Self::Metadata(error)
	}
}

pub(super) fn without_materialization<T>(
	success: LifecycleEffect,
	operation: impl FnOnce() -> Result<T, WriterError>,
) -> Result<T, WriterError> {
	match with_materialization_disabled(operation) {
		Ok(outcome) => outcome,
		Err(ScopeError::Configure { error, restoration }) => {
			Err(WriterError::Configure { error, restoration })
		}
		Err(ScopeError::Restore { error, outcome }) => Err(WriterError::Restore {
			error,
			outcome: outcome.map(|_| success).map_err(Box::new),
		}),
	}
}
