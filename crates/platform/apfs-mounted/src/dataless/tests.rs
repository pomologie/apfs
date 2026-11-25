use std::{cell::RefCell, collections::VecDeque, panic::catch_unwind, thread};

use super::{ThreadPolicy::*, *};

enum Call {
	Read(Result<ThreadPolicy, PolicyError>),
	Write(ThreadPolicy, Result<(), PolicyError>),
}

struct Script(RefCell<VecDeque<Call>>);

impl Script {
	fn new(calls: impl IntoIterator<Item = Call>) -> Self {
		Self(RefCell::new(calls.into_iter().collect()))
	}

	fn assert_finished(&self) {
		assert!(self.0.borrow().is_empty());
	}
}

impl PolicyIo for Script {
	fn current(&self) -> Result<ThreadPolicy, PolicyError> {
		match self.0.borrow_mut().pop_front() {
			Some(Call::Read(result)) => result,
			_ => panic!("unexpected policy query"),
		}
	}

	fn set(&self, value: ThreadPolicy) -> Result<(), PolicyError> {
		match self.0.borrow_mut().pop_front() {
			Some(Call::Write(expected, result)) => {
				assert_eq!(value, expected);
				result
			}
			_ => panic!("unexpected policy update to {value:?}"),
		}
	}
}

fn io_error(errno: libc::c_int) -> PolicyError {
	PolicyError::Io(io::Error::from_raw_os_error(errno))
}

#[test]
fn a_failed_initial_query_does_not_run_the_operation() {
	let script = Script::new([Call::Read(Err(io_error(libc::EIO)))]);
	assert!(matches!(
		with_policy(&script, || panic!("operation must be skipped")),
		Err(ScopeError::Configure { error: PolicyError::Io(error), restoration: None })
			if error.raw_os_error() == Some(libc::EIO)
	));
	script.assert_finished();
}

#[test]
fn an_unverified_disabled_setting_rolls_back_before_returning() {
	let script = Script::new([
		Call::Read(Ok(Inherited)),
		Call::Write(Disabled, Ok(())),
		Call::Read(Ok(Enabled)),
		Call::Read(Ok(Enabled)),
		Call::Write(Inherited, Ok(())),
		Call::Read(Ok(Inherited)),
	]);
	assert!(matches!(
		with_policy(&script, || panic!("operation must be skipped")),
		Err(ScopeError::Configure {
			error: PolicyError::UnexpectedPolicy {
				expected: Disabled,
				observed: Enabled
			},
			restoration: None,
		})
	));
	script.assert_finished();
}

#[test]
fn a_failed_setter_is_rolled_back_and_both_failures_are_preserved() {
	let script = Script::new([
		Call::Read(Ok(Enabled)),
		Call::Write(Disabled, Err(io_error(libc::EIO))),
		Call::Read(Ok(Disabled)),
		Call::Write(Enabled, Err(io_error(libc::EPERM))),
		Call::Read(Ok(Disabled)),
		Call::Write(Enabled, Ok(())),
		Call::Read(Ok(Enabled)),
	]);
	assert!(matches!(
		with_policy(&script, || panic!("operation must be skipped")),
		Err(ScopeError::Configure {
			error: PolicyError::Io(error),
			restoration: Some(PolicyError::Io(restoration)),
		}) if error.raw_os_error() == Some(libc::EIO)
			&& restoration.raw_os_error() == Some(libc::EPERM)
	));
	script.assert_finished();
}

#[test]
fn a_restore_mismatch_keeps_successful_effect_and_failed_operation_outcomes() {
	for outcome in [Ok(42), Err(io::Error::from_raw_os_error(libc::ENOSPC))] {
		let script = Script::new([
			Call::Read(Ok(Inherited)),
			Call::Write(Disabled, Ok(())),
			Call::Read(Ok(Disabled)),
			Call::Read(Ok(Disabled)),
			Call::Write(Inherited, Ok(())),
			Call::Read(Ok(Disabled)),
			Call::Read(Ok(Disabled)),
			Call::Write(Inherited, Ok(())),
			Call::Read(Ok(Inherited)),
		]);
		let observed = outcome.as_ref().copied().map_err(io::Error::raw_os_error);
		let Err(ScopeError::Restore {
			outcome,
			error:
				PolicyError::UnexpectedPolicy {
					expected: Inherited,
					observed: Disabled,
				},
		}) = with_policy(&script, || outcome)
		else {
			panic!("expected a retained outcome and restore error");
		};
		assert_eq!(outcome.map_err(|error| error.raw_os_error()), observed);
		script.assert_finished();
	}
}

#[test]
fn an_already_disabled_thread_is_verified_on_return() {
	let script = Script::new([
		Call::Read(Ok(Disabled)),
		Call::Read(Ok(Enabled)),
		Call::Write(Disabled, Ok(())),
		Call::Read(Ok(Disabled)),
	]);
	assert_eq!(with_policy(&script, || 42).unwrap(), 42);
	script.assert_finished();
}

#[test]
fn classifies_only_the_documented_content_errno() {
	assert!(matches!(
		ContentError::while_materialization_disabled(io::Error::from_raw_os_error(libc::EDEADLK)),
		ContentError::Unavailable(error) if error.raw_os_error() == Some(libc::EDEADLK)
	));
	for errno in [libc::EACCES, libc::EIO, libc::ENOENT] {
		assert!(matches!(
			ContentError::while_materialization_disabled(io::Error::from_raw_os_error(errno)),
			ContentError::Io(error) if error.raw_os_error() == Some(errno)
		));
	}
}

#[test]
fn native_scope_is_thread_local_and_restores_after_success_error_and_unwind() {
	let original = thread_policy().unwrap();
	let independent_policy = || thread::spawn(thread_policy).join().unwrap().unwrap();
	let independent_before = independent_policy();
	let result = with_materialization_disabled(|| {
		assert_eq!(thread_policy().unwrap(), Disabled);
		assert_eq!(independent_policy(), independent_before);
		with_materialization_disabled(|| {
			assert_eq!(thread_policy().unwrap(), Disabled);
			42
		})
		.unwrap()
	})
	.unwrap();
	assert_eq!(result, 42);
	assert_eq!(thread_policy().unwrap(), original);

	let failed = with_materialization_disabled(|| {
		assert_eq!(thread_policy().unwrap(), Disabled);
		Err::<(), _>("synthetic I/O failure")
	});
	assert!(matches!(failed, Ok(Err("synthetic I/O failure"))));
	assert_eq!(thread_policy().unwrap(), original);

	let panicked = catch_unwind(|| {
		with_materialization_disabled::<()>(|| {
			assert_eq!(thread_policy().unwrap(), Disabled);
			panic!("synthetic unwind");
		})
		.unwrap();
	});
	assert!(panicked.is_err());
	assert_eq!(thread_policy().unwrap(), original);
}
