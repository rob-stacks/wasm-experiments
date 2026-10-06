//! Clarity built-ins (conversions, hashing & crypto) extracted from stacks-core.
//!
//! Each function keeps the logic of the corresponding `clarity/src/vm/functions/*`
//! implementation and the `stacks-common` helpers it calls, minus the Clarity VM
//! (no `Value` arguments, evaluation, cost tracking or VM errors).

pub mod cases;
pub mod consensus;
pub mod conversions;
pub mod crypto;
pub mod encoding;

pub use cases::run;
