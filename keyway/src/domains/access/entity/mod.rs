//! Delegations, ownership, and the rule that reads them.

mod access;
mod delegation;
mod level;
mod subject;

pub use access::{Access, Basis, resolve};
pub use delegation::{Delegation, Ownership};
pub use level::{Level, UnknownLevel};
pub use subject::Subject;
