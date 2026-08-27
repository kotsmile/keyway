//! The vocabulary in `CONTEXT.md`, as types.
//!
//! Nothing here talks to a backend or to a database. A secret's value lives in
//! whatever secret manager holds it; what keyway owns is who may see it and
//! what has been done to it.

mod actor;
mod delegation;
mod level;
mod secret;
mod subject;

pub use actor::{Actor, Role};
pub use delegation::{Delegation, Ownership};
pub use level::{Level, UnknownLevel};
pub use secret::{Metadata, Secret, Version, VersionState};
pub use subject::Subject;
