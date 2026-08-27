//! The vocabulary in `CONTEXT.md`, as types.
//!
//! Nothing here talks to a backend or to a database. A `Secret`'s value lives
//! in whatever secret manager holds it; what keyway owns is who may see it and
//! what has been done to it.

mod level;
mod subject;

pub use level::Level;
pub use subject::Subject;
