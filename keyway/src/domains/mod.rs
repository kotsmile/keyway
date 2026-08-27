//! What keyway is about.
//!
//! - [`secrets`] — the inventory, and the seam over the backends holding it
//! - [`access`] — who may see what: delegations, ownership, and the one
//!   function that resolves them
//! - [`identity`] — who is asking, and what keyway remembers about them
//! - [`tokens`] — the credential for callers that can hold no session
//! - [`audit`] — what was done, reads included

pub mod access;
pub mod audit;
pub mod identity;
pub mod secrets;
pub mod tokens;
