//! The keyway backend.
//!
//! Laid out by domain rather than by technical layer. Each domain owns its
//! `entity` (pure types and rules, no I/O), its `infra` (the adapters that
//! implement the ports the domain declares), and its `transport` (how it is
//! reached). A domain's `mod.rs` holds its service and the repository traits
//! that service is generic over, so the rules can be tested with no database
//! and no network.

pub mod config;
pub mod container;
pub mod domains;
pub mod infra;
pub mod router;
pub mod transport;
