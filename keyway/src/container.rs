//! The concrete wiring.
//!
//! Every service is generic over the ports its domain declares, so the rules
//! can be tested with no database and no network. This is the one place that
//! says which implementation each port actually gets.

use crate::domains::access::{AccessService, infra::PostgresAccessRepo};
use crate::domains::audit::{AuditService, infra::PostgresAuditRepo};
use crate::domains::identity::{IdentityService, infra::PostgresIdentityRepo};
use crate::domains::secrets::{OwnStoreService, infra::PostgresOwnStoreRepo};
use crate::domains::tokens::{TokenService, infra::PostgresTokenRepo};
use std::sync::Arc;

pub type Access = Arc<AccessService<PostgresAccessRepo>>;
pub type Audit = Arc<AuditService<PostgresAuditRepo>>;
pub type Identity = Arc<IdentityService<PostgresIdentityRepo>>;
pub type Tokens = Arc<TokenService<PostgresTokenRepo>>;
pub type OwnStore = OwnStoreService<PostgresOwnStoreRepo>;
