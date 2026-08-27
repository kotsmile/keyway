use super::Store;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Every configured Store, in declaration order.
///
/// Declaration order is the order the console lists them in, so the config
/// file decides what a person sees first.
pub struct Registry {
    order: Vec<String>,
    by_id: BTreeMap<String, Arc<Store>>,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// Two Stores answering to one id makes every grant written against it
    /// ambiguous, which is worth failing the process over rather than
    /// resolving arbitrarily.
    #[error("duplicate store id {0:?}")]
    Duplicate(String),
}

impl Registry {
    /// Indexes the Stores.
    ///
    /// # Errors
    ///
    /// When two Stores share an id.
    pub fn new(stores: impl IntoIterator<Item = Store>) -> Result<Self, RegistryError> {
        let mut order = Vec::new();
        let mut by_id = BTreeMap::new();
        for store in stores {
            let id = store.id().to_owned();
            if by_id.contains_key(&id) {
                return Err(RegistryError::Duplicate(id));
            }
            order.push(id.clone());
            by_id.insert(id, Arc::new(store));
        }
        Ok(Self { order, by_id })
    }

    /// Resolves a Store id.
    ///
    /// Returns `None` for an unknown one; the caller reports that the same way
    /// it reports an unknown secret, so a URL cannot be used to learn which
    /// Stores exist.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<Arc<Store>> {
        self.by_id.get(id).cloned()
    }

    /// Every Store, in declaration order.
    #[must_use]
    pub fn all(&self) -> Vec<Arc<Store>> {
        self.order
            .iter()
            .filter_map(|id| self.by_id.get(id).cloned())
            .collect()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }
}
