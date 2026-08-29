//! The single file a deployment is configured by.
//!
//! Every value is a string, credentials included: there is no second channel
//! and no environment read for a setting of its own. A credential reaches the
//! process through a `${env:NAME}` placeholder in this file, so what a
//! deployment holds is declared next to what needs it.

mod placeholder;
mod selector;
mod store;

pub use placeholder::{Reason, Unresolved};
pub use selector::Selector;
pub use store::{StoreConfig, Verb};

use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: Server,
    pub postgres: Postgres,
    pub oidc: Oidc,
    #[serde(default)]
    pub stores: Vec<StoreConfig>,
    #[serde(default)]
    pub branding: Branding,
    #[serde(default)]
    pub telemetry: Telemetry,
}

/// Where traces go, if anywhere.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Telemetry {
    /// An OTLP collector. Empty means traces stay local: a deployment with no
    /// collector should not be retrying exports into the void.
    #[serde(default)]
    pub otlp_endpoint: String,
    #[serde(default = "default_service_name")]
    pub service_name: String,
}

fn default_service_name() -> String {
    "keyway".to_owned()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Server {
    #[serde(default = "default_address")]
    pub address: String,
    /// Where `/metrics` is served, deliberately not the API's port.
    ///
    /// A scrape endpoint publishes what a deployment holds — Store ids, call
    /// rates, error rates — to whoever can reach it, and a metrics port is
    /// almost always less guarded than an API one. Separating them lets a
    /// deployment expose the API and keep this on the cluster network.
    #[serde(default = "default_metrics_address")]
    pub metrics_address: String,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            address: default_address(),
            metrics_address: default_metrics_address(),
        }
    }
}

fn default_address() -> String {
    ":8080".to_owned()
}

fn default_metrics_address() -> String {
    ":9090".to_owned()
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Postgres {
    pub addr: String,
    pub name: String,
    pub user: String,
    pub password: String,
    #[serde(default = "default_sslmode")]
    pub sslmode: String,
    #[serde(default = "default_max_conn")]
    pub max_conn: u32,
}

fn default_sslmode() -> String {
    "require".to_owned()
}

fn default_max_conn() -> u32 {
    10
}

/// Identity, from any OIDC issuer.
///
/// The claim names are configuration because keyway assumes nothing about how
/// an issuer spells things (ADR-0003). Group names are matched exactly; an
/// issuer wanting a grant to a parent group to cover the teams inside it emits
/// the ancestors in the claim.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Oidc {
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub redirect_url: String,
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,
    /// Stripped from a role name before keyway reads it, so a realm can
    /// namespace its roles (`keyway:admin`) without keyway assuming a scheme.
    #[serde(default = "default_role_prefix")]
    pub role_prefix: String,
    /// Signs and encrypts the session cookie. At least 32 bytes.
    ///
    /// Changing it signs everybody out, which is the intended way to sign
    /// everybody out.
    #[serde(default)]
    pub session_key: String,
    /// How long a browser session lasts.
    #[serde(default = "default_session_hours")]
    pub session_hours: i64,
    /// An optional live connection to the identity provider.
    ///
    /// Unset, keyway calls it on no request at all and a token's groups are
    /// what was remembered at its holder's last sign-in. Set, membership is
    /// live and disabling an account cuts every token it issued (ADR-0004).
    #[serde(default)]
    pub directory: String,
    /// Who a local run acts as. With no issuer, authentication is off and the
    /// service acts as this user — every authorisation decision is still made,
    /// so a local run behaves like production minus the redirect.
    #[serde(default)]
    pub dev_user: String,
    #[serde(default)]
    pub dev_roles: Vec<String>,
    #[serde(default)]
    pub dev_groups: Vec<String>,
}

fn default_groups_claim() -> String {
    "groups".to_owned()
}

fn default_roles_claim() -> String {
    "realm_access.roles".to_owned()
}

fn default_role_prefix() -> String {
    "keyway:".to_owned()
}

fn default_session_hours() -> i64 {
    8
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Branding {
    #[serde(default = "default_brand_name")]
    pub name: String,
    #[serde(default)]
    pub logo: String,
    #[serde(default)]
    pub favicon: String,
    #[serde(default = "default_accent")]
    pub accent: String,
}

impl Default for Branding {
    fn default() -> Self {
        Self {
            name: default_brand_name(),
            logo: String::new(),
            favicon: String::new(),
            accent: default_accent(),
        }
    }
}

fn default_brand_name() -> String {
    "keyway".to_owned()
}

fn default_accent() -> String {
    "#2563eb".to_owned()
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_norway::Error,
    },
    /// Every unresolved placeholder, together. A deployment with three unset
    /// variables should learn that in one boot rather than in three.
    #[error("unresolved placeholders in {path}:\n{}", .unresolved.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n"))]
    Unresolved {
        path: PathBuf,
        unresolved: Vec<Unresolved>,
    },
    #[error("two stores share the id {id:?}; every grant written against it would be ambiguous")]
    DuplicateStore { id: String },
}

/// Reads, resolves and validates the file at `path`.
///
/// # Errors
///
/// Fails when the file cannot be read or parsed, when a placeholder does not
/// resolve, or when two stores share an id.
pub fn load(path: impl AsRef<Path>) -> Result<Config, Error> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
        path: path.to_owned(),
        source,
    })?;
    from_str(&text, path, &|name| std::env::var(name).ok())
}

/// The body of [`load`], with the environment injected so it can be tested.
///
/// # Errors
///
/// As [`load`], minus the read.
pub fn from_str(
    text: &str,
    path: &Path,
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<Config, Error> {
    let mut document: serde_norway::Value =
        serde_norway::from_str(text).map_err(|source| Error::Parse {
            path: path.to_owned(),
            source,
        })?;
    placeholder::resolve(&mut document, lookup).map_err(|unresolved| Error::Unresolved {
        path: path.to_owned(),
        unresolved,
    })?;
    let config: Config = serde_norway::from_value(document).map_err(|source| Error::Parse {
        path: path.to_owned(),
        source,
    })?;
    config.validate()?;
    Ok(config)
}

impl Config {
    fn validate(&self) -> Result<(), Error> {
        let mut seen = BTreeSet::new();
        for store in &self.stores {
            if !seen.insert(store.id.as_str()) {
                return Err(Error::DuplicateStore {
                    id: store.id.clone(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const SAMPLE: &str = r#"
postgres:
  addr: localhost:5432
  name: keyway
  user: keyway
  password: ${env:PGPASS}

oidc:
  issuer: https://id.example.com/realms/acme
  client_id: keyway
  client_secret: ${env:OIDC_SECRET}

stores:
  - id: gcp-prod
    type: gcp
    title: Google Cloud (production)
    allow: [read, edit]
    project: acme-prod
    select:
      labels:
        keyway: "true"
"#;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    fn load_sample(yaml: &str, pairs: &[(&str, &str)]) -> Result<Config, Error> {
        from_str(yaml, Path::new("config.yml"), &env(pairs))
    }

    #[test]
    fn reads_a_whole_file() {
        let config =
            load_sample(SAMPLE, &[("PGPASS", "hunter2"), ("OIDC_SECRET", "s3cret")]).unwrap();

        assert_eq!(config.postgres.password, "hunter2");
        assert_eq!(config.oidc.client_secret, "s3cret");
        assert_eq!(config.stores.len(), 1);
        assert_eq!(config.stores[0].id, "gcp-prod");
        assert_eq!(config.stores[0].kind, "gcp");
        assert!(config.stores[0].allow.contains(&Verb::Read));
        assert!(!config.stores[0].allow.contains(&Verb::Delete));
    }

    #[test]
    fn defaults_fill_in_what_a_short_file_omits() {
        let config = load_sample(SAMPLE, &[("PGPASS", "x"), ("OIDC_SECRET", "y")]).unwrap();
        assert_eq!(config.server.address, ":8080");
        assert_eq!(config.branding.name, "keyway");
        assert_eq!(config.oidc.groups_claim, "groups");
        // Not `disable`: a deployment that has said nothing about TLS to its
        // database has not thereby asked for none.
        assert_eq!(config.postgres.sslmode, "require");
    }

    #[test]
    fn an_unset_placeholder_is_fatal() {
        let error = load_sample(SAMPLE, &[("PGPASS", "hunter2")]).unwrap_err();
        let Error::Unresolved { unresolved, .. } = error else {
            panic!("expected unresolved placeholders");
        };
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].path, "oidc.client_secret");
    }

    #[test]
    fn adapter_settings_are_kept_for_the_store_to_read() {
        let config = load_sample(SAMPLE, &[("PGPASS", "x"), ("OIDC_SECRET", "y")]).unwrap();
        assert_eq!(
            config.stores[0]
                .settings
                .get("project")
                .and_then(|v| v.as_str()),
            Some("acme-prod"),
            "a store's own keys belong to its SecretManager, not to this schema"
        );
    }

    #[test]
    fn two_stores_on_one_id_fail_the_boot() {
        let yaml = SAMPLE.to_owned()
            + "  - id: gcp-prod\n    type: gcp\n    allow: [read]\n    project: other\n";
        let error = load_sample(&yaml, &[("PGPASS", "x"), ("OIDC_SECRET", "y")]).unwrap_err();
        assert!(matches!(error, Error::DuplicateStore { .. }));
    }

    #[test]
    fn a_misspelled_top_level_key_is_refused() {
        // `postgress:` should not read as "no postgres block configured".
        let yaml = SAMPLE.replace("postgres:", "postgress:");
        let error = load_sample(&yaml, &[("PGPASS", "x"), ("OIDC_SECRET", "y")]).unwrap_err();
        assert!(matches!(error, Error::Parse { .. }));
    }
}
