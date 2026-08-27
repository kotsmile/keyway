//! A Directory backed by Keycloak's admin API.
//!
//! Optional, and off unless configured. What it buys back is the one property
//! keyway loses by not asking an identity provider on every request: disabling
//! an account cuts every API token it issued, within a cache window (ADR-0004).
//!
//! It is Keycloak-specific because the admin REST API is Keycloak's, not
//! OIDC's — which is exactly why this is a trait with an implementation rather
//! than something baked into the identity domain.

use crate::domains::identity::{Directory, DirectoryAnswer};
use async_trait::async_trait;
use eyre::{Context as _, bail};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a resolved subject is trusted.
///
/// The same window a copied claim gets, and for the same reason: it is the
/// longest a change may take to bite. Shortening it does not make the system
/// safer so much as it makes the identity provider a hard dependency of every
/// request; lengthening it quietly reintroduces the stale-membership problem
/// this exists to avoid.
const CACHE_FOR: Duration = Duration::from_mins(5);

pub struct KeycloakDirectory {
    admin_base: String,
    client_id: String,
    client_secret: String,
    token_url: String,
    http: reqwest::Client,
    cache: Mutex<HashMap<String, (Instant, Option<DirectoryAnswer>)>>,
}

/// What the cache had, distinguishing "we know they are gone" from "we do not
/// know yet". An `Option<Option<_>>` says the same thing and reads as neither.
enum Cached {
    Known(Option<DirectoryAnswer>),
    Stale,
}

#[derive(Deserialize)]
struct AccessToken {
    access_token: String,
}

#[derive(Deserialize)]
struct KcUser {
    id: String,
    #[serde(default)]
    enabled: bool,
}

#[derive(Deserialize)]
struct KcGroup {
    path: String,
}

impl KeycloakDirectory {
    /// Builds a Directory from the same confidential client keyway already
    /// uses to sign people in.
    ///
    /// The admin base is DERIVED from the issuer rather than configured
    /// separately: the two can only ever disagree by mistake, and a service
    /// pointed at one realm for login and another for identity would authorise
    /// against the wrong population without anything looking misconfigured.
    ///
    /// # Errors
    ///
    /// When the issuer is not a realm url.
    pub fn new(issuer: &str, client_id: &str, client_secret: &str) -> eyre::Result<Self> {
        let issuer = issuer.trim_end_matches('/');
        let Some((host, realm)) = issuer.rsplit_once("/realms/") else {
            bail!("{issuer} is not a Keycloak realm url (no /realms/ in it)");
        };

        Ok(Self {
            admin_base: format!("{host}/admin/realms/{realm}"),
            client_id: client_id.to_owned(),
            client_secret: client_secret.to_owned(),
            token_url: format!("{issuer}/protocol/openid-connect/token"),
            http: reqwest::Client::new(),
            cache: Mutex::new(HashMap::new()),
        })
    }

    fn cached(&self, handle: &str) -> Cached {
        let Ok(cache) = self.cache.lock() else {
            return Cached::Stale;
        };
        match cache.get(handle) {
            Some((at, answer)) if at.elapsed() < CACHE_FOR => Cached::Known(answer.clone()),
            _ => Cached::Stale,
        }
    }

    fn remember(&self, handle: &str, answer: Option<DirectoryAnswer>) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(handle.to_owned(), (Instant::now(), answer));
        }
    }

    /// The client's own access token, via the service account.
    ///
    /// Needs `serviceAccountsEnabled` on the client and `view-users` from
    /// `realm-management` — one flag and one role mapping on a client keyway
    /// already holds, so no second credential to rotate.
    async fn admin_token(&self) -> eyre::Result<String> {
        let response: AccessToken = self
            .http
            .post(&self.token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
            ])
            .send()
            .await
            .wrap_err("asking keycloak for a service-account token")?
            .error_for_status()
            .wrap_err("keycloak refused the service-account grant")?
            .json()
            .await
            .wrap_err("reading the service-account token")?;
        Ok(response.access_token)
    }
}

#[async_trait]
impl Directory for KeycloakDirectory {
    async fn resolve(&self, handle: &str) -> eyre::Result<Option<DirectoryAnswer>> {
        if let Cached::Known(answer) = self.cached(handle) {
            return Ok(answer);
        }

        let token = self.admin_token().await?;

        let users: Vec<KcUser> = self
            .http
            .get(format!("{}/users", self.admin_base))
            .bearer_auth(&token)
            // `exact` matters: without it Keycloak substring-matches, and
            // `alice` would return `alice2` as well.
            .query(&[("username", handle), ("exact", "true")])
            .send()
            .await
            .wrap_err("looking up a user")?
            .error_for_status()?
            .json()
            .await
            .wrap_err("reading a user")?;

        let Some(user) = users.into_iter().next() else {
            // Gone from the directory entirely. Remembered as absent so a
            // departed account does not cost a lookup on every request.
            self.remember(handle, None);
            return Ok(None);
        };

        if !user.enabled {
            self.remember(
                handle,
                Some(DirectoryAnswer {
                    enabled: false,
                    groups: Vec::new(),
                }),
            );
            return Ok(Some(DirectoryAnswer {
                enabled: false,
                groups: Vec::new(),
            }));
        }

        let groups: Vec<KcGroup> = self
            .http
            .get(format!("{}/users/{}/groups", self.admin_base, user.id))
            .bearer_auth(&token)
            .send()
            .await
            .wrap_err("listing a user's groups")?
            .error_for_status()?
            .json()
            .await
            .wrap_err("reading a user's groups")?;

        let answer = DirectoryAnswer {
            enabled: true,
            // Paths, matched exactly. keyway parses no structure out of a
            // group name (ADR-0003), so a realm wanting a grant to a parent
            // group to cover the teams inside it emits the ancestors.
            groups: groups.into_iter().map(|g| g.path).collect(),
        };
        self.remember(handle, Some(answer.clone()));
        Ok(Some(answer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_admin_base_is_derived_from_the_issuer() {
        // Configuring them separately means they can only ever disagree by
        // mistake, and that mistake authorises against the wrong population.
        let directory =
            KeycloakDirectory::new("https://id.example.com/realms/acme", "keyway", "s3cret")
                .unwrap();
        assert_eq!(
            directory.admin_base,
            "https://id.example.com/admin/realms/acme"
        );
        assert_eq!(
            directory.token_url,
            "https://id.example.com/realms/acme/protocol/openid-connect/token"
        );
    }

    #[test]
    fn a_trailing_slash_does_not_change_the_answer() {
        let directory =
            KeycloakDirectory::new("https://id.example.com/realms/acme/", "keyway", "x").unwrap();
        assert_eq!(
            directory.admin_base,
            "https://id.example.com/admin/realms/acme"
        );
    }

    #[test]
    fn an_issuer_that_is_not_a_realm_is_refused_at_boot() {
        // Another OIDC provider does not have this API, and failing here says
        // so rather than failing on the first sign-in.
        assert!(KeycloakDirectory::new("https://accounts.google.com", "keyway", "x").is_err());
    }

    #[test]
    fn a_cached_answer_is_returned_until_it_goes_stale() {
        let directory =
            KeycloakDirectory::new("https://id.example.com/realms/acme", "keyway", "x").unwrap();

        assert!(matches!(directory.cached("alice"), Cached::Stale));
        directory.remember(
            "alice",
            Some(DirectoryAnswer {
                enabled: true,
                groups: vec!["/SRE".to_owned()],
            }),
        );
        let Cached::Known(Some(answer)) = directory.cached("alice") else {
            panic!("expected a cached answer");
        };
        assert_eq!(answer.groups, ["/SRE"]);
    }

    #[test]
    fn a_departed_account_is_remembered_as_absent() {
        // Otherwise every request for somebody who left costs a lookup.
        let directory =
            KeycloakDirectory::new("https://id.example.com/realms/acme", "keyway", "x").unwrap();
        directory.remember("gone", None);

        assert!(matches!(directory.cached("gone"), Cached::Known(None)));
    }
}
