//! The browser door.
//!
//! Authorization code flow with PKCE against any OIDC issuer. keyway assumes
//! nothing about how an issuer spells things (ADR-0003): the claim carrying
//! groups is named in config, and group names are matched exactly — an issuer
//! that wants a grant to a parent group to cover the teams inside it emits the
//! ancestors in the claim.

use crate::config::Oidc as OidcConfig;
use crate::domains::identity::entity::Role;
use eyre::{Context as _, bail};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde_json::Value;

/// A configured issuer, discovered once at boot.
pub struct Oidc {
    client: CoreClient<
        openidconnect::EndpointSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointMaybeSet,
        openidconnect::EndpointMaybeSet,
    >,
    http: openidconnect::reqwest::Client,
    groups_claim: String,
    roles_claim: String,
    role_prefix: String,
}

/// Who signed in, as the claim describes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedIn {
    pub handle: String,
    pub email: String,
    pub name: String,
    pub groups: Vec<String>,
    pub roles: Vec<Role>,
}

/// What a redirect to the issuer needs remembering across it.
pub struct Pending {
    pub authorize_url: String,
    pub csrf: String,
    pub nonce: String,
    pub pkce_verifier: String,
}

impl Oidc {
    /// Discovers the issuer.
    ///
    /// At boot rather than per request: a console that only discovers its
    /// issuer when somebody tries to sign in is one that looks healthy while
    /// being unusable.
    ///
    /// # Errors
    ///
    /// When discovery fails or the configuration is not a valid issuer.
    pub async fn discover(config: &OidcConfig) -> eyre::Result<Self> {
        let http = openidconnect::reqwest::ClientBuilder::new()
            // An issuer that redirects is an issuer being impersonated.
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .build()
            .wrap_err("building an http client")?;

        let issuer = IssuerUrl::new(config.issuer.clone()).wrap_err("the oidc issuer url")?;
        let metadata = CoreProviderMetadata::discover_async(issuer, &http)
            .await
            .wrap_err_with(|| format!("discovering {}", config.issuer))?;

        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
        )
        .set_redirect_uri(
            RedirectUrl::new(config.redirect_url.clone()).wrap_err("the oidc redirect url")?,
        );

        Ok(Self {
            client,
            http,
            groups_claim: config.groups_claim.clone(),
            roles_claim: config.roles_claim.clone(),
            role_prefix: config.role_prefix.clone(),
        })
    }

    /// Where to send somebody, and what to remember while they are gone.
    #[must_use]
    pub fn start(&self) -> Pending {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, csrf, nonce) = self
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_owned()))
            .add_scope(Scope::new("profile".to_owned()))
            .add_scope(Scope::new("email".to_owned()))
            .add_scope(Scope::new("groups".to_owned()))
            .set_pkce_challenge(challenge)
            .url();

        Pending {
            authorize_url: url.to_string(),
            csrf: csrf.secret().clone(),
            nonce: nonce.secret().clone(),
            pkce_verifier: verifier.secret().clone(),
        }
    }

    /// Exchanges the code for an identity.
    ///
    /// # Errors
    ///
    /// When the exchange fails, the id token is absent or its claims do not
    /// verify.
    pub async fn finish(
        &self,
        code: &str,
        nonce: &str,
        pkce_verifier: &str,
    ) -> eyre::Result<SignedIn> {
        let tokens = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_owned()))?
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_owned()))
            .request_async(&self.http)
            .await
            .wrap_err("exchanging the authorization code")?;

        let Some(id_token) = tokens.id_token() else {
            bail!("the issuer returned no id token");
        };
        let claims = id_token
            .claims(
                &self.client.id_token_verifier(),
                &Nonce::new(nonce.to_owned()),
            )
            .wrap_err("verifying the id token")?;

        // `preferred_username` is the handle everything keys and logs on; the
        // subject is stable but unreadable, and an audit log full of uuids
        // answers nobody's question.
        let handle = claims.preferred_username().map_or_else(
            || claims.subject().as_str().to_owned(),
            |u| u.as_str().to_owned(),
        );

        let extra = serde_json::to_value(claims).unwrap_or(Value::Null);

        Ok(SignedIn {
            handle,
            email: claims
                .email()
                .map(|e| e.as_str().to_owned())
                .unwrap_or_default(),
            name: claims
                .name()
                .and_then(|n| n.get(None))
                .map(|n| n.as_str().to_owned())
                .unwrap_or_default(),
            groups: strings_at(&extra, &self.groups_claim),
            roles: strings_at(&extra, &self.roles_claim)
                .iter()
                .filter_map(|name| name.strip_prefix(&self.role_prefix).and_then(Role::parse))
                .collect(),
        })
    }
}

/// Reads a claim by dotted path, e.g. `realm_access.roles`.
///
/// A path rather than a key because issuers nest: Keycloak puts realm roles
/// under `realm_access.roles`, and a flat lookup would find nothing and grant
/// nothing, silently.
fn strings_at(claims: &Value, path: &str) -> Vec<String> {
    let mut current = claims;
    for segment in path.split('.') {
        match current.get(segment) {
            Some(next) => current = next,
            None => return Vec::new(),
        }
    }
    match current {
        Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(ToOwned::to_owned))
            .collect(),
        // A single string is a claim with one value, which some issuers emit
        // rather than a one-element array.
        Value::String(one) => vec![one.clone()],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_flat_claim_is_read() {
        let claims = json!({ "groups": ["SRE", "platform"] });
        assert_eq!(strings_at(&claims, "groups"), ["SRE", "platform"]);
    }

    #[test]
    fn a_nested_claim_is_read_by_path() {
        // Keycloak's shape. A flat lookup would find nothing and grant
        // nothing, silently.
        let claims = json!({ "realm_access": { "roles": ["keyway:admin"] } });
        assert_eq!(strings_at(&claims, "realm_access.roles"), ["keyway:admin"]);
    }

    #[test]
    fn a_single_string_claim_is_one_value() {
        let claims = json!({ "groups": "SRE" });
        assert_eq!(strings_at(&claims, "groups"), ["SRE"]);
    }

    #[test]
    fn a_missing_claim_is_empty_rather_than_an_error() {
        // Somebody with no groups is not a failure, and refusing to sign them
        // in would make "no teams yet" indistinguishable from a broken issuer.
        let claims = json!({ "sub": "abc" });
        assert!(strings_at(&claims, "groups").is_empty());
        assert!(strings_at(&claims, "realm_access.roles").is_empty());
    }

    #[test]
    fn a_claim_of_the_wrong_shape_is_empty() {
        let claims = json!({ "groups": { "not": "a list" } });
        assert!(strings_at(&claims, "groups").is_empty());
    }
}
