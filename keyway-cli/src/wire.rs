//! What the API looks like from out here.
//!
//! Its own types rather than the backend's, so the CLI stays a small binary
//! that formats output instead of a copy of the server.

use crate::profile::Profile;
use eyre::{Context as _, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: String,
    pub store: String,
    pub name: String,
    #[serde(default)]
    pub latest_version: String,
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub basis: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub id: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    pub subject_kind: String,
    pub subject: String,
    pub level: String,
    #[serde(default)]
    pub keys: Vec<String>,
    pub granted_by: String,
}

/// What `delegate` is being asked to write. A struct rather than seven
/// positional arguments, because most of them are strings and an argument list
/// nobody can read is one somebody eventually passes in the wrong order.
pub struct NewGrant<'a> {
    pub kind: &'a str,
    pub subject: &'a str,
    pub level: &'a str,
    pub keys: &'a [String],
    pub days: i64,
    pub note: &'a str,
}

#[derive(Deserialize)]
struct ApiError {
    error: String,
}

pub struct Client {
    profile: Profile,
    http: reqwest::Client,
}

impl Client {
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            http: reqwest::Client::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.profile.url.trim_end_matches('/'))
    }

    pub async fn list(&self) -> eyre::Result<Vec<Secret>> {
        self.get_json("/api/secrets").await
    }

    pub async fn view(&self, id: &str) -> eyre::Result<Secret> {
        self.get_json(&format!("/api/secrets/{id}")).await
    }

    pub async fn reveal(
        &self,
        id: &str,
        key: Option<&str>,
        version: Option<&str>,
    ) -> eyre::Result<String> {
        let mut url = self.url(&format!("/api/secrets/{id}/value"));
        let mut query = Vec::new();
        if let Some(key) = key {
            query.push(format!("key={key}"));
        }
        if let Some(version) = version {
            query.push(format!("version={version}"));
        }
        if !query.is_empty() {
            url = format!("{url}?{}", query.join("&"));
        }

        let response = self
            .http
            .get(url)
            .bearer_auth(&self.profile.token)
            .send()
            .await
            .wrap_err("reaching keyway")?;
        let response = check(response).await?;
        Ok(response.text().await?)
    }

    pub async fn create(
        &self,
        store: &str,
        name: &str,
        value: &str,
        note: &str,
    ) -> eyre::Result<Secret> {
        self.post_json(
            "/api/secrets",
            &serde_json::json!({
                "store": store, "name": name, "value": value, "note": note
            }),
        )
        .await
    }

    pub async fn patch(&self, id: &str, value: &str, note: &str) -> eyre::Result<Version> {
        self.post_json(
            &format!("/api/secrets/{id}/versions"),
            &serde_json::json!({ "value": value, "note": note }),
        )
        .await
    }

    pub async fn delegate(&self, id: &str, grant: NewGrant<'_>) -> eyre::Result<Grant> {
        self.post_json(
            &format!("/api/secrets/{id}/grants"),
            &serde_json::json!({
                "subject_kind": grant.kind,
                "subject": grant.subject,
                "level": grant.level,
                "keys": grant.keys,
                "days": grant.days,
                "note": grant.note
            }),
        )
        .await
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> eyre::Result<T> {
        let response = self
            .http
            .get(self.url(path))
            .bearer_auth(&self.profile.token)
            .send()
            .await
            .wrap_err("reaching keyway")?;
        Ok(check(response).await?.json().await?)
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> eyre::Result<T> {
        let response = self
            .http
            .post(self.url(path))
            .bearer_auth(&self.profile.token)
            .json(body)
            .send()
            .await
            .wrap_err("reaching keyway")?;
        Ok(check(response).await?.json().await?)
    }
}

/// Turns a failure into a sentence worth reading.
///
/// A 404 is reported as "no such secret, or you cannot see it" because that is
/// exactly what the server means: it will not distinguish the two, and neither
/// should this.
async fn check(response: reqwest::Response) -> eyre::Result<reqwest::Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }

    let body = response.text().await.unwrap_or_default();
    let message = serde_json::from_str::<ApiError>(&body)
        .map(|e| e.error)
        .unwrap_or(body);

    match status.as_u16() {
        401 => bail!("not signed in, or the token is no longer valid"),
        403 => bail!("{message}"),
        404 => bail!("no such secret, or you cannot see it"),
        _ => bail!("keyway said {status}: {message}"),
    }
}
