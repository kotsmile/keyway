//! The browser session.
//!
//! Everything the session needs lives in an encrypted cookie rather than in
//! server memory: keyway runs several replicas, and a session held in one of
//! them is a session that vanishes on a rolling deploy.
//!
//! The cookie is a *private* one — encrypted and authenticated, not merely
//! signed — because it carries the caller's groups, which is a fact about the
//! organisation and not something to hand out in readable form.

use crate::domains::identity::entity::{Actor, Role};
use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub handle: String,
    pub groups: Vec<String>,
    pub roles: Vec<String>,
    /// Checked on every request. A cookie's own `Max-Age` is a hint the client
    /// is free to ignore, so the expiry has to be inside the encrypted value
    /// as well.
    pub expires_at: DateTime<Utc>,
}

impl Session {
    /// Not configurable. It is a property of this service's identity rather
    /// than of a deployment, and a name somebody could change is a name
    /// somebody could change to another service's.
    pub const COOKIE: &'static str = "keyway_session";

    /// Whether this session still stands.
    #[must_use]
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.expires_at > now
    }

    /// Who this session is, as the rest of the system reasons about callers.
    #[must_use]
    pub fn actor(&self) -> Actor {
        Actor::new(
            self.handle.clone(),
            self.groups.clone(),
            self.roles
                .iter()
                .filter_map(|r| Role::parse(r))
                .collect::<Vec<_>>(),
        )
    }

    /// The cookie carrying it.
    #[must_use]
    pub fn into_cookie(self, hours: i64) -> Cookie<'static> {
        let value = serde_json::to_string(&self).unwrap_or_default();
        Cookie::build((Self::COOKIE, value))
            .path("/")
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Lax)
            .max_age(time::Duration::hours(hours))
            .build()
    }

    /// Reads one back.
    #[must_use]
    pub fn from_cookie(value: &str) -> Option<Self> {
        serde_json::from_str(value).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(expires_at: DateTime<Utc>) -> Session {
        Session {
            handle: "alice".to_owned(),
            groups: vec!["SRE".to_owned()],
            roles: vec!["create".to_owned()],
            expires_at,
        }
    }

    #[test]
    fn a_session_round_trips_through_its_cookie() {
        let original = session(Utc::now() + chrono::Duration::hours(8));
        let cookie = original.clone().into_cookie(8);
        let read = Session::from_cookie(cookie.value()).expect("reads back");

        assert_eq!(read.handle, "alice");
        assert_eq!(read.groups, ["SRE"]);
        assert!(read.actor().may_create());
    }

    #[test]
    fn an_expired_session_is_not_live() {
        // The cookie's own Max-Age is a hint a client may ignore, so the
        // expiry is checked from inside the encrypted value too.
        assert!(!session(Utc::now() - chrono::Duration::seconds(1)).is_live(Utc::now()));
        assert!(session(Utc::now() + chrono::Duration::hours(1)).is_live(Utc::now()));
    }

    #[test]
    fn a_role_this_build_cannot_read_grants_nothing() {
        // A realm may hold roles from other systems. Ignoring a name nothing
        // here can interpret is the only safe reading of it.
        let mut s = session(Utc::now() + chrono::Duration::hours(1));
        s.roles = vec!["some-other-system:admin".to_owned()];

        let actor = s.actor();
        assert!(!actor.is_admin());
        assert!(!actor.may_create());
    }

    #[test]
    fn the_cookie_is_not_readable_by_script_and_not_sent_cross_site() {
        let cookie = session(Utc::now() + chrono::Duration::hours(8)).into_cookie(8);
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }
}
