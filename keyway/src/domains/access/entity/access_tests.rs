use super::{Basis, resolve};
use crate::domains::access::entity::{Delegation, Level, Ownership, Subject};
use crate::domains::identity::entity::{Actor, Role};
use chrono::{DateTime, TimeZone, Utc};
use uuid::Uuid;

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 27, 12, 0, 0).unwrap()
}

fn alice() -> Actor {
    Actor::new("alice", ["SRE".to_owned()], [])
}

fn grant(subject: Subject, level: Level) -> Delegation {
    Delegation {
        id: Uuid::new_v4(),
        store: "gcp-prod".to_owned(),
        secret: "db-creds".to_owned(),
        subject,
        level,
        keys: Vec::new(),
        granted_by: "carol".to_owned(),
        granted_at: now(),
        expires_at: None,
        note: String::new(),
    }
}

fn owned_by(owner: &str) -> Ownership {
    Ownership {
        store: "gcp-prod".to_owned(),
        secret: "db-creds".to_owned(),
        owner: owner.to_owned(),
        since: now(),
    }
}

#[test]
fn nothing_is_the_default() {
    let access = resolve(&alice(), None, &[], now());
    assert_eq!(access.basis, Basis::Nothing);
    assert!(!access.is_visible(), "an unmentioned secret is not visible");
}

#[test]
fn a_grant_opens_exactly_what_it_says() {
    // ADR-0002: the delegation carries its own level and no role caps it.
    // Alice holds NO roles at all here.
    let grants = [grant(Subject::User("alice".to_owned()), Level::Write)];
    let access = resolve(&alice(), None, &grants, now());

    assert_eq!(access.level, Some(Level::Write));
    assert!(access.allows(Level::Read));
    assert_eq!(
        access.basis,
        Basis::Delegated {
            subject: "alice".to_owned()
        }
    );
}

#[test]
fn a_group_grant_reaches_a_member() {
    let grants = [grant(Subject::Group("SRE".to_owned()), Level::Read)];
    let access = resolve(&alice(), None, &grants, now());
    assert_eq!(access.level, Some(Level::Read));
}

#[test]
fn a_grant_to_a_team_the_caller_is_not_in_opens_nothing() {
    let grants = [grant(Subject::Group("platform".to_owned()), Level::Write)];
    assert!(!resolve(&alice(), None, &grants, now()).is_visible());
}

#[test]
fn a_person_and_a_team_of_the_same_name_are_not_confused() {
    // The scenario ADR-0003 exists for. `bob` the person is not in the claim;
    // `bob` the team is. A grant to the person must not reach the member.
    let bob_the_team_member = Actor::new("carol", ["bob".to_owned()], []);
    let to_the_person = [grant(Subject::User("bob".to_owned()), Level::Write)];
    assert!(!resolve(&bob_the_team_member, None, &to_the_person, now()).is_visible());

    let to_the_team = [grant(Subject::Group("bob".to_owned()), Level::Write)];
    assert!(resolve(&bob_the_team_member, None, &to_the_team, now()).is_visible());
}

#[test]
fn the_best_grant_wins_when_a_caller_is_named_twice() {
    // Named directly at read, and through a team at write. The answer is what
    // was granted, not whichever row came back first.
    let grants = [
        grant(Subject::User("alice".to_owned()), Level::Read),
        grant(Subject::Group("SRE".to_owned()), Level::Write),
    ];
    assert_eq!(
        resolve(&alice(), None, &grants, now()).level,
        Some(Level::Write)
    );

    let reversed = [grants[1].clone(), grants[0].clone()];
    assert_eq!(
        resolve(&alice(), None, &reversed, now()).level,
        Some(Level::Write),
        "the answer must not depend on row order"
    );
}

#[test]
fn an_expired_grant_opens_nothing() {
    let mut expired = grant(Subject::User("alice".to_owned()), Level::Write);
    expired.expires_at = Some(now() - chrono::Duration::seconds(1));
    assert!(!resolve(&alice(), None, &[expired], now()).is_visible());
}

#[test]
fn a_grant_expiring_later_still_opens() {
    let mut live = grant(Subject::User("alice".to_owned()), Level::Read);
    live.expires_at = Some(now() + chrono::Duration::hours(1));
    assert!(resolve(&alice(), None, &[live], now()).is_visible());
}

#[test]
fn an_owner_runs_their_secret_whatever_role_they_hold() {
    // Ownership is orthogonal: alice holds no roles and no grant.
    let access = resolve(&alice(), Some(&owned_by("alice")), &[], now());
    assert_eq!(access.level, Some(Level::Write));
    assert_eq!(access.basis, Basis::Owner);
}

#[test]
fn ownership_by_somebody_else_grants_nothing_by_itself() {
    assert!(!resolve(&alice(), Some(&owned_by("bob")), &[], now()).is_visible());
}

#[test]
fn admin_opens_everything() {
    let admin = Actor::new("root", [], [Role::Admin]);
    let access = resolve(&admin, Some(&owned_by("alice")), &[], now());
    assert_eq!(access.level, Some(Level::Write));
    assert_eq!(access.basis, Basis::Admin);
}

#[test]
fn an_owner_who_is_also_admin_is_recorded_as_the_owner() {
    // The narrower reason is the truer one, and it is what the audit row says.
    let admin = Actor::new("alice", [], [Role::Admin]);
    let access = resolve(&admin, Some(&owned_by("alice")), &[], now());
    assert_eq!(access.basis, Basis::Owner);
}

#[test]
fn the_create_role_opens_no_existing_secret() {
    // It brings new secrets into the inventory and says nothing about the ones
    // already there.
    let creator = Actor::new("alice", [], [Role::Create]);
    assert!(!resolve(&creator, None, &[], now()).is_visible());
    assert!(creator.may_create());
}

#[test]
fn a_key_scoped_grant_opens_only_those_keys() {
    // What makes it safe to bundle a bot's credentials into one secret and
    // still hand out exactly one of them.
    let mut scoped = grant(Subject::Group("SRE".to_owned()), Level::Read);
    scoped.keys = vec!["db_password".to_owned()];
    let access = resolve(&alice(), None, &[scoped], now());

    assert!(access.allows_key(Level::Read, "db_password"));
    assert!(!access.allows_key(Level::Read, "api_key"));
}

#[test]
fn an_unscoped_grant_opens_every_key_including_later_ones() {
    // The grant names a secret, not a snapshot of it.
    let access = resolve(
        &alice(),
        None,
        &[grant(Subject::User("alice".to_owned()), Level::Read)],
        now(),
    );
    assert!(access.allows_key(Level::Read, "a-key-added-tomorrow"));
}

#[test]
fn guest_sees_the_shape_but_never_the_value() {
    let access = resolve(
        &alice(),
        None,
        &[grant(Subject::User("alice".to_owned()), Level::Guest)],
        now(),
    );
    assert!(access.is_visible());
    assert!(!access.allows(Level::Read), "guest must not reveal");
    assert!(!access.allows(Level::Write));
}

#[test]
fn a_read_grant_does_not_permit_a_new_version() {
    let access = resolve(
        &alice(),
        None,
        &[grant(Subject::User("alice".to_owned()), Level::Read)],
        now(),
    );
    assert!(access.allows(Level::Read));
    assert!(!access.allows(Level::Write));
}

#[test]
fn a_token_carries_its_holders_access_and_names_itself() {
    // ADR-0004: a token acts as the person who minted it, and the audit row
    // can say which credential did it.
    let via = alice().via_token("7f3a9c2e");
    let grants = [grant(Subject::Group("SRE".to_owned()), Level::Read)];

    assert_eq!(resolve(&via, None, &grants, now()).level, Some(Level::Read));
    assert_eq!(via.token_id(), Some("7f3a9c2e"));
}

#[test]
fn a_token_holder_with_no_remembered_groups_loses_group_grants() {
    // The consequence ADR-0004 names: without a Directory, a token's groups
    // are whatever was remembered at the last sign-in. Empty means a grant to
    // a team is invisible to it.
    let forgotten = Actor::new("alice", [], []).via_token("7f3a9c2e");
    let grants = [grant(Subject::Group("SRE".to_owned()), Level::Read)];
    assert!(!resolve(&forgotten, None, &grants, now()).is_visible());
}
