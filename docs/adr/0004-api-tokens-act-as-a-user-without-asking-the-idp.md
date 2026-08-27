# API tokens act as a user without asking the identity provider

A `kw-<id>-<secret>` token binds to a user subject and acts as that person.
keyway resolves the grants addressed to them from its own tables, and takes
their groups from the claim it remembered at their last sign-in — it calls the
identity provider on no request at all. An optional Directory, off by default,
replaces the remembered groups with a live lookup and adds an account-enabled
check.

locker did the opposite: it stored only a subject and re-asked Keycloak on every
request, which is what made "disable the account and every token it issued dies
within minutes" true for free. That design cannot be ported. It reads Keycloak's
admin REST API — `serviceAccountsEnabled` plus `view-users` — and ADR-0003 made
identity generic OIDC, which specifies no such API. Okta, Auth0 and Entra each
expose something different, and plain OIDC offers only `userinfo`, which needs
an access token for the very user whose token is absent.

**Consequences.** Out of the box, deleting a token is the only way to revoke it:
an offboarded employee's token keeps working until someone removes it, and the
offboarding checklist is the control. Deployments that want the old property
configure a Directory and buy it back — for Keycloak that is one flag and one
role mapping on the confidential client keyway already holds. Remembered groups
can also go stale, bounded by how often the person signs in; minting a token
requires a browser session, so they are never empty.
