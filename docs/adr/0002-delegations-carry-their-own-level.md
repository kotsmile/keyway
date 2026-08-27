# Delegations carry their own level

A Delegation records the Level it grants, and nothing caps it afterwards. In
locker a delegation named only *who*, and the grantee's group role capped *how
far* — two gates, neither of which opened a secret alone. That design existed
because another internal service (warden) approved who held which role, so a
secret's owner could not escalate anyone past it. keyway has no warden, and
without one the ceiling is intricate machinery guarding a property nobody
enforces.

**Consequences.** "Who can see this secret, and how far" is answered by reading
one list, and roles shrink to what a person may do irrespective of any secret.
The cost is real: an owner may now grant `write` to someone an organization
considers read-only, and no keyway role prevents it. A deployment that needs
that guard needs a ceiling putting back — see ADR-0003 for why the per-group
form of it could not have survived anyway.
