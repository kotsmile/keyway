# Identity is generic OIDC, configured per deployment

keyway reads identity from any OIDC issuer, with the claim names and the group
root given in the config file. It assumes nothing about how groups are spelled.
locker assumed a great deal — a `/g:longyai` root as a constant in domain code,
`g:`/`r:` prefixes on every path segment, and role selectors that resolved a
group by matching a *suffix* of its path — all of which are one organization's
tree conventions rather than anything Keycloak provides. None of it is
deployable by a stranger, which for an open-source secrets console is
disqualifying.

**Consequences.** Two guarantees that came free from Keycloak paths have to be
re-earned. A groups claim may now yield bare names, so a Delegation records its
Subject's kind explicitly instead of inferring "group" from a leading slash —
otherwise a team called `sre` and a person called `sre` are the same row. And
nothing hierarchical can be assumed of a group name, so a grant to a parent
group no longer covers the teams inside it by string matching; an issuer that
wants that must expand ancestors into the claim itself.
