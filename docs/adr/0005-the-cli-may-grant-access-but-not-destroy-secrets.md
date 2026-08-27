# The CLI may grant access but not destroy secrets

The CLI is `list`, `get`, `view`, `create`, `patch`, `delegate` and `login`, with
`--json` and `--yaml` on all of them. It deliberately has no `delete` and no
ownership transfer: those stay in the console.

The split is by blast radius rather than by read/write, which is why it looks
inconsistent at first glance. `delegate` is scriptable because managing access
alongside the infrastructure that needs it is a real workflow and a mistaken
grant is visible in the audit log and revocable in a click. Deleting a secret is
neither — it loses data, and a non-interactive `delete` in a CI script is the
one operation with no undo. Ownership transfer is left out for a different
reason: it changes who is answerable for a secret, which is a conversation
rather than a command.

`get` reveals a value and is audited; `view` returns metadata only and is not.
Splitting them means browsing from a terminal never fills the audit log with
reveals nobody performed.

`login` opens the frontend to mint a token rather than minting one over the API.
That keeps every token's remembered groups (ADR-0004) seeded by a real sign-in,
and it means the CLI never holds a credential that can create more of itself.
