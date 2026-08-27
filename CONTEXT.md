# keyway

The secrets console: an aggregator over the secret managers an organization
already runs, which owns who may see what and records every look.

## Language

### Backends

**SecretManager**:
keyway's port to one kind of backing service — GCP Secret Manager, YC Lockbox,
AWS Secrets Manager, Kubernetes Secrets, keyway's own store. It is CODE: one
implementation per kind, named by a **Store**'s `type:`. Adding a backend means
writing one of these and nothing else.
_Avoid_: adapter, provider, driver, platform, backend.

**Store**:
One CONFIGURED backing service, declared in the config file with an `id`, a
`type` naming its **SecretManager**, an `allow` list and its credential. The
`id` is what a **Secret** belongs to and what delegation, ownership and audit
rows are keyed by, so it is chosen once and left alone.
_Avoid_: platform, provider, vault, secret manager (one word, capitalised, is
the code; a Store is one deployment's use of it).

**Allow**:
What this deployment may do in one **Store** — `read`, `edit`, `create`,
`delete`, each gating one part of the **SecretManager** trait. Four verbs rather
than a `readOnly` flag because the interesting case is the shared production
project keyway may read and amend but must never create or destroy in.

**Select**:
Which of a backing service's secrets a **Store** exposes at all. Every
**SecretManager** maps it to its backend's own filter — labels in GCP, YC and
Kubernetes, tags in AWS. Scoping is a property of aggregating somebody else's
secret manager, not of any one backend: a cluster is full of service-account
tokens and a shared project is full of other teams' credentials, and neither
belongs in the console.

**Protect**:
Which secrets a **Store** shows but refuses to edit, matched on labels and
annotations. It exists because a secret can be owned by a reconciler — External
Secrets, Argo CD, Helm — and an edit keyway accepts there is an edit the next
reconcile silently discards. The defaults name those three; a deployment
overrides them for its own tooling.

### Configuration

**Config file**:
The single file a keyway deployment is configured by. Every value in it is a
string, including the credentials — there is no second channel, no `os.Getenv`
for a setting of its own.
_Avoid_: env config, settings, values (a chart's `values.yaml` renders this
file, it is not this file).

**Placeholder**:
A `${env:NAME}` in the **Config file**, resolved from the environment. It is
namespaced by source rather than a bare `${NAME}`, so a second source can be
added later without the syntax having to change meaning. An unresolved one is
fatal at boot: a deployment that starts with a credential missing is a
deployment that fails on first use instead.
_Avoid_: env var (the variable is one; the placeholder is the reference to it).

### Secrets

**Secret**:
An entry in a **Store**, addressed by **uuid** and never by name. Its payload
stays in the backing store; what keyway's own database holds is who owns it, who
it is delegated to, and who read it.
_Avoid_: credential (that is the value inside), key (that is one kv entry of it).

**Version**:
One immutable revision as the **Store** records it. No secret manager records
who wrote a version — that gap is exactly what keyway's audit log fills.

**Reveal**:
Reading a **Secret**'s value. Always audited — the reason the word exists
separately from "read".

**Ownership**:
The creator's standing over a **Secret**: change, delete, delegate, transfer. At
most one owner, because an owner is who you *ask* about a secret. Orthogonal to
any role — an owner runs their secret whatever role they hold.

**Delegation**:
A grant over one **Secret**, or over one kv key of it, to a **Subject**, at a
**Level**, optionally with an expiry. It is self-describing: what it says is
what it opens, and nothing else caps it. The grantee still cannot re-delegate it
or transfer it — those belong to **Ownership**.
_Avoid_: share, permission, access grant.

**Level**:
How far a **Delegation** opens its **Secret**: `guest` sees that it exists and
which keys it has, `read` may **Reveal** the values, `write` may also push a new
version. An order, not a set — a comparison is the whole authorisation test.
_Avoid_: permission, scope, viewer/readonly/readwrite.

### Identity

**Subject**:
Who a **Delegation** is addressed to: a person or a **Group**, and which of the
two is recorded EXPLICITLY rather than inferred from the shape of the name. A
team called `sre` and a person whose handle is `sre` are two different subjects.
_Avoid_: principal, grantee, recipient.

**Group**:
A set of people keyway learns from the session's groups claim, never from a
membership list of its own. What a claim yields — a bare name, a path — is the
issuer's business, and keyway matches the name exactly: it parses no structure,
so an issuer wanting a grant to a parent group to cover the teams inside it puts
the ancestors in the claim.
_Avoid_: team, org unit, role (a role is what a person holds, a group is who
they are with).

**Actor**:
Who is asking, resolved once at the edge: a handle, the **Groups** they belong
to, and the **Roles** they hold. A browser session reads all three from the
claim; an **API token** names a handle and takes the groups **keyway
remembered**.

**Remembered groups**:
The groups claim as it stood at a person's last sign-in, kept so an **API
token** — which carries no claim of its own — can act as that person in full. It
is refreshed by every login and is what a **Directory**, when one is configured,
replaces with a live answer.
_Avoid_: cached groups, snapshot (a snapshot is frozen; this is refreshed).

**API token**:
A `kw-<id>-<secret>` credential keyway issues itself, for a caller that can hold
no browser session — External Secrets, CI, the CLI. It acts as the person who
minted it and carries no grants of its own. The `id` is public, so an audit row
names which token acted; only the secret half is stored, hashed, and the
plaintext exists once, in the response that created it.
_Avoid_: offline token, service token, API key.

**Directory**:
An optional live connection to the identity provider, off unless configured. It
answers what a **Directory**-less deployment can only remember: which **Groups**
a subject is in right now, and whether their account is still enabled — so
disabling somebody cuts every **API token** they issued. Without one, deleting
the token is the only revocation.
_Avoid_: admin API, user store, IdP sync.

**Role**:
What a person may do irrespective of any one **Secret** — administer keyway, or
bring new secrets into the inventory. Roles do not cap a **Delegation** and are
not how sight of a secret is granted; that is the delegation's own job.
_Avoid_: ceiling, permission, access level (that is **Level**, which is a
property of a grant, not of a person).

## Model

- A **Secret** lives in exactly one **Store**, has exactly one owner, and has
  any number of **Delegations**; a **Reveal** by anyone is an audit row.
- A **SecretManager** is code and a **Store** is configuration: two Stores may
  name the same SecretManager — a production project and a sandbox one — and
  each carries its own `allow` and its own credential.
- Handing over the right to delegate or to change a payload is a transfer of
  **Ownership**, which is a different act with its own audit line.
- A **Delegation** names its **Subject**'s kind outright, so nothing depends on
  a handle and a **Group** name being told apart by how they are spelled.
- **Group** membership is the issuer's answer. A session reads it from the
  claim, an **API token** uses the **Remembered groups**, and a **Directory**
  replaces both with a live lookup — keyway stores the name a grant was made to
  and never a membership list of its own.
- A **Delegation** and an **Ownership** are the only two things that open a
  **Secret**. A **Role** opens none of them: "who can see this, and how far" is
  answered by reading one list of grants.
- An **API token** never widens what its holder could already do, and minting
  one passes through a browser session — so the **Remembered groups** behind it
  were always seeded by a real sign-in.
- A **Store** answers for its own scope: **Select** decides what it holds,
  **Allow** what this deployment may do across it, and **Protect** what it must
  not touch because a reconciler owns it.
