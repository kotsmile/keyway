# keyway

A secrets console over the secret managers you already run.

keyway doesn't replace GCP Secret Manager, Lockbox or AWS Secrets Manager — it
sits over them and owns the two things none of them answer: **who may see what**,
and **who looked**.

Payloads stay in the backing store. What keyway's own database holds is who owns
a secret, who it is delegated to, and every read.

```
$ keyway list
7b0d1e2f-3a4b-5c6d-8e9f-0a1b2c3d4e5f  gcp-prod  payments-db   (read)
2849559a-b458-5ea6-a3f0-d8ab9be7f8b4  local     ci-signing    (write)

$ export DB_PASSWORD=$(keyway get 7b0d1e2f-… -k db_password)
```

## Try it

No cloud account needed — the quickstart uses keyway's own encrypted store.

```bash
git clone https://github.com/kotsmile/keyway && cd keyway
docker compose up
```

Then open <http://localhost:8081> for the console; the API is on `:8080`. The quickstart runs with **no authentication**
and acts as a dev user; see [Authentication](#authentication) before pointing it
at anything real.

## What it does

**Aggregates.** One console over every secret manager you run. Adding a backend
means writing one `SecretManager` implementation and nothing else.

**Delegates.** A grant names a subject — a person or a group — and the level it
opens: `guest` sees a secret exists and which keys it has, `read` may reveal it,
`write` may push a new version. A grant can be scoped to individual keys of a
key/value secret, which is what makes it safe to keep a bot's credentials in one
secret and hand out exactly one of them.

**Audits.** Every action, reads included. For a secrets tool the interesting
question is far more often *who looked at this* than *who changed it*.

**Serves External Secrets.** Point a `ClusterSecretStore` at keyway and a team
hands a secret to its cluster by writing one grant — no admin, no infrastructure
change. See [docs/external-secrets.md](docs/external-secrets.md).

## Configuration

One file. Every value is a string, credentials included; a `${env:NAME}`
placeholder pulls one out of the environment, and an unresolved one is fatal at
boot rather than on first use.

```yaml
server:
  address: ":8080"
  metrics_address: ":9090"   # deliberately not the API's port

postgres:
  addr: localhost:5432
  name: keyway
  user: keyway
  password: ${env:PGPASSWORD}

oidc:
  issuer: https://id.example.com/realms/acme
  client_id: keyway
  client_secret: ${env:OIDC_SECRET}
  groups_claim: groups

stores:
  - id: gcp-prod
    type: gcp
    title: Google Cloud (production)
    allow: [read, edit]        # not create, not delete
    project: acme-prod
    select:
      labels: { keyway: "true" }
```

**`allow`** is four verbs rather than a read-only flag, because the interesting
configuration is neither end of that boolean: it's the shared production project
keyway may read and amend but must never create or destroy in.

**`select`** scopes what a Store exposes at all — a cluster is full of
service-account tokens and a shared project is full of other teams' credentials,
and neither belongs in a console.

**`protect`** marks secrets that are visible but not editable because a
reconciler owns them. It defaults to the markers External Secrets, Argo CD and
Helm set, so an edit keyway would accept and the next reconcile would silently
discard is refused with a message naming the owner instead.

## Authentication

Three doors:

| | |
| --- | --- |
| **Browser session** | OIDC against any issuer; claim names come from config |
| **API token** | `kw-<id>-<secret>`, for External Secrets, CI and the CLI |
| **Dev mode** | with no `issuer` configured, keyway acts as `dev_user` |

Dev mode still makes every authorisation decision — a local run behaves like
production minus the redirect — but it authenticates nobody. It logs a warning at
startup, and it is what `docker compose up` uses.

A token acts as the person who minted it and carries no grants of its own.
**Without a Directory configured, deleting a token is the only way to revoke it**
— disabling the account in your identity provider does not cut it, because
keyway never asks. That trade is deliberate and written up in
[ADR-0004](docs/adr/0004-api-tokens-act-as-a-user-without-asking-the-idp.md).

## The CLI

```bash
keyway login https://keyway.example.com   # opens the console to mint a token

keyway list --store gcp-prod
keyway view <uuid>                        # metadata; not a reveal
keyway get  <uuid> -k db_password         # the value; audited
keyway create --store local --name ci-signing --value -   # `-` reads stdin
keyway patch <uuid> --value -
keyway delegate <uuid> --group SRE --level read --key db_password
```

`--json` and `--yaml` on every command.

There is no `keyway delete` and no ownership transfer, deliberately: a script may
widen access but must never destroy a secret. The reasoning is in
[ADR-0005](docs/adr/0005-the-cli-may-grant-access-but-not-destroy-secrets.md).

## Running it

Build from source (Go 1.26+):

```bash
go build -o keywayd ./cmd/api   # the server
go build -o keyway  ./cmd/cli   # the CLI
```

The dashboard builds separately — see `keyway-dashboard/` (pnpm; the compose
quickstart and the Helm chart use its published image).

```bash
keywayd --config config.yml migrate   # its own command, never on boot
keywayd --config config.yml serve
```

`migrate` is separate on purpose: three replicas racing to migrate during a
rolling deploy fail in a way nobody can reproduce.

Metrics are Prometheus text on the metrics port. They are labelled by Store and
outcome and **never by secret name** — a label is a time series per distinct
value, so naming secrets there would both explode cardinality and publish the
inventory to anyone who can reach a scrape endpoint. Traces go to OTLP when
`telemetry.otlp_endpoint` is set, and nowhere otherwise.

## Understanding the code

- **[CONTEXT.md](CONTEXT.md)** — the vocabulary. Store, SecretManager, Delegation,
  Level, Subject, Reveal. Worth ten minutes before reading any code.
- **[docs/adr/](docs/adr/)** — why things are shaped as they are, including the
  decisions a reader would otherwise reasonably want to reverse.

The backend is laid out by domain (`internal/{secrets,access,identity,tokens,audit}`).
Each owns its `entity` (rules, no I/O), `service` (application code) and
`infra` (adapters); the HTTP handlers for all of them live together in
`internal/transport/http`, and `config/` sits at the repo root.
Services depend on the repository interfaces their domain declares, so the
rules are testable with no database and no network.

## Status

Early, but complete end to end: the own store, the HTTP API, API tokens, the
audit log, the External Secrets contract, the CLI, OIDC sign-in and the console
are all built and working.

The four cloud adapters — GCP, Yandex Lockbox, AWS and Kubernetes — are written
and unit-tested against recorded response shapes, but **have not been run
against a real backend**. Point one at a sandbox project before trusting it.

## Licence

MIT.
