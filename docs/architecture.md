# Architecture

How this repository is laid out, which layer may import which, and what to do
when you add a domain or a backend. It describes structure only. The words —
Store, SecretManager, Delegation, Level, Subject, Reveal — belong to
[CONTEXT.md](../CONTEXT.md), and the decisions behind the behaviour belong to
[docs/adr/](adr/). The reusable rules that came out of the same review are in
[patterns.md](patterns.md); this document says where code goes, that one says
what shape it takes.

keyway is the reference implementation of this layout for the author's Go
services. A reader building a new service from these two documents alone should
be able to reproduce the structure without ever opening keyway's code — so
every claim below names the file it came from.

## The three directives

Three rules decide every placement question in this tree, and the rest of the
document is their consequences.

**The layout is forced.** It is the siren layout (`devtools/siren` in the
mikasa monorepo): `config/` at the repository root, `cmd/<binary>/main.go` as the single binding place, domains
directly under `internal/` each owning `entity`, `service` and `infra`, and
transport centralised under `internal/transport/<protocol>/`. It is not
negotiated per service. A second service laid out differently costs a reader
the map they already have.

**Entities validate, and services speak entities.** A rule about what a value
may be lives on the type that carries it, in `entity`. A service loads, asks
and writes; it does not re-derive what a constructor already decided. The
access domain states this outright: the rules live in `entity` and touch
nothing, and `entity.Resolve` is the whole authorisation test
(`internal/access/service/access.go`, package comment).

**Infra translates, it does not decide.** An adapter turns rows or a REST
response into entities and back. Every policy question — how stale an answer
may be, which verbs are permitted, which grants open a secret — is answered
above it. `internal/access/infra/persistence.go` says "translation only", and
notes that nothing there filters by who is asking, because a caller-filtered
query would put half the authorisation rule in SQL.

## The tree

```
config/                     the config file's schema, at the root
cmd/
  api/main.go               keywayd: the cobra tree and the whole of serve()
  cli/                      keyway: the CLI, with its own internal/ tree
internal/
  access/       entity/ service/ infra/
  audit/        entity/ service/ infra/
  identity/     entity/ service/ infra/
  secrets/      entity/ service/ infra/
  tokens/       entity/ service/ infra/
  transport/
    http/                   every domain's handlers, and the router
  postgres/                 the pool, the migrator, and pgtest
  telemetry/                traces and metrics
migrations/                 goose SQL, embedded by embed.go
e2e/                        the compose end-to-end gate
```

### `config/` — at the repository root

`config` is a public package, not an `internal/` one, because it is the
schema of the file an operator writes. `config.Load` reads, resolves
placeholders and validates in one pass, and returns a `config.Config`
(`config/config.go`).

What belongs here: the YAML schema, the closed enums the file's words select
from (`config.StoreKind`, `config.DirectoryKind`), the per-kind settings
getters (`config/settings.go`), and the errors a bad file earns.

What must never appear here: any decision that outlives parsing. `config`
refuses a word the build cannot serve; it does not decide what the word means
once accepted. Note the one import it does make — `config` imports
`internal/secrets/entity` so that a store's `id` becomes a
`secretsentity.StoreID` at the moment it is read (`config/store.go`,
`StoreConfig.UnmarshalYAML`). Configuration is where a deployment's word
becomes a typed value, and that is the only direction that import runs.

### `cmd/<binary>/main.go` — the binding place

`cmd/api/main.go` is one file and holds the cobra tree, `serve()`,
`mountStores()` and the small helpers around them. There is no `wire.go`, no
`app.go`, no `container.go`, and no second file in the package.

The rule: everything that says "this implementation, for this port, in this
process" happens here, in a place a reader finds by opening `main.go`. A
wiring helper file is the same code with an extra hop, and the hop is what
lets a dependency be constructed somewhere nobody thinks to look.

What must never appear here: a decision about meaning. `cmd/api/main.go` used
to read `declared.Settings["project"].(string)` per store kind, and used to
decide which words in `dev_roles` named a role. Both moved out —
the settings reading to `config/settings.go` and the role parsing to
`identityservice.NewDevActor` — and both files say why in their headers.
`main.go` selects and constructs; it does not interpret.

### `internal/<domain>/entity/` — rules, no I/O

The types, their constructors, their invariants, and the ports this domain owns
the vocabulary of. No database, no HTTP client, no `context.Context` where the
type does not need one.

Examples worth reading in order: `internal/secrets/entity/identifiers.go` (the
three identifier types and the reasoning for them),
`internal/access/entity/access.go` (`Resolve`, the whole authorisation test as
one pure function), `internal/tokens/entity/entity.go` (the token format,
minting and verification with no storage anywhere in it).

What must never appear here: an import of `service` or `infra` from the same
domain, and any I/O. `entity` is the layer a test can exercise with no
database and no network.

### `internal/<domain>/service/` — application code

The operations a caller performs, wire-agnostic and storage-agnostic. A service
holds ports as interface fields and is constructed by `New…` taking those
ports (`accessservice.NewService(repo)`,
`identityservice.NewService(repo, directory)`).

The repository port is declared here, not in `infra`:
`accessservice.Repo`, `auditservice.Repo`, `identityservice.Repo`,
`secretsservice.OwnStoreRepo`. The domain says what it needs from storage;
storage does not announce what it offers.

Policy that is not a rule about a single value also lives here — the staleness
window in `identityservice.CachedDirectory`, the `allow`/`select`/`protect`
fence in `secretsservice.Store`.

What must never appear here: SQL, an HTTP request, or a cloud SDK type.

### `internal/<domain>/infra/` — adapters

One file per backing thing. `internal/secrets/infra/` holds `gcp.go`, `yc.go`,
`aws.go`, `k8s.go`, `own_store.go`; `internal/identity/infra/` holds
`keycloak.go`, `oidc.go` and `persistence.go`.

Every adapter asserts the port it fills at compile time, next to its
constructor: `var _ accessservice.Repo = (*PostgresAccessRepo)(nil)`
(`internal/access/infra/persistence.go`),
`var _ identityservice.Directory = (*KeycloakDirectory)(nil)`
(`internal/identity/infra/keycloak.go`),
`var _ identityservice.Issuer = (*Oidc)(nil)` (`internal/identity/infra/oidc.go`).

Row and response shapes stay private to the package — `delegationDTO` in
`internal/access/infra/persistence.go`, `kcUser` and `kcGroup` in
`internal/identity/infra/keycloak.go`. They are translated to entities before
they leave.

What must never appear here: a policy decision. `KeycloakDirectory.Resolve`
asks Keycloak every time it is called and remembers nothing; the caching is
`identityservice.CachedDirectory`'s, and the file says so in its header.

### `internal/transport/<protocol>/` — centralised, not per-domain

`internal/transport/http/` holds every domain's handlers together:
`access.go`, `audit.go`, `identity.go`, `secrets.go`, `tokens.go`, mounted by
`router.go`, over the shared `State`, `Auth`, `Codec` and `ApiError` in
`http.go`, `auth.go`, `session.go` and `error.go`.

Transport is centralised rather than split per domain because the things that
must agree across domains live here: one error vocabulary, one session cookie,
one auth middleware, one router. A per-domain transport package gives each
domain its own opinion about what a 404 means, which is exactly the drift
`error.go` exists to prevent — an unknown Store, an unknown secret and a secret
this caller may not see are all the same 404, deliberately.

Each domain's routes are registered by a `mount…` function in its own file, and
`Build` calls them in order (`internal/transport/http/router.go`).

What must never appear here: an import of any `infra` package. `State.Oidc` is
`identityservice.Issuer`, the port, not `*identityinfra.Oidc` — the field
comment says holding the concrete type is what made reaching a PKCE verifier
from a handler possible in the first place. The transport imports `config` for
`config.Branding` and `config.Verb`, which are wire-visible schema, and nothing
else below the service layer.

A second protocol would be a sibling: `internal/transport/grpc/`, with the same
rule.

### Shared flat packages under `internal/`

`internal/postgres/` is the pool, the migrator and the sqlx-history adoption
(`Connect`, `Migrate`, `adoptSqlxHistory`), plus `pgtest/` for the tests.
`internal/telemetry/` is the Prometheus registry, the metric names and the OTLP
trace provider.

These are flat because they belong to no domain and every domain uses them.
The test for whether something belongs here rather than in a domain: could you
delete a domain and still need this? A connection pool survives; a repository
does not.

What must never appear here: knowledge of a domain's types. `internal/postgres`
knows `config.Postgres` and `*sqlx.DB` and nothing about a Delegation.

### `migrations/` and `embed.go`

Numbered goose SQL at the root, embedded by `embed.go` into `keyway.Migrations`
and handed to goose by `postgres.Migrate`. Migration is its own subcommand
(`keywayd migrate`), never something `serve` does, because three replicas
racing to migrate during a rolling deploy fail in a way nobody can reproduce
(`cmd/api/main.go`, the `migrate` command's `Long`).

### `e2e/`

The compose end-to-end gate: a real PostgreSQL, `keywayd migrate`, `keywayd
serve`, the built CLI and the built dashboard, driven by `e2e/run.sh`. It is
shell and Python on purpose — it asserts what an unchanged client sees, so it
must not share a line of code with the server.

## The dependency rule

Read the arrow as "may import".

```
cmd/api/main.go  ──▶  everything

transport/http   ──▶  <domain>/service, <domain>/entity, config
<domain>/infra   ──▶  own service, own entity, other domains' entity, config
<domain>/service ──▶  own entity, other domains' entity, config
<domain>/entity  ──▶  other domains' entity          (see the exceptions)

postgres, telemetry ──▶ config only
config           ──▶  secrets/entity only
```

And the reverse, which is the half that matters:

- `entity` imports no `service` and no `infra`, in its own domain or any other.
- `service` imports no `infra` and no `transport`. It imports `config`, which
  is the deliberate exception described below.
- `infra` imports no `transport`, and no other domain's `service`.
- `config` imports no `service`, no `infra` and no `transport`.
- Nothing imports `cmd`.

Two things in that table are worth stating plainly because they surprise people
who expect a strict onion.

**`service` may import `config`.** `secretsservice.Store` holds a
`config.StoreConfig` and asks it `Can(verb)`; `secretsservice.KeyringFor` takes
one. This is allowed because `config` is a schema package with no I/O and no
policy — it is closer to `entity` than to `infra`. The alternative, copying the
declaration into a domain struct, produces a second definition of a Store that
can drift from the file an operator edits.

**`infra` may import `config`.** `identityinfra.Discover` takes a
`config.Oidc`, and `postgres.Connect` takes a `config.Postgres`. An adapter is
constructed from a deployment's declaration, so it reads that declaration's
type.

### The two exceptions, at their seams

The rule "entity imports only entity" holds, but two entity-to-entity imports
are one-directional in a way that constrains everything downstream. Both are
documented where they bite, and both are named here so a reader meets them
before the compiler does.

**`identity/entity` imports `access/entity`, for `Subject` and `Level`.**
An `Actor` answers `IsAddressedBy(subject access.Subject)` and
`Ceiling() (access.Level, bool)` — questions phrased in the access domain's
vocabulary — so identity depends on access, and access can never import
identity back.

The consequence is the interesting part. The access and audit domains still
need to ask who is calling, so they declare their own narrow interfaces:
`accessentity.Caller` (`Handle() string`, `IsAdmin()`, `IsAddressedBy`,
`Subjects()`) and `auditservice.Actor` (`Handle() string`, `TokenID()`). Both
speak `Handle() string` and not `identityentity.Handle`, because naming the
typed handle would be the cycle. `identityentity.Actor` satisfies both, and the
conversion happens at that one seam. `internal/identity/entity/names.go` says
this in its header, and `Actor.Handle` repeats it at the method that pays for
it, next to `Actor.Name`, which is the typed accessor for identity's own use.

**`access/entity` and `audit/entity` import `secrets/entity`, for `StoreID` and
`SecretName`.** A grant and an audit row are keyed by a Store id and a secret
name, and those are the secrets domain's concepts. Declaring a third string
type in each domain would mean three types that must agree and no compiler
check that they do. `internal/secrets/entity/identifiers.go` states the rule at
the source: the identifiers live in the secrets domain, and access, audit and
the transport import them rather than re-declaring what they mean.

There are exactly three such imports in non-test code:
`identity/entity → access/entity` (`internal/identity/entity/entity.go`),
`audit/entity → secrets/entity` (`internal/audit/entity/entity.go`), and
`access/entity → secrets/entity` (`internal/access/entity/delegation.go`).

A fourth appears in `internal/access/entity/access_test.go`, which imports
`identity/entity` — the direction the production code cannot take. It is legal
because that file is the external test package (`package entity_test`), which
Go compiles separately, so the test can exercise a real `identityentity.Actor`
against `Resolve` without the production package importing identity. That is
the right tool when a test needs the far side of a seam; it is not a licence to
add the import to the package proper.

The general form: when two domains need the same identifier, it lives in the
domain that owns the concept, and the other imports it. When a domain needs to
ask a *question* of another domain that would close the loop, it declares a
narrow interface in its own package and takes a plain type across the seam.
Write the reason at both ends. Pattern 10 in [patterns.md](patterns.md) is this
rule stated as a habit.

## What `main.go` must look like

`cmd/api/main.go`, read top to bottom, is the shape to copy.

1. **Package comment.** What the binary is, what it is called, and why that
   name. `keywayd` builds from `cmd/api` because the user-facing name belongs
   to the CLI.
2. **`main()`: the cobra tree only.** A persistent `--config` flag, a `migrate`
   subcommand, a `serve` subcommand, `root.Execute()`, `os.Exit(1)` on failure.
   Each `RunE` loads the config and calls one function. No wiring here.
3. **`serve()`, in dependency order:**
   - telemetry first, with a bounded flush deferred, so everything after it is
     instrumented;
   - the database pool, with `defer db.Close()`;
   - the services that need nothing but storage, one line each
     (`accessservice.NewService(accessinfra.NewPostgresAccessRepo(db))`);
   - the optional dependencies, each a `switch` or an `if` over the config with
     the interface left nil when unconfigured — the directory, then the issuer;
   - the things built from a list (`mountStores`);
   - the process-level values (the session codec, the dev actor);
   - the `State` struct that the transport is given;
   - the servers, and `run(ctx, api, metrics)`.
4. **Helpers below `serve()`, each with a doc comment carrying the reason:**
   `run` (signal, drain, `errgroup`), `sessionCodec`, `normalise`,
   `mountStores`.

Two details in `serve()` are load-bearing and easy to lose.

The optional dependencies are declared as the *interface* and left nil:

```go
var issuer identityservice.Issuer
if cfg.Oidc.Issuer != "" {
	discovered, err := identityinfra.Discover(ctx, cfg.Oidc)
	if err != nil {
		return err
	}
	issuer = discovered
}
```

Assigning `discovered` unconditionally would put a nil `*Oidc` inside a
non-nil interface, and every `state.Oidc == nil` check downstream would read
false. The comment in `cmd/api/main.go` says so, and `State.Oidc` in
`internal/transport/http/http.go` repeats the requirement from the other side.

And instrumentation is a constructor parameter, not a global. `mountStores`
takes `observe secretsservice.BackendObserver` and passes it to every
`NewStore`; a nil observer means "not instrumented" and nothing else changes
(`secretsservice.NewStore`, `secretsservice.timed`).

## How to add a new domain

The steps, in the order that keeps the build green at each one.

1. Create `internal/<domain>/entity/`. Write the types and their constructors
   first, with the invariants on the types. If an identifier already exists in
   another domain, import it; do not declare a second one.
2. Write the entity tests alongside, in the same package. Table-driven, and
   testing what the type accepts as deliberately as what it refuses (pattern 2).
3. Create `internal/<domain>/service/`. Declare the ports the domain needs —
   `Repo` at minimum — as interfaces in this package, phrased in entity types.
   Write `Service`, `NewService(ports…)`, and the operations.
4. Write the service tests with in-package fakes implementing those ports. No
   database.
5. Create `internal/<domain>/infra/`. Write the adapter, its private DTO types,
   and `var _ <domain>service.Repo = (*Postgres…Repo)(nil)` beside the
   constructor.
6. Write the infra test against a real PostgreSQL through
   `internal/postgres/pgtest`, keying rows uniquely rather than truncating.
7. Add `internal/transport/http/<domain>.go` with a `mount<Domain>` function
   and the handlers, and call it from `Build` in `router.go`. Add the domain's
   service to `State`.
8. Wire it in `cmd/api/main.go`: construct the repo, construct the service,
   put it on the `State` literal. One line each, in the block with the others.
9. If the domain owns a schema, add a numbered migration in `migrations/`.

If step 3 makes you want to import another domain's `service`, stop: declare a
narrow interface in your own package naming exactly the questions you ask, and
let the other domain's type satisfy it. `accessentity.Caller` is that move.

## How to add a new backend or adapter

The secrets domain is the worked example — adding a SecretManager is the thing
keyway is designed to make cheap — but the shape is the same for any port.

1. Add the word to the closed enum in `config`: a `StoreKind` constant and an
   entry in `config.StoreKinds()`. That alone makes the config file accept it
   and makes `config.UnknownStoreKindError` list it in its message.
2. If the kind needs settings of its own, add a `<Kind>Settings` struct and a
   `StoreConfig.<Kind>Settings()` getter in `config/settings.go`. The getter
   returns a value or a `*MissingSettingError` naming the store and the key.
   The raw keys stay in `StoreConfig.Settings`; the file format does not change.
3. Write `internal/secrets/infra/<kind>.go` implementing
   `secretsentity.SecretManager`. Translate the backend's shapes to
   `entity.Secret`, `entity.Version` and `entity.Metadata`; wrap the backend's
   own failures with `entity.Backend("doing something", err)`. Do not check
   `allow`, `select` or `protect` — the `Store` does that around you
   (`secretsentity.SecretManager`, the interface comment).
4. Add a case to the `switch` in `mountStores` in `cmd/api/main.go`: read the
   settings through the getter, construct the adapter, assign it to `manager`.
   Leave the `default` case alone — it stands so that a kind added to `config`
   and forgotten here fails the boot instead of quietly serving one Store fewer.
5. Test the adapter against recorded response shapes in
   `internal/secrets/infra/<kind>_test.go`.

For a non-secrets port the same five steps collapse to three: declare the port
in the domain that owns the vocabulary, implement it in `infra` with a
compile-time assertion, and select it in `main.go` with a `switch` whose
`default` refuses to start. `identityservice.Directory` and its Keycloak
implementation are the second worked example.

## Where the tests live, and what each layer's tests prove

Tests sit beside the code, in the same package, so a test may reach an
unexported helper. There is no separate test tree.

**`entity` tests prove the rules.** Table-driven over a map of named cases,
`t.Parallel()` at both levels. Their distinguishing habit is that the table
carries an *accepted* half as deliberately as a *refused* half:
`internal/secrets/entity/identifiers_test.go` accepts store ids with spaces,
slashes, dots and Cyrillic because a rule tighter than the one already in force
would orphan a live deployment's grants.
`internal/identity/entity/names_test.go` does the same for handles and group
names. Golden vectors live here too, pinning formats that must not move —
the Rust-minted token in `internal/tokens/entity/entity_test.go`.

**`service` tests prove the application logic, with fakes.** In-package structs
implementing the domain's own ports, and an injected clock where time matters.
`internal/identity/service/directory_cache_test.go` ages the cache by moving a
`func() time.Time`, never by sleeping, and asserts call counts on the inner
fake — that a departed account is not looked up twice, and that a failed lookup
is not cached. No database.

**`infra` tests prove the SQL, against a real PostgreSQL.** `pgtest.DB(t)`
reads `KEYWAY_TEST_DATABASE_URL` and calls `t.Skip` when it is unset, so
`go test ./...` passes on a laptop with nothing running
(`internal/postgres/pgtest/pgtest.go`). It migrates once per process under a
PostgreSQL advisory lock, because `go test ./...` runs packages in parallel and
goose takes no lock of its own. Tests sharing that database key their rows
uniquely — a uuid-suffixed store name — and never truncate, because a TRUNCATE
in one package is data loss in another.

The skip is a trap by construction, so CI closes it: `.github/workflows/ci.yml`
runs PostgreSQL 18 as a service and sets `KEYWAY_TEST_DATABASE_URL`, with a
comment saying that otherwise these tests would pass by doing nothing.

**`transport` tests prove the wire, over `httptest`.** A `world` struct builds
one deployment's state from real services over fakes — a `Registry` over a fake
manager, real `accessservice`, `auditservice`, `tokensservice` and
`identityservice` over in-package fake repos — so a test exercises the whole
stack above storage
(`internal/transport/http/parity_test.go`, `newWorld`). What they pin is
statuses and body shapes: 415 for a missing Content-Type, 400 for unparseable
JSON, 422 for the wrong shape, the `basis` wire string, `?key=` semantics.

**`e2e/run.sh` is the gate.** Compose brings up PostgreSQL migrated the way the
Rust server left it, runs `keywayd migrate` and asserts it adopts the sqlx
history and applies nothing, runs `keywayd serve`, then drives the built CLI
and every endpoint the dashboard's `api.ts` constructs. It is the only place
the binaries, the schema and the clients are exercised together.

The whole gate in CI is four commands:
`test -z "$(gofmt -l cmd config internal embed.go)"`, `go build ./...`,
`go vet ./...`, `go test -race -count=1 ./...`.

## Where keyway differs from siren, legitimately

siren (`devtools/siren`) is the reference this tree was moved to, and the
differences are all consequences of keyway having things siren does not.

siren has one subcommand, `serve`, and no `migrate`, because it keeps no
database — its only persistent state is a JSON file
(`cmd/siren/main.go`, package comment). keyway has PostgreSQL, so it has
`migrations/`, `internal/postgres/`, and a `migrate` subcommand that is
deliberately not part of `serve`.

keyway ships a second binary, `cmd/cli`, and it does not import the server's
packages at all. It defines its own wire types under
`cmd/cli/internal/{wire,output,profile}` — depending on the server's packages
would compile the database driver and four cloud SDKs into a binary that
formats output (`cmd/cli/main.go`, package comment). A `cmd/<binary>/internal/`
tree is the right home for code that belongs to one binary and nothing else.

siren keeps `internal/source/` and `internal/richtext/` as flat shared
packages; keyway's equivalents are `internal/postgres/` and
`internal/telemetry/`. Same rule, different nouns.

Everything else is identical: `config/` at the root, `cmd/<binary>/main.go` as
the binding place with the whole of `serve()` in it, `internal/<domain>/`
holding `entity`, `service` and `infra`, and `internal/transport/<protocol>/`
centralised — siren's is `internal/transport/{http,telegram}/`.

## How to verify this document is still correct

Run these when the tree moves. Each one fails loudly if a claim above has gone
stale.

- The layout: `ls config cmd/api internal/transport/http` succeeds, and
  `ls internal/*/entity internal/*/service internal/*/infra` lists five domains.
- `cmd/api` is one file: `ls cmd/api` prints `main.go` and nothing else.
- The dependency rule, in the direction that matters:
  `go list -deps ./internal/access/entity | grep keyway` names no `service`,
  `infra` or `transport` package, and
  `grep -rn '/infra"' internal/transport/` finds nothing.
- The two exceptions are still the only ones:
  `grep -rn 'keyway/internal/[a-z]*/entity"' internal/*/entity/*.go | grep -v _test`
  returns exactly three lines — identity→access, audit→secrets and
  access→secrets.
- No mutable package-level seam has come back:
  `grep -rn '^var [A-Z][A-Za-z]* func' internal/` returns nothing.
- The test convention holds: `grep -rn 'KEYWAY_TEST_DATABASE_URL' .` finds it
  in `internal/postgres/pgtest/pgtest.go` and `.github/workflows/ci.yml`.
- The gate itself: `gofmt -l cmd config internal embed.go` is silent,
  `go build ./...` and `go vet ./...` are green, and `go test ./...` passes.

## Related

- [CONTEXT.md](../CONTEXT.md) — the domain vocabulary. Read it first.
- [patterns.md](patterns.md) — the numbered pattern catalogue this layout
  assumes.
- [adr/0007-keyway-is-the-go-services-reference-layout.md](adr/0007-keyway-is-the-go-services-reference-layout.md)
  — the decision that produced both documents.
- [adr/0006-go-port-keeping-the-wire-and-schema.md](adr/0006-go-port-keeping-the-wire-and-schema.md)
  — the port, and the layout rule this review superseded.
