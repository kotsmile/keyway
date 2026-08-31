# Patterns

Fifteen rules this codebase applies consistently, each one written down because
it was learned from a specific failure rather than chosen from a catalogue.
They are numbered so they can be cited in review — "this is pattern 7" — and
each carries the failure it prevents, a real place in keyway to read it, and
what it looks like in a service that is starting from nothing.

Structure is [architecture.md](architecture.md)'s subject; this document is
about shape. The vocabulary is [CONTEXT.md](../CONTEXT.md)'s.

Some of these are general Go practice stated sharply. Some are specific to a
system where the cost of a mistake is somebody seeing a secret they should not.
Where that is the reason, it says so, because a service with a different cost
profile may reasonably choose differently — and should do so knowingly.

---

## 1. Identifier value objects live in the domain that owns the concept

**Rule.** Every identifier is a named string type with a `New…`/`Parse…`
constructor and a `String()`, declared once in the domain that owns the
concept; every other domain imports it rather than declaring a third string.

**Why.** Three strings that must agree and no compiler check that they do. A
Store id spelled `string` in access, `string` in audit and `string` in secrets
is three definitions of one thing, and nothing catches the day they drift.
Worse, bare strings are interchangeable at a call site: see pattern 3.

**In keyway.** `internal/secrets/entity/identifiers.go` declares `StoreID`,
`SecretName` and `VersionID` with `NewStoreID`, `NewSecretName` and the
`String` methods. `internal/access/entity/delegation.go` and
`internal/audit/entity/entity.go` import them; so does `config`, in
`config/store.go:StoreConfig.UnmarshalYAML`, which is where a deployment's
word becomes a `StoreID`. The identity domain does the same for its own
concepts in `internal/identity/entity/names.go`: `Handle` and `GroupName`,
with `NewHandle` and `NewGroupName`.

They are named string types, not opaque structs with a hidden field. That is a
compromise, stated in the file: a conversion is still possible where a caller
insists, but nothing does it by accident, and in exchange the types marshal,
bind and scan exactly as the strings they replaced — so neither the wire nor
the database schema moves when you introduce them.

**In a new service.** Name every identifier the moment two packages pass it.
Put it in the package that defines what it means, give it a constructor that
refuses the values that would be silently wrong, and let every other package
import it. Do not reach for a UUID wrapper struct if the value has to keep
landing in the same column.

---

## 2. The must-not-refuse test table

**Rule.** When you introduce a type over data that already exists, test what it
must accept with the same care as what it rejects, and say in the table why
each accepted case is there.

**Why.** A constructor is a validation rule, and a validation rule introduced
over live data is a migration. A `StoreID` that refuses spaces renames somebody
production Store, and renaming one orphans every delegation, ownership and
audit row keyed by it. The refusal half of a test table is easy to write and
easy to over-tighten; the acceptance half is what stops you.

**In keyway.** `internal/secrets/entity/identifiers_test.go:TestAStoreIDMustNameAStore`
accepts `acme.prod`, `the vault`, `team/prod`, `PROD` and `хранилище`, each
with a comment saying these are ids some deployment has already keyed its
grants by. `TestASecretNameMustNameASecret` accepts `a/b`, `payment bot`, `..`
and a 300-byte name, because a name is somebody else's contract — an External
Secrets manifest, an existing tool — and a backend that dislikes one says so at
the call, where the reason can be specific.
`internal/identity/entity/names_test.go:TestAHandleMustNameSomebody` accepts an
email, a uuid, `Alice A.`, `алиса` and `ACME\alice`, and asserts the handle is
*not* trimmed, because it is compared exactly against what a grant was written
to.

**In a new service.** Write the accepted column first, from real data. If you
cannot name a caller for an accepted case, you are guessing; if you cannot name
a failure for a rejected case, you are over-validating. The file header should
say which of the two halves is the load-bearing one.

---

## 3. Type adjacent arguments before anything else

**Rule.** When two or more parameters of the same underlying type sit next to
each other in a signature, give them distinct named types — that pair is the
swap the compiler currently allows.

**Why.** `Access(ctx, name, version)` and `GrantsOn(ctx, store, secret)` are
signatures where transposing two strings compiles cleanly and reads a
different secret's value. This is not a hypothetical class of bug; it is the
one class the system exists to prevent, and the type system will do the check
for free.

**In keyway.** The header of `internal/secrets/entity/identifiers.go` names the
three call shapes that motivated the types: `Access(ctx, name, version)`,
`AAD(store, name, version)`, `GrantsOn(ctx, store, secret)`.
`secretsentity.SecretManager.Access` carries the point in its own doc comment —
"the name and the version are separate types on purpose: this is the signature
where passing them the wrong way round would read a value under an id nobody
asked for". `accessservice.Repo.GrantsOn` and `OwnerOf` take
`(store secrets.StoreID, secret secrets.SecretName)`.

**In a new service.** Grep your interfaces for two consecutive `string` or
`int64` parameters. Those are the ones to type first — before the identifiers
that only ever appear alone, which are lower value. Ordering the work this way
gets the safety early.

---

## 4. A redacting value type for anything secret, with one named exit

**Rule.** A credential in flight gets its own type whose `String()` and
`LogValue()` both redact, and exactly one method — named so that reading a call
site tells you a secret is leaving — returns the real value.

**Why.** A plain `string` field reads like every other field in the struct, so
it reaches a log line through `%v`, through an error wrapping, or through a
struct dump, and nobody reviewing the code notices. Redaction that is enforced
by the type cannot be forgotten; redaction that is a convention will be.

**In keyway.** `internal/tokens/entity/entity.go:Plaintext` is a named string
type. `Plaintext.String` returns the constant `Redacted` (`kw-<redacted>`);
`Plaintext.LogValue` returns the same as an `slog.Value`;
`Plaintext.Expose` returns the real thing and is called in exactly one
non-test place, `internal/transport/http/tokens.go`, in the response that
minted the token. `internal/tokens/entity/entity_test.go` asserts all three.

Two mechanical details matter when you copy this. `slog` asks for `LogValue`
before it asks for `String`, so both are needed — `String` alone leaves an
`slog` attribute unredacted. And `encoding/json` honours neither: it marshals a
named string type as its underlying string. In keyway that is deliberate, and
the type says so — the one response body carrying a token must carry it
verbatim. In a service where the credential must never be serialised, add a
`MarshalJSON` that refuses or redacts, and test it.

The type also does not attempt to scrub memory. The doc comment says why: Go's
garbage collector moves and copies strings, so pretending to zero one would be
theatre. Redaction is the discipline that can actually be enforced.

**In a new service.** One type per credential shape, three methods, one audited
exit. Assert the redaction in a test, and assert the `Expose` call sites by
counting them.

---

## 5. Accept-and-warn is a named function returning `(kept, dropped)`

**Rule.** Where a list from outside may contain entries this build cannot
interpret, write one function that returns both the entries it kept and the
ones it dropped, and make every caller log what it dropped.

**Why.** Accept-and-warn as a habit becomes accept-and-be-silent. A `continue`
inside a loop at each call site is invisible: a deployment that misspelled
`admn` in `dev_roles` gets a console with the admin button missing and nothing
anywhere saying why. Returning the dropped entries makes the logging the
caller's obligation rather than its option, and puts the decision — that
dropping is right here, and refusing the whole set is not — in one place with
its reasoning.

**In keyway.** `internal/identity/entity/entity.go:ParseRoles` returns
`(roles []Role, unknown []string)`, and its comment gives the reason: role
words arrive from a realm that may carry roles belonging to other systems
entirely, so refusing the whole set over one unknown word would lock somebody
out of a console because their realm also runs a wiki — and granting something
for a word this build cannot interpret would be worse.
`internal/identity/entity/names.go:GroupNamesOf` returns
`(groups []GroupName, dropped []string)` for the same reason.
`internal/identity/service/dev.go:NewDevActor` calls both and logs each drop
with the words dropped and the words this build knows.
`internal/identity/entity/names_test.go:TestAnUnusableGroupIsDroppedRatherThanFailingTheClaim`
asserts both halves of the return.

Note where the same domain chooses the opposite: `accessentity.ParseLevel`
returns an error, because a delegation whose level failed to parse is one
nobody can reason about, and guessing the weakest reading still guesses. The
difference is whether the unusable entry is one of many or the whole answer.

**In a new service.** Any time you write `continue` over data from a claim, a
config file or another system, ask what tells the operator. If the answer is
"nothing", make the function return the drops.

---

## 6. Policy decorates a port; it does not live inside an adapter

**Rule.** Caching, retries, rate limiting and staleness windows go in a type
that implements the port and wraps another implementation of it, in the
`service` package. An adapter asks its backend every time and decides nothing.

**Why.** "How long may an answer be trusted" is a statement about how fast a
revocation must bite. That is the domain's policy, and it must be true of every
implementation of the port, not just the one that happened to grow a cache. Put
it in the adapter and the second adapter has different security properties,
silently. Put it in the service's authorisation path as a branch and the path
now differs by where an answer came from, which is exactly what must not
happen.

**In keyway.** `internal/identity/service/directory_cache.go:CachedDirectory`
implements `identityservice.Directory` and wraps one, with
`DefaultStaleness = 5 * time.Minute` declared beside it. Its comment states the
payoff: written down in one place, "disabling an account cuts every API token
it issued, within this window" is a sentence ADR-0004 can make.
`identityservice.Directory`'s own comment says what the port deliberately
excludes — caching — and that an implementation is expected to ask its provider
every single time. `internal/identity/infra/keycloak.go` complies and says so
in its header. `cmd/api/main.go` composes them:
`identityservice.NewCachedDirectory(keycloak, identityservice.DefaultStaleness, time.Now)`.

Two details worth copying. A failed lookup is deliberately not cached, so a
provider that is down does not fix its answer in place for five minutes. And a
*negative* answer is cached — "gone from the directory entirely" — because a
token a reconcile loop presents every minute would otherwise turn a dead
account into a load test.

**In a new service.** Declare the port without the policy. Write the decorator
in the same package as the port. Compose them in `main.go`. State in the port's
doc comment what implementations must *not* do.

---

## 7. No mutable package-level seams

**Rule.** Anything `main` assigns is a constructor parameter. There are no
package-level `var Something func(…)` hooks. A nil dependency means "not
instrumented", and nothing else changes.

**Why.** A mutable global assigned from `main` is a dependency that nothing
declares. It does not appear in a constructor, so a reader of the call site has
no way to know where it came from; two tests cannot hold different opinions
about it; and with `-race` a test that sets it races anything that reads it.

**In keyway.** `internal/secrets/service/store.go:BackendObserver` is a
function type taken by `NewStore(cfg, manager, observe)`, and its doc comment
records what it replaced: "a dependency of a Store, passed to the constructor,
rather than the package-level variable this used to be… Everything else keyway
wires is wired in main.go by name, and so is this."
`cmd/api/main.go:mountStores` takes the observer as a parameter and passes it
to every `NewStore`. `secretsservice.timed` treats a nil observer as
"not instrumented" and calls straight through, which is what the transport
tests pass (`internal/transport/http/parity_test.go:newWorld` constructs its
Store with `nil`).

The same rule applies to clocks. `CachedDirectory` takes `now func() time.Time`
so a test can age the cache without sleeping; `internal/transport/http`'s
`State.Now()` reads one clock through the auth state so a whole request agrees
on one source of time.

The stale comment this rule leaves behind is worth naming, because it is what
made the old global survive as long as it did:
`internal/telemetry/telemetry.go:Telemetry.BackendCall` went on describing the
variable it used to be assigned to for a whole pass after that variable was
deleted. A doc comment that names a seam has to move when the seam does, and
nothing in the toolchain will tell you it has not.

**In a new service.** Grep for `^var [A-Z][A-Za-z]* func` and for `time.Now()`
called inside a domain package. Both are the same smell. Injecting a nil-able
observer costs one parameter and buys a test that can assert what was recorded.

---

## 8. Closed config enums, per-kind settings getters, refused at parse

**Rule.** A word in the config file that selects a compiled-in implementation is
a typed closed list refused during parsing, with the same error type the later
lookup would raise; the settings only one kind needs get a typed getter rather
than an inline map assertion.

**Why.** Two separate wins. Refusing at parse means the message names the wrong
word before anything has connected to anything — an unknown `type:` reported at
mount time arrives after a cloud client has already been built. And reusing the
error type means the sentence an operator reads is identical wherever the
refusal happens, so the two cannot drift into contradicting each other.

The settings half prevents a quieter failure: `declared.Settings["project"].(string)`
repeated per kind, each with its own `ok` to forget, inside a `switch` in
`main.go`. That is configuration decoding wearing a switch statement.

**In keyway.** `config/store.go` declares `StoreKind`, the five constants,
`StoreKinds()`, `ParseStoreKind` and `UnknownStoreKindError`, whose message is
built from `StoreKinds()` so adding a kind updates the sentence.
`config/config.go` does the same for `DirectoryKind` with
`DirectoryKind.UnmarshalYAML` and `UnknownDirectoryError`, and for
`config.Verb` with `Verb.UnmarshalYAML`. `cmd/api/main.go` switches over the
already-validated kinds and its `default` returns the *same*
`&config.UnknownStoreKindError{…}` and `&config.UnknownDirectoryError{…}`.

`config/settings.go` holds `GcpSettings`, `YcSettings`, `AwsSettings`,
`K8sSettings` and `KeywaySettings` with a getter each, returning either a value
or a `*MissingSettingError` naming the store and the key. Its header records
what moved and why. Note two judgements in it: a non-string value reads as
absent, because every value in the config file is a string and a
`namespace: 123` is a typo rather than an int to coerce; and
`KeywaySettings()` never fails, because which keys are usable is the keyring's
judgement and it gives a better error.

**In a new service.** One typed enum per selector word. `UnmarshalYAML` (or
`UnmarshalText`) that refuses. One error type, used at parse and at selection.
A settings struct and getter per kind, in the config package, never in `main`.

---

## 9. Ports go where the vocabulary lives; DTOs go with the port

**Rule.** Declare an interface in the domain when that domain owns the words it
is phrased in, and in the consumer when it does not. The types the port speaks
move with the port, so no layer above ever imports `infra`. Watch for the
typed-nil interface at every optional port.

**Why.** A port declared in `infra` is storage announcing what it offers, which
inverts the dependency the layering exists to establish. A port declared in the
domain but phrased in another domain's types creates a cycle. And a port whose
DTOs live in `infra` drags `infra` into every package that calls it, which is
how a handler ends up able to reach a PKCE verifier.

**In keyway, all three cases.**

*The domain owns the vocabulary, so the port is the domain's.*
`identityservice.Directory` and `identityservice.Issuer` are declared in
`internal/identity/service/identity.go`. The `Issuer` comment states the test:
"the port is declared here rather than in the transport that calls it, because
`Pending` and `SignedIn` are this domain's vocabulary". Their DTOs —
`Pending`, `SignedIn`, `DirectoryAnswer` — sit in the same file.
`internal/identity/infra/oidc.go` and `keycloak.go` implement them and assert
it (`var _ identityservice.Issuer = (*Oidc)(nil)`).

*The consumer does not own the vocabulary, so the port is the consumer's.*
`accessentity.Caller` in `internal/access/entity/access.go` names exactly the
four questions the access domain asks about whoever is calling; its comment
says that in Rust this was the identity domain's `Actor` outright, and in Go
that import would be a cycle. `auditservice.Actor` in
`internal/audit/service/audit.go` does the same with two methods.
`identityentity.Actor` satisfies both without either domain importing identity.

*The typed-nil trap.* `cmd/api/main.go` declares
`var issuer identityservice.Issuer` and assigns only inside the `if`, because
assigning a nil `*Oidc` into the interface would make `state.Oidc == nil` read
false everywhere. `internal/transport/http/http.go:State.Oidc` repeats the
requirement from the consuming side: "whatever builds a `State` must leave it
nil rather than store a nil pointer inside a non-nil interface."

**In a new service.** Ask who owns the nouns in the method signatures. Put the
interface there. Put its structs in the same file. For every optional
dependency, declare the variable as the interface type and assign only on the
branch that constructs it.

---

## 10. Document the cycle you could not break, at the seam

**Rule.** When two packages genuinely need each other and you broke the loop
with a narrow interface, a plain type or a duplicated constant, write down at
both ends what the loop was and what the workaround costs.

**Why.** The workaround looks like sloppiness to the next reader. Somebody will
"tidy" `Handle() string` into `Handle() entityHandle`, and the build will break
in a way that takes an hour to understand. The comment converts an hour into a
sentence. It also stops the workaround spreading: a reader who knows the
constraint is local will not copy it into a package that has no such problem.

**In keyway.** The identity→access dependency is documented three times, each
at a place where it bites.
`internal/identity/entity/names.go`, header: "Note what does NOT use them: the
`Caller` and `Actor` interfaces the access and audit domains declare speak
`Handle() string`. `identity/entity` imports `access/entity` (for `Subject` and
`Level`), so `access/entity` cannot import this package back without a cycle —
the port stays a plain string, deliberately, and the conversion happens at that
one seam."
`internal/identity/entity/entity.go:Actor.Handle` repeats it at the method,
next to `Actor.Name`, which is the typed accessor for identity's own use.
`internal/access/entity/access.go:Caller` states it from the other side.

The secrets deviation is documented the same way:
`internal/secrets/service/store.go`, package comment, records that `Store` and
`Registry` live in `service` rather than `entity` because `config` already
imports `entity` and a `Store` carries a `config.StoreConfig` — fine in Rust
across modules of one crate, an import cycle in Go.

**In a new service.** The comment needs three things: what the cycle was, what
the workaround is, and what would happen if somebody undid it. One paragraph,
at each end.

---

## 11. Deduplicate the duplication, not the design

**Rule.** When the same thing appears twice, remove the repeated *mechanism* and
keep the repeated *guard*. Two checks that fail differently, at different times,
for different readers, are not duplication.

**Why.** "Don't repeat yourself" applied to guards deletes defence in depth. The
two checks usually differ in when they fire and who reads the message, and
collapsing them loses whichever property the survivor lacked. Meanwhile the
actual duplication — the same three lines of decoding written five times, each
with its own thing to forget — is invisible because it is spread across a
`switch`.

**In keyway, both halves of the same refactor.**

*The mechanism was deduplicated.* `config/settings.go` header: the
`declared.Settings["project"].(string)` reading, repeated per kind in
`cmd/api/main.go` "each with its own silent `ok` to forget", moved into five
typed getters. The mount site now asks for the settings of a kind and gets
either a value or a sentence naming the store and the key.

*The guard was kept, deliberately.* In the same refactor,
`config.ParseStoreKind` began refusing unknown kinds at parse — which makes the
`default` case in `cmd/api/main.go:mountStores` unreachable. It stands anyway,
and the function's doc comment argues for it: "a kind added to config and not
to this switch is exactly the mistake worth failing the process over: silently
serving four of five declared Stores is worse than not starting, since nobody
notices the fifth is missing."

The same shape appears in the duplicate-store-id check, which exists in `config`
(`config.DuplicateStoreError`, raised by `Config.validate`) and again in the
registry (`secretsservice.DuplicateStoreError`, raised by `NewRegistry`). Two
types, two messages, two layers — because the registry is also constructed by
tests that never went through a config file.

**In a new service.** Before deleting a second check, name what it catches that
the first does not, and who reads its message. If the answer is "nothing" and
"the same person", delete it. Otherwise keep it and write the reason above it —
an unexplained unreachable branch is deleted by the next reader.

---

## 12. Preserve the status, move the decision

**Rule.** When a validation moves to a different layer, the caller must see the
same status and the same sentence it saw before. Moving a check is a
refactoring; changing what a caller is told is a wire decision, and the two do
not travel together.

**Why.** Moving a rule up to the edge is almost always right — it is refused
before any entropy is generated, any row written or any backend called, and the
message can name the field. But the caller has a client, and the client
branches on the status. A refactor that also turns a 400 into a 422 is a
breaking change disguised as a tidy-up, and it will be found in production
rather than in review.

**In keyway.** `internal/secrets/entity/identifiers.go:NewSecretName` refuses
the empty name "with the same `InvalidNameError` keyway's own Store already
answered with — the wording is what a caller reads, so it stays where it was
even though the check has moved up".

`internal/transport/http/secrets.go`, in the create handler, spells the rule
out: the name is parsed at the edge and reported through the secrets domain's
own `InvalidNameError`, "which the error mapping answers exactly as it did when
keyway's own Store raised it from underneath — changing that status is a wire
decision, and this pass does not make wire decisions."

`internal/transport/http/tokens.go` does the same twice:
`tokensentity.NewName` is "read at the edge, and reported in the entity's own
words — the same sentence and the same 400 the service answered with when it
did this check itself"; and `tokensentity.ParseID` failing yields `NotFound()`,
"which is what the delete already answered for one that simply is not there —
and for the same reason: a different answer would confirm which ids are real."

The tests pin the invariance rather than the new location:
`internal/tokens/entity/entity_test.go:TestANameIsRequired` — "The rule moved
from `Mint` onto the `Name` type… What it refuses is unchanged."

**In a new service.** When you move a check, keep the error type and let it
travel. If the old layer's error was untyped, give it a type before you move
it, in a separate commit. Assert the status in a transport test, not the
location of the check.

---

## 13. One gateway owns the fence, so no adapter can forget it

**Rule.** Where a permission, a scope or an instrumentation obligation applies
to every implementation of a port, put it in a single wrapper type that all
calls go through, and say in the port's own doc comment that implementations
must not do it themselves.

**Why.** An obligation spread across N adapters is an obligation the N+1th
forgets, and forgetting it looks like nothing at all until somebody deletes a
production secret from a Store that was meant to be read-only. This is
pattern 6's sibling: 6 is an optional decorator composed in `main`; this is a
mandatory gateway that the registry only ever hands out.

**In keyway.** `internal/secrets/service/store.go:Store` wraps a
`secretsentity.SecretManager` and applies four things every adapter would
otherwise repeat: `Store.require` checks the configured `allow` verb,
`Store.selects` applies `select`, `Store.requireUnprotected` applies `protect`,
and `secretsservice.timed` records the metered call. Its comment names the
stake: "`allow` is a fence rather than a hint, and putting it in one place
means a new adapter cannot forget to check it — the worst kind of bug to ship
in a secrets tool."
`secretsentity.SecretManager`'s interface comment closes the loop from the
other end: "Implementations do not enforce `allow`, `select` or `protect` — the
`Store` does that around them, so no adapter can forget to."
`secretsservice.Registry.Get` is the only way to obtain a `Store`, so there is
no path to a bare adapter.

The metric labels get the same treatment: `secretsservice.operation` is an
unexported string type with eight constants, "a bounded set, spelled once",
because an operation label built from a caller's string is a cardinality
problem that only appears in production.

**In a new service.** Ask of every rule in an adapter: would a new adapter
author know to write this? If not, hoist it into the wrapper and delete it from
the adapters. Then write the prohibition into the interface's doc comment,
where the next implementer reads it.

---

## 14. Refuse the whole process rather than serve a partial one

**Rule.** A misconfiguration that would make the service serve less than it was
told to serve fails the boot, with a message naming what was wrong. Degrading
quietly is not available.

**Why.** Nobody notices the fifth of five Stores is missing. A console that
starts, looks healthy and silently omits one backing service is worse than one
that refuses to start, because the refusal is diagnosed in minutes and the
omission is diagnosed after somebody could not find a secret they were sure
existed.

**In keyway.** `cmd/api/main.go:mountStores` returns an error for an unknown
kind rather than skipping the Store, with that exact argument in its doc
comment. `config.Config.validate` refuses two Stores sharing an id, because
"every grant written against it would be ambiguous"
(`config.DuplicateStoreError`); `secretsservice.NewRegistry` refuses the same
thing again. `config.requireBlocks` refuses a file with no `postgres` or `oidc`
block at all — their fields default, the blocks themselves do not, because "a
deployment that has said nothing about its database or its issuer has misplaced
the file, not configured an empty one". The YAML decoder runs with
`decoder.KnownFields(true)` so a misspelled `postgress:` is an error rather
than "no postgres block configured". `config.UnresolvedError` carries every
unresolved `${env:…}` placeholder together, so three unset variables are
learned in one boot rather than three. And `identityinfra.Discover` runs at
boot, because "a console that only reaches its issuer when somebody tries to
sign in is one that looks healthy while being unusable".

The counter-examples are as deliberate. A Kubernetes Store with no `select`
warns rather than failing, because it is a bad idea and not a broken one. A
Store that fails to list at request time is reported as empty rather than
failing the whole listing, "one unreachable cloud project must not black out
the console" (`internal/transport/http/secrets.go:listSecrets`). A missing
`oidc.session_key` generates one and warns loudly
(`cmd/api/main.go:sessionCodec`).

**In a new service.** Sort every configuration failure into "the operator gets
less than they asked for" (fatal at boot) and "the operator gets something
suboptimal they may have meant" (warn). Do the network discovery your first
request would do, at boot.

---

## 15. Answer identically for "does not exist" and "you may not see it"

**Rule.** Where the existence of a thing is itself information, the not-found
answer and the not-permitted answer are the same status and the same body, and
the code says that they are the same on purpose.

**Why.** A 403 confirms the thing exists. In a secrets console, "there is a
secret called `stripe-live-key` in the `prod` Store" is a fact worth guessing
for, and an endpoint that distinguishes the two answers is an oracle for
enumerating the inventory. This is domain-specific: a service where existence
is public should prefer the more informative status.

**In keyway.** `internal/transport/http/error.go`, file header: "a response must
not teach a caller anything they could not already ask for. An unknown Store,
an unknown secret and a secret somebody may not see are all 404 — a 403 would
confirm that the thing exists, which is a fact worth guessing for."
`http.NotFound()` carries the same note; `http.Forbidden()` is documented as
"used only where the caller already knows the thing exists".
`secretsservice.Registry.Get` returns nil for an unknown id, and its comment
says the caller reports that the same way it reports an unknown secret, "so a
URL cannot be used to learn which Stores exist".
`secretsservice.Store.Get` returns `entity.ErrNotFound` rather than a refusal
for a secret outside `select`: "a Store that does not expose something should
not confirm it exists."
`internal/transport/http/tokens.go` applies it to token ids.

`internal/transport/http/error.go:WriteError` also keeps the internal detail
out: an `ApiError` carrying an `Err` logs the full error and reports the string
`internal error`.

**In a new service.** Decide once, per resource, whether existence is public.
Write the decision in the error file's header. Then make the two paths return
the same constructor, so the next handler cannot get it wrong by choosing a
status.

---

## How to verify this document is still correct

Each pattern above names files and symbols. These checks catch the ones most
likely to rot.

- `grep -rn 'func (p Plaintext)' internal/tokens/entity/entity.go` shows
  `String`, `LogValue` and `Expose` (pattern 4), and
  `grep -rn '\.Expose()' internal/ cmd/ --include='*.go' | grep -v _test` names
  exactly one call site.
- `grep -rn '^var [A-Z][A-Za-z]* func' internal/` is empty, and so is
  `grep -rn 'ObserveBackendCall' internal/` (pattern 7).
- `grep -rn 'var _ ' internal/*/infra/*.go` shows a compile-time port assertion
  beside every adapter (pattern 9).
- `grep -rn '/infra"' internal/transport/` is empty (pattern 9).
- `go test ./internal/secrets/entity/ ./internal/identity/entity/ -run 'MustName'`
  passes and exercises the must-not-refuse tables (pattern 2).
- The gate: `gofmt -l cmd config internal embed.go` silent, `go build ./...`,
  `go vet ./...`, `go test -race ./...` green.

## Related

- [architecture.md](architecture.md) — the layout these patterns assume.
- [CONTEXT.md](../CONTEXT.md) — the domain vocabulary.
- [adr/0007-keyway-is-the-go-services-reference-layout.md](adr/0007-keyway-is-the-go-services-reference-layout.md)
  — the review that produced this catalogue.
