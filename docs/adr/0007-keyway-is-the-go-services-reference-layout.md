# keyway is the Go services' reference layout

An architecture review of the Go tree, run in three passes over August 2026,
was given three directives and applied them throughout.

**The siren layout is forced.** The tree matches `devtools/siren`: `config/` at
the repository root, `cmd/<binary>/main.go` as the single binding place with
the whole of `serve()` in it and no wiring helper files beside it, domains
directly under `internal/` each owning `entity`, `service` and `infra`, and
transport centralised under `internal/transport/<protocol>/`. This supersedes
the layout rule in ADR-0006, which had the Go tree mirror the Rust one
(`internal/domains/…`, per-domain transport, `internal/config`). Nothing else
in ADR-0006 moves: the wire format, the Postgres schema and the config
vocabulary are untouched by the restructure, so ADR-0002 through ADR-0005
remain binding and the dashboard and CLI did not change a line.

**Entities validate, and services speak entities.** Rules about what a value
may be moved onto the types that carry it — the identifier constructors, the
token name and id, the handle and group name — and the services above them
load, ask and write without re-deriving what a constructor already decided.

**Infra translates, it does not decide.** Policy that had settled inside
adapters moved out: the directory staleness window became a decorator over the
port, the store settings reading became typed getters in `config`, and the
metrics observer became a constructor parameter rather than a package-level
variable.

**Consequences.** The cost is one that will be paid repeatedly: three
entity-to-entity dependencies could not be broken and are worked around with
narrow interfaces and plain `string` at the seams, which reads like sloppiness
until you find the comment. The move also produced a tree that no longer looks
like the Rust one it was ported from, so `git log` before the cutover is harder
to follow against current paths. In exchange, keyway is now the documented
reference for the author's other Go services — warrant is to be rebuilt to this
same shape from these documents rather than from this code, which is why the
structure and the reusable rules are written down as
[docs/architecture.md](../architecture.md) and
[docs/patterns.md](../patterns.md) rather than left implicit in the tree.
