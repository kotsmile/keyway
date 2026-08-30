# Go port, keeping the wire and schema

Supersedes the language half of ADR-0001: keyway is being ported from Rust to
Go. The reasons are consolidation and velocity — warrant is Go, locker was Go,
and one maintainer carrying a Rust codebase inside an otherwise-Go ecosystem
pays for it in context-switching, iteration speed, and a higher bar for
contributors. ADR-0001's other half stands: locker remains a reading reference
only, never a port base — its code stays internal and tangled with `oidcx`,
`configx`, and warden's role grammar.

The port is a drop-in, not a v2. The Postgres schema, the HTTP wire format,
and the config vocabulary do not change, so ADR-0002 through ADR-0005 remain
binding, the React dashboard and the existing migrations carry over untouched,
and the parity gate is the ported test suite plus the unchanged dashboard and
CLI running against the Go server on the same database.

The Go code keeps this repo's folder structure as the goal — `cmd/`
entrypoints over an `internal/` tree mirroring the existing domain split
(`domains/{identity,access,secrets,audit,tokens}`, `infra`, `transport`,
`config`). Warrant contributes tooling conventions only (sqlx, goose, embedded
migrations, CI shape), not layout. Go lands at the repo root on `main`
alongside the Rust crates, which are deleted in one commit once parity passes.

> 2026-08-30: the cutover landed (kotsmile/keyway#30, this commit). The parity
> gate passed (#29) and the crates, the Cargo manifests and the `.sqlx` cache
> are gone; the Rust migrations survive as frozen fixtures in
> `e2e/rust-migrations/`, and everything else Rust lives in `git log` only.
