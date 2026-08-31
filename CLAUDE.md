# keyway

## Architecture

Read before moving or adding a file. `docs/architecture.md` is the layout —
what belongs in `config/`, `cmd/<binary>/main.go`, `internal/<domain>/{entity,
service,infra}` and `internal/transport/<protocol>/`, which layer may import
which, and how to add a domain or a backend. `docs/patterns.md` is the
numbered pattern catalogue that layout assumes; cite patterns by number in
review. The decision behind both is
`docs/adr/0007-keyway-is-the-go-services-reference-layout.md`.

## Agent skills

### Issue tracker

Issues live as GitHub issues in `kotsmile/keyway`, managed with the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage roles, using the default label strings. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.
