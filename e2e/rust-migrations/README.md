# The Rust server's migrations, frozen

These three files are byte-for-byte what the Rust server shipped and applied
with sqlx — no goose markers, exactly as `sqlx migrate run` saw them. The
crates were deleted at the cutover (kotsmile/keyway#30); these stayed behind
as a fixture, because a real deployed lineage still exists: databases the
Rust server migrated, holding this schema and a `_sqlx_migrations` history.

`e2e/run.sh` step 1 applies them raw to simulate such a database, and step 2
proves `keywayd migrate` adopts the sqlx history into goose without re-running
anything (`adoptSqlxHistory` in `internal/postgres/postgres.go`).

Never edit these files. The live schema is `migrations/` at the repo root —
the same files under the same numeric prefixes, plus goose markers — and new
migrations go there.
