// Package keyway carries what the binaries embed, so `go build` alone
// produces something deployable — a binary that cannot find its own
// migrations is one more file for an image to get wrong.
package keyway

import "embed"

// Migrations is the schema, in goose format. The files are the same three the
// Rust server applied with sqlx; `migrate` adopts a database's sqlx history
// before goose looks, so an existing deployment is not re-migrated.
//
//go:embed migrations/*.sql
var Migrations embed.FS
