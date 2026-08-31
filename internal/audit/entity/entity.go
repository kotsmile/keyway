// Package entity is what happened, and who did it.
//
// Reads are recorded alongside writes, which is unusual and intended: for a
// secrets tool the interesting question is far more often "who looked at
// this" than "who changed it".
//
// Append-only. There is no update and no delete in this package, and none
// anywhere else either.
package entity

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	secrets "github.com/kotsmile/keyway/internal/secrets/entity"
)

// Action is what was done.
//
// A string rather than an integer enum so a row whose action this build
// cannot read is reported as it was stored rather than guessed at — the log
// is evidence, and evidence with gaps is worse than evidence with an
// unfamiliar word in it.
type Action string

const (
	Create Action = "create"
	Update Action = "update"
	// Reveal is a value being read. The reason `reveal` exists as a word
	// separate from "read".
	Reveal   Action = "reveal"
	Delete   Action = "delete"
	Delegate Action = "delegate"
	Revoke   Action = "revoke"
	// Transfer is ownership changing hands. Its own action rather than a
	// delegate with a flag, because it is the one entry that says who STOPPED
	// being answerable for a secret.
	Transfer Action = "transfer"
)

// ParseAction reads an action out of its word.
func ParseAction(name string) (Action, bool) {
	switch Action(name) {
	case Create, Update, Reveal, Delete, Delegate, Revoke, Transfer:
		return Action(name), true
	}
	return "", false
}

// IsKnown is whether this build has a constant for this action.
//
// It exists because the `action` column carries a CHECK constraint listing
// exactly these seven words: an entry with anything else is refused by
// PostgreSQL with a message about a constraint, which tells the person
// reading the log nothing about what they actually did wrong. Checking here
// means a mistyped action is caught where the word was chosen.
//
// Note the asymmetry with reading: a row already stored under a word this
// build does not know is reported AS STORED (see the Entry comment), because
// the log is evidence and evidence with gaps is worse than evidence with an
// unfamiliar word in it. Writing is the strict direction; reading is not.
func (a Action) IsKnown() bool {
	_, known := ParseAction(string(a))
	return known
}

// UnknownActionError is an entry nothing in this build could have meant.
type UnknownActionError struct {
	Action Action
}

func (e *UnknownActionError) Error() string {
	return fmt.Sprintf(
		"%q is not an audit action; this build has: create, update, reveal, delete, delegate, revoke, transfer",
		string(e.Action))
}

// Entry is one line of the log. It records WHAT was touched and by whom,
// never the payload.
//
// The json tags mirror the Rust serde attributes exactly, absent fields
// included, because the dashboard already reads this shape.
type Entry struct {
	ID    int64     `json:"id"`
	At    time.Time `json:"at"`
	Actor string    `json:"actor"`
	// ViaToken is the public id of the API token that acted, empty for a
	// browser session. What the id half of `kw-<id>-<secret>` exists for.
	ViaToken string             `json:"via_token,omitempty"`
	Action   Action             `json:"action"`
	Store    secrets.StoreID    `json:"store"`
	Secret   secrets.SecretName `json:"secret"`
	// SecretID is the uuid the secret answered to when this happened. Absent
	// on entries recorded before it was kept.
	SecretID *uuid.UUID        `json:"secret_id,omitempty"`
	Version  secrets.VersionID `json:"version,omitempty"`
	// Keys is which key/value entries the action touched. Never the values.
	Keys []string `json:"keys,omitempty"`
	// Subject is the grantee, for a delegate or revoke — and the NEW owner,
	// for a transfer.
	Subject string `json:"subject,omitempty"`
	Note    string `json:"note,omitempty"`
}

// Record is what to append.
//
// The Rust side made this a builder because most entries set two fields and
// an argument list nobody can read is one somebody eventually passes in the
// wrong order; Go struct literals name their fields, which is the same cure,
// and the With* methods stay for call sites that read better chained.
type Record struct {
	Action   Action
	SecretID uuid.UUID
	Store    secrets.StoreID
	Secret   secrets.SecretName
	Version  secrets.VersionID
	Keys     []string
	Subject  string
	Note     string
}

// NewRecord is a record with the fields every entry sets.
func NewRecord(action Action, secretID uuid.UUID, store secrets.StoreID, secret secrets.SecretName) Record {
	return Record{Action: action, SecretID: secretID, Store: store, Secret: secret}
}

// WithVersion names the backend version the action was about.
func (r Record) WithVersion(version secrets.VersionID) Record {
	r.Version = version
	return r
}

// WithKeys names which key/value entries the action touched.
func (r Record) WithKeys(keys []string) Record {
	r.Keys = keys
	return r
}

// WithSubject names the grantee — or, for a transfer, the new owner.
func (r Record) WithSubject(subject string) Record {
	r.Subject = subject
	return r
}

// WithNote carries the sentence the next reader needs.
func (r Record) WithNote(note string) Record {
	r.Note = note
	return r
}
