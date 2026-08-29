package entity

import "fmt"

// Level is how far a delegation opens its secret.
//
// It is an ORDER, and a comparison is the whole authorisation test. Being
// allowed to overwrite a secret you may not read is not a power anybody wants
// to grant by accident, so the constants are declared weakest first and `<`
// over them is the ladder.
type Level int

const (
	// Guest sees that a secret exists and which keys it has.
	Guest Level = iota
	// Read may reveal the values.
	Read
	// Write may also push a new version.
	Write
)

// String is the word a config file and an API spell this level with.
func (l Level) String() string {
	switch l {
	case Guest:
		return "guest"
	case Read:
		return "read"
	case Write:
		return "write"
	}
	return fmt.Sprintf("level(%d)", int(l))
}

// Reveals is whether this level discloses a secret's value.
func (l Level) Reveals() bool { return l >= Read }

// MarshalText spells the level the way the wire and the database do.
func (l Level) MarshalText() ([]byte, error) { return []byte(l.String()), nil }

// UnmarshalText reads a level back from its word.
func (l *Level) UnmarshalText(text []byte) error {
	parsed, err := ParseLevel(string(text))
	if err != nil {
		return err
	}
	*l = parsed
	return nil
}

// ParseLevel reads a level from its word.
func ParseLevel(s string) (Level, error) {
	switch s {
	case "guest":
		return Guest, nil
	case "read":
		return Read, nil
	case "write":
		return Write, nil
	}
	return Guest, &UnknownLevelError{Word: s}
}

// UnknownLevelError is a level word nothing here can interpret. It is an
// error rather than a silent Guest: a delegation whose level failed to parse
// is one nobody can reason about, and guessing the weakest reading still
// guesses.
type UnknownLevelError struct {
	Word string
}

func (e *UnknownLevelError) Error() string {
	return fmt.Sprintf("unknown level %q, expected guest, read or write", e.Word)
}
