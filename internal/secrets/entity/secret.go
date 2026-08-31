package entity

// Secret is one secret's metadata — never its payload.
//
// Listing is the most common thing keyway does and it must not read a single
// value to do it: a list that decrypts everything is an audit log full of
// reveals nobody performed.
type Secret struct {
	// Store is which Store it lives in.
	Store StoreID `json:"store"`
	// Name is what the backend knows it by. Not what keyway addresses it by:
	// the API speaks uuids, because a name is somebody else's contract — ESO
	// manifests and existing tooling address these by name, and renaming them
	// to uuids would break every one of those to buy keyway an id it can
	// carry in a label instead.
	Name        SecretName `json:"name"`
	Labels      Metadata   `json:"labels,omitempty"`
	Annotations Metadata   `json:"annotations,omitempty"`
	// LatestVersion is the version an unqualified read resolves to. Empty for
	// a secret that exists but has never been given a payload, which some
	// backends allow and which reads as "not set" rather than as an error.
	LatestVersion VersionID `json:"latest_version,omitempty"`
}

// Reference is where this secret lives, as it reads in an error or a log
// line.
func (s Secret) Reference() string {
	return s.Store.String() + "/" + s.Name.String()
}

// Version is one immutable revision as the backend records it.
//
// Note what is NOT here: an author. No secret manager records who added a
// version, and that gap is exactly what keyway's audit log fills.
type Version struct {
	// ID is the backend's own identifier for it.
	ID    VersionID    `json:"id"`
	State VersionState `json:"state"`
}

// VersionState is whether a version can still answer for its payload.
type VersionState string

const (
	VersionEnabled  VersionState = "enabled"
	VersionDisabled VersionState = "disabled"
	// VersionDestroyed means the payload is gone for good, so nothing may
	// offer to reveal it.
	VersionDestroyed VersionState = "destroyed"
)

// ParseVersionState reads a state out of the word a backend or a row uses.
//
// An unrecognised word reads as DESTROYED rather than as enabled, and that is
// the whole reason this is a function in the entity package rather than a
// switch in each adapter: "a state this build does not understand must not be
// offered for reveal" is a rule about payloads, and a rule kept in five
// places is a rule four of them can get wrong. The adapters map their own
// vocabulary onto these words (Google's enum, AWS's stage labels) and hand
// the word here.
func ParseVersionState(word string) VersionState {
	switch VersionState(word) {
	case VersionEnabled:
		return VersionEnabled
	case VersionDisabled:
		return VersionDisabled
	default:
		return VersionDestroyed
	}
}

// Word is how a row stores this state.
func (s VersionState) Word() string {
	return string(ParseVersionState(string(s)))
}

// Readable is whether this version still has a payload to reveal.
func (v Version) Readable() bool {
	return v.State == VersionEnabled
}
