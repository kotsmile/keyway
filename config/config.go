// Package config reads the single file a deployment is configured by.
//
// Every value is a string, credentials included: there is no second channel
// and no environment read for a setting of its own. A credential reaches the
// process through a `${env:NAME}` placeholder in this file, so what a
// deployment holds is declared next to what needs it.
package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	secretsentity "github.com/kotsmile/keyway/internal/secrets/entity"
)

type Config struct {
	Server    Server        `yaml:"server"`
	Postgres  Postgres      `yaml:"postgres"`
	Oidc      Oidc          `yaml:"oidc"`
	Stores    []StoreConfig `yaml:"stores"`
	Branding  Branding      `yaml:"branding"`
	Telemetry Telemetry     `yaml:"telemetry"`
}

// Telemetry is where traces go, if anywhere.
type Telemetry struct {
	// OtlpEndpoint is an OTLP collector. Empty means traces stay local: a
	// deployment with no collector should not be retrying exports into the
	// void.
	OtlpEndpoint string `yaml:"otlp_endpoint"`
	ServiceName  string `yaml:"service_name"`
}

type Server struct {
	Address string `yaml:"address"`
	// MetricsAddress is where /metrics is served, deliberately not the API's
	// port.
	//
	// A scrape endpoint publishes what a deployment holds — Store ids, call
	// rates, error rates — to whoever can reach it, and a metrics port is
	// almost always less guarded than an API one. Separating them lets a
	// deployment expose the API and keep this on the cluster network.
	MetricsAddress string `yaml:"metrics_address"`
}

type Postgres struct {
	Addr     string `yaml:"addr"`
	Name     string `yaml:"name"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	SSLMode  string `yaml:"sslmode"`
	MaxConn  int    `yaml:"max_conn"`
}

// Oidc is identity, from any OIDC issuer.
//
// The claim names are configuration because keyway assumes nothing about how
// an issuer spells things (ADR-0003). Group names are matched exactly; an
// issuer wanting a grant to a parent group to cover the teams inside it emits
// the ancestors in the claim.
type Oidc struct {
	Issuer       string `yaml:"issuer"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	RedirectURL  string `yaml:"redirect_url"`
	GroupsClaim  string `yaml:"groups_claim"`
	RolesClaim   string `yaml:"roles_claim"`
	// RolePrefix is stripped from a role name before keyway reads it, so a
	// realm can namespace its roles (keyway:admin) without keyway assuming a
	// scheme.
	RolePrefix string `yaml:"role_prefix"`
	// SessionKey signs and encrypts the session cookie. At least 32 bytes.
	//
	// Changing it signs everybody out, which is the intended way to sign
	// everybody out.
	SessionKey string `yaml:"session_key"`
	// SessionHours is how long a browser session lasts.
	SessionHours int64 `yaml:"session_hours"`
	// Directory is an optional live connection to the identity provider.
	//
	// Unset, keyway calls it on no request at all and a token's groups are
	// what was remembered at its holder's last sign-in. Set, membership is
	// live and disabling an account cuts every token it issued (ADR-0004).
	Directory DirectoryKind `yaml:"directory"`
	// DevUser is who a local run acts as. With no issuer, authentication is
	// off and the service acts as this user — every authorisation decision is
	// still made, so a local run behaves like production minus the redirect.
	DevUser   string   `yaml:"dev_user"`
	DevRoles  []string `yaml:"dev_roles"`
	DevGroups []string `yaml:"dev_groups"`
}

// DirectoryKind names which identity provider's admin API to talk to — the
// `oidc.directory` word.
//
// A closed list for the same reason a Store's `type:` is one: it selects an
// implementation compiled into this binary, so an unknown word is a
// deployment expecting live membership checks and silently not getting them.
// Empty is the ordinary case and means none is configured.
type DirectoryKind string

const (
	// DirectoryNone is no live connection at all. A token's groups are what
	// was remembered at its holder's last sign-in, and deleting the token is
	// the only revocation.
	DirectoryNone DirectoryKind = ""
	// DirectoryKeycloak is Keycloak's admin REST API. Keycloak-specific
	// because that API is Keycloak's, not OIDC's.
	DirectoryKeycloak DirectoryKind = "keycloak"
)

// UnknownDirectoryError is a `directory:` naming something this build cannot
// talk to.
type UnknownDirectoryError struct {
	Kind string
}

func (e *UnknownDirectoryError) Error() string {
	return fmt.Sprintf("oidc.directory names an unknown kind %q; this build has: keycloak", e.Kind)
}

// UnmarshalYAML refuses a directory this build does not have, at parse.
func (d *DirectoryKind) UnmarshalYAML(node *yaml.Node) error {
	var word string
	if err := node.Decode(&word); err != nil {
		return err
	}
	switch DirectoryKind(word) {
	case DirectoryNone, DirectoryKeycloak:
		*d = DirectoryKind(word)
		return nil
	default:
		return &UnknownDirectoryError{Kind: word}
	}
}

// IsConfigured is whether this deployment asked for a live directory at all.
func (d DirectoryKind) IsConfigured() bool { return d != DirectoryNone }

type Branding struct {
	Name    string `yaml:"name"`
	Logo    string `yaml:"logo"`
	Favicon string `yaml:"favicon"`
	Accent  string `yaml:"accent"`
}

// defaults is the Config a file that says nothing gets, matching what the
// Rust server defaulted field by field.
func defaults() Config {
	return Config{
		Server: Server{
			Address:        ":8080",
			MetricsAddress: ":9090",
		},
		Postgres: Postgres{
			// Not `disable`: a deployment that has said nothing about TLS to
			// its database has not thereby asked for none.
			SSLMode: "require",
			MaxConn: 10,
		},
		Oidc: Oidc{
			GroupsClaim:  "groups",
			RolesClaim:   "realm_access.roles",
			RolePrefix:   "keyway:",
			SessionHours: 8,
		},
		Branding: Branding{
			Name:   "keyway",
			Accent: "#2563eb",
		},
		Telemetry: Telemetry{
			ServiceName: "keyway",
		},
	}
}

// ParseError is a file that could not be read as this schema.
type ParseError struct {
	Path string
	Err  error
}

func (e *ParseError) Error() string { return fmt.Sprintf("parsing %s: %v", e.Path, e.Err) }
func (e *ParseError) Unwrap() error { return e.Err }

// UnresolvedError carries every unresolved placeholder, together. A
// deployment with three unset variables should learn that in one boot rather
// than in three.
type UnresolvedError struct {
	Path       string
	Unresolved []Unresolved
}

func (e *UnresolvedError) Error() string {
	lines := make([]string, len(e.Unresolved))
	for i, u := range e.Unresolved {
		lines[i] = u.String()
	}
	return fmt.Sprintf("unresolved placeholders in %s:\n%s", e.Path, strings.Join(lines, "\n"))
}

// DuplicateStoreError is two stores on one id.
type DuplicateStoreError struct {
	ID secretsentity.StoreID
}

func (e *DuplicateStoreError) Error() string {
	return fmt.Sprintf(
		"two stores share the id %q; every grant written against it would be ambiguous",
		e.ID.String())
}

// Load reads, resolves and validates the file at path.
func Load(path string) (Config, error) {
	text, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading %s: %w", path, err)
	}
	return FromString(string(text), path, func(name string) (string, bool) {
		return os.LookupEnv(name)
	})
}

// FromString is the body of Load, with the environment injected so it can be
// tested.
func FromString(text, path string, lookup func(string) (string, bool)) (Config, error) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(text), &document); err != nil {
		return Config{}, &ParseError{Path: path, Err: err}
	}
	if unresolved := resolve(&document, lookup); len(unresolved) > 0 {
		return Config{}, &UnresolvedError{Path: path, Unresolved: unresolved}
	}
	if err := requireBlocks(&document); err != nil {
		return Config{}, &ParseError{Path: path, Err: err}
	}

	// Re-encoded and decoded strictly, because strictness is the point: a
	// misspelled `postgress:` should not read as "no postgres block
	// configured" in a file that gates who sees what.
	resolved, err := yaml.Marshal(&document)
	if err != nil {
		return Config{}, &ParseError{Path: path, Err: err}
	}
	config := defaults()
	decoder := yaml.NewDecoder(bytes.NewReader(resolved))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return Config{}, &ParseError{Path: path, Err: err}
	}
	if err := config.validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

// requireBlocks refuses a file with no postgres or oidc block at all. Their
// fields default, the blocks themselves do not: a deployment that has said
// nothing about its database or its issuer has misplaced the file, not
// configured an empty one.
func requireBlocks(document *yaml.Node) error {
	root := document
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	present := map[string]bool{}
	if root.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(root.Content); i += 2 {
			present[root.Content[i].Value] = true
		}
	}
	for _, required := range []string{"postgres", "oidc"} {
		if !present[required] {
			return fmt.Errorf("missing field %q", required)
		}
	}
	return nil
}

func (c Config) validate() error {
	seen := map[secretsentity.StoreID]bool{}
	for _, store := range c.Stores {
		if seen[store.ID] {
			return &DuplicateStoreError{ID: store.ID}
		}
		seen[store.ID] = true
	}
	return nil
}
