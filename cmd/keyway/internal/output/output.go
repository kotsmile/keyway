// Package output is how results are printed.
//
// Plain by default, `--json` and `--yaml` on every command. Plain output for
// `get` is the bare value with no decoration, because it is almost always
// being piped into something.
package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kotsmile/keyway/cmd/keyway/internal/wire"
)

type Format int

const (
	Plain Format = iota
	JSON
	YAML
)

// Printer holds the two streams, so tests can read what a command printed.
// Only the empty-list notice goes to Err: it is commentary, not output, and
// must not corrupt a piped `list --json`... or a piped plain one.
type Printer struct {
	Out io.Writer
	Err io.Writer
}

// render prints the structured formats. False means plain, which each caller
// lays out itself.
func (p Printer) render(value any, format Format) (bool, error) {
	switch format {
	case JSON:
		rendered, err := marshalJSON(value)
		if err != nil {
			return true, err
		}
		fmt.Fprintln(p.Out, rendered)
	case YAML:
		rendered, err := marshalYAML(value)
		if err != nil {
			return true, err
		}
		// The marshalled document already ends in a newline, and the print
		// adds one more — faithfully mirroring the Rust CLI's output.
		fmt.Fprintln(p.Out, rendered)
	default:
		return false, nil
	}
	return true, nil
}

func (p Printer) Secrets(secrets []wire.Secret, format Format) error {
	if done, err := p.render(secrets, format); done {
		return err
	}

	if len(secrets) == 0 {
		fmt.Fprintln(p.Err, "nothing you can see")
		return nil
	}

	width := 0
	for _, secret := range secrets {
		if len(secret.Store) > width {
			width = len(secret.Store)
		}
	}
	for _, secret := range secrets {
		level := ""
		if secret.Level != nil {
			level = fmt.Sprintf("  (%s)", *secret.Level)
		}
		// The uuid first: it is what every other command takes.
		fmt.Fprintf(p.Out, "%s  %-*s  %s%s\n", secret.ID, width, secret.Store, secret.Name, level)
	}
	return nil
}

func (p Printer) Secret(secret wire.Secret, format Format) error {
	if done, err := p.render(secret, format); done {
		return err
	}
	fmt.Fprintf(p.Out, "id      %s\n", secret.ID)
	fmt.Fprintf(p.Out, "store   %s\n", secret.Store)
	fmt.Fprintf(p.Out, "name    %s\n", secret.Name)
	if secret.LatestVersion != "" {
		fmt.Fprintf(p.Out, "version %s\n", secret.LatestVersion)
	}
	if secret.Level != nil {
		fmt.Fprintf(p.Out, "level   %s\n", *secret.Level)
	}
	if secret.Basis != "" {
		fmt.Fprintf(p.Out, "access  %s\n", secret.Basis)
	}
	return nil
}

// Value is a revealed value.
//
// Plain prints it bare — no key, no quotes, no label — because the whole
// point is `export DB_PASSWORD=$(keyway get … -k db_password)`.
func (p Printer) Value(value string, format Format) error {
	switch format {
	case Plain:
		fmt.Fprintln(p.Out, value)
	case JSON:
		rendered, err := marshalJSON(value)
		if err != nil {
			return err
		}
		fmt.Fprintln(p.Out, rendered)
	case YAML:
		rendered, err := marshalYAML(value)
		if err != nil {
			return err
		}
		fmt.Fprint(p.Out, rendered)
	}
	return nil
}

func (p Printer) Version(version wire.Version, format Format) error {
	if done, err := p.render(version, format); done {
		return err
	}
	fmt.Fprintf(p.Out, "version %s (%s)\n", version.ID, version.State)
	return nil
}

func (p Printer) Grant(grant wire.Grant, format Format) error {
	if done, err := p.render(grant, format); done {
		return err
	}
	fmt.Fprintf(p.Out, "granted %s to %s %s", grant.Level, grant.SubjectKind, grant.Subject)
	if len(grant.Keys) == 0 {
		fmt.Fprintln(p.Out)
	} else {
		fmt.Fprintf(p.Out, " (keys: %s)\n", strings.Join(grant.Keys, ", "))
	}
	return nil
}

// marshalJSON matches serde_json's pretty printer: two-space indent, no HTML
// escaping, no trailing newline.
func marshalJSON(value any) (string, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buffer.String(), "\n"), nil
}

func marshalYAML(value any) (string, error) {
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	if err := encoder.Close(); err != nil {
		return "", err
	}
	return buffer.String(), nil
}
