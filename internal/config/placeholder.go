package config

// ${env:NAME} resolution.
//
// Substitution happens on the PARSED document, over string values only —
// deliberately, rather than on the raw file before YAML is read. Raw
// substitution is the obvious implementation and it has two faults that matter
// for a file full of credentials: a value containing a newline or a quote
// rewrites the document's structure rather than filling in a field, and a
// placeholder written inside a comment is resolved too, so an unset one there
// fails a boot for no reason.

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ReasonKind says why a placeholder did not resolve.
type ReasonKind int

const (
	// UnsetVariable is ${env:NAME} where NAME is not set.
	UnsetVariable ReasonKind = iota
	// UnknownSource is a source other than `env`. The syntax is namespaced so
	// that another source can be added later; until one is, anything else is a
	// typo.
	UnknownSource
	// Malformed has no `:` at all, e.g. the bare ${NAME} other tools use.
	Malformed
)

// Unresolved is one placeholder that could not be resolved, and where it was
// written.
type Unresolved struct {
	// Path is where in the document, as a reader would point at it:
	// stores[0].key.
	Path string
	// Reference is the placeholder as written, without its ${}.
	Reference string
	Kind      ReasonKind
	// Name is the unset variable or the unknown source the Kind points at.
	Name string
}

func (u Unresolved) String() string {
	switch u.Kind {
	case UnsetVariable:
		return fmt.Sprintf("%s: ${%s} is unset in the environment (%s)", u.Path, u.Reference, u.Name)
	case UnknownSource:
		return fmt.Sprintf("%s: ${%s} names an unknown source %q, expected env", u.Path, u.Reference, u.Name)
	default:
		return fmt.Sprintf("%s: ${%s} is missing a source, expected ${env:NAME}", u.Path, u.Reference)
	}
}

// resolve substitutes every placeholder in the document, or reports all of
// them at once.
//
// All of them, rather than the first: a deployment with three unset variables
// should learn that in one boot, not in three.
func resolve(node *yaml.Node, lookup func(string) (string, bool)) []Unresolved {
	var errs []Unresolved
	walk(node, "", lookup, &errs)
	// Sorted so the reported order is the same on every run; a caller
	// comparing two boots should not have to care about document order.
	sort.SliceStable(errs, func(i, j int) bool { return errs[i].Path < errs[j].Path })
	return errs
}

func walk(node *yaml.Node, path string, lookup func(string) (string, bool), errs *[]Unresolved) {
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			walk(child, path, lookup, errs)
		}
	case yaml.SequenceNode:
		for i, child := range node.Content {
			walk(child, fmt.Sprintf("%s[%d]", path, i), lookup, errs)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			childPath := key.Value
			if path != "" {
				childPath = path + "." + key.Value
			}
			walk(value, childPath, lookup, errs)
		}
	case yaml.ScalarNode:
		if node.Tag != "!!str" {
			return
		}
		if replaced, changed := substitute(node.Value, path, lookup, errs); changed {
			node.Value = replaced
			// A substituted value may hold anything — a newline, a quote — so
			// the encoder picks the style rather than keeping the original's.
			node.Style = 0
		}
	}
}

// substitute returns the substituted string, or changed=false when there was
// nothing to do.
func substitute(text, path string, lookup func(string) (string, bool), errs *[]Unresolved) (string, bool) {
	if !strings.Contains(text, "${") {
		return "", false
	}
	var out strings.Builder
	rest := text
	for {
		start := strings.Index(rest, "${")
		if start < 0 {
			break
		}
		out.WriteString(rest[:start])
		after := rest[start+2:]
		end := strings.Index(after, "}")
		if end < 0 {
			// An unterminated ${ is literal text: there is nothing to resolve
			// and nothing to complain about.
			out.WriteString(rest[start:])
			return out.String(), true
		}
		reference := after[:end]
		if value, unresolved := valueOf(reference, lookup); unresolved == nil {
			out.WriteString(value)
		} else {
			unresolved.Path = path
			unresolved.Reference = reference
			*errs = append(*errs, *unresolved)
		}
		rest = after[end+1:]
	}
	out.WriteString(rest)
	return out.String(), true
}

func valueOf(reference string, lookup func(string) (string, bool)) (string, *Unresolved) {
	source, name, found := strings.Cut(reference, ":")
	if !found {
		return "", &Unresolved{Kind: Malformed}
	}
	if source != "env" {
		return "", &Unresolved{Kind: UnknownSource, Name: source}
	}
	if value, ok := lookup(name); ok {
		return value, nil
	}
	return "", &Unresolved{Kind: UnsetVariable, Name: name}
}
