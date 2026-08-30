package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func parse(t *testing.T, text string) *yaml.Node {
	t.Helper()
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(text), &node), "valid yaml")
	return &node
}

// at navigates the resolved document the way the Rust tests indexed a Value.
func at(t *testing.T, node *yaml.Node, path ...any) any {
	t.Helper()
	var doc any
	require.NoError(t, node.Decode(&doc))
	for _, step := range path {
		switch step := step.(type) {
		case string:
			doc = doc.(map[string]any)[step]
		case int:
			doc = doc.([]any)[step]
		}
	}
	return doc
}

func TestResolvesAPlaceholderInANestedValue(t *testing.T) {
	doc := parse(t, "postgres:\n  password: ${env:PGPASS}\n")
	require.Empty(t, resolve(doc, env(map[string]string{"PGPASS": "hunter2"})))
	assert.Equal(t, "hunter2", at(t, doc, "postgres", "password"))
}

func TestResolvesAPlaceholderEmbeddedInALongerString(t *testing.T) {
	doc := parse(t, "postgres:\n  addr: ${env:PGHOST}:5432\n")
	require.Empty(t, resolve(doc, env(map[string]string{"PGHOST": "db.internal"})))
	assert.Equal(t, "db.internal:5432", at(t, doc, "postgres", "addr"))
}

func TestReportsEveryUnresolvedPlaceholderAtOnce(t *testing.T) {
	doc := parse(t, "a: ${env:ONE}\nb: ${env:TWO}\n")
	errs := resolve(doc, env(nil))
	assert.Len(t, errs, 2, "a boot should report all of them, not one")
}

func TestNamesThePathAReaderWouldPointAt(t *testing.T) {
	doc := parse(t, "stores:\n  - id: local\n    key: ${env:KEY}\n")
	errs := resolve(doc, env(nil))
	require.Len(t, errs, 1)
	assert.Equal(t, "stores[0].key", errs[0].Path)
}

func TestABarePlaceholderIsMalformedRatherThanAnEnvLookup(t *testing.T) {
	// Other tools spell it ${NAME}. Silently treating that as env would make
	// the namespace meaningless the moment a second source exists.
	doc := parse(t, "a: ${PGPASS}\n")
	errs := resolve(doc, env(map[string]string{"PGPASS": "hunter2"}))
	require.Len(t, errs, 1)
	assert.Equal(t, Malformed, errs[0].Kind)
}

func TestAnUnknownSourceIsRefused(t *testing.T) {
	doc := parse(t, "a: ${file:/etc/secret}\n")
	errs := resolve(doc, env(nil))
	require.Len(t, errs, 1)
	assert.Equal(t, UnknownSource, errs[0].Kind)
	assert.Equal(t, "file", errs[0].Name)
}

func TestAValueContainingYamlCannotRestructureTheDocument(t *testing.T) {
	// The reason substitution runs after the parse. A raw-file implementation
	// would turn this into two mapping entries.
	doc := parse(t, "stores:\n  - key: ${env:EVIL}\n")
	require.Empty(t, resolve(doc, env(map[string]string{"EVIL": "x\nallow: [delete]"})))
	store := at(t, doc, "stores", 0).(map[string]any)
	assert.Equal(t, "x\nallow: [delete]", store["key"])
	_, leaked := store["allow"]
	assert.False(t, leaked)
}

func TestACommentIsNotAPlaceABootCanFail(t *testing.T) {
	// Also a consequence of parsing first: comments are gone by then.
	doc := parse(t, "# see ${env:NOT_SET}\na: 1\n")
	assert.Empty(t, resolve(doc, env(nil)))
}

func TestAnUnterminatedPlaceholderIsLiteralText(t *testing.T) {
	doc := parse(t, "a: \"${env:X\"\n")
	require.Empty(t, resolve(doc, env(nil)))
	assert.Equal(t, "${env:X", at(t, doc, "a"))
}
