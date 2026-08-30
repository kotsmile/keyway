package output

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kotsmile/keyway/cmd/keyway/internal/wire"
)

func printer() (Printer, *strings.Builder, *strings.Builder) {
	out := &strings.Builder{}
	err := &strings.Builder{}
	return Printer{Out: out, Err: err}, out, err
}

func str(s string) *string { return &s }

func TestSecretsPlainAlignsStoresAndLeadsWithTheID(t *testing.T) {
	t.Parallel()
	p, out, errOut := printer()
	require.NoError(t, p.Secrets([]wire.Secret{
		{ID: "aaaa", Store: "prod", Name: "db-password", Level: str("read")},
		{ID: "bbbb", Store: "staging", Name: "api-key"},
	}, Plain))

	assert.Equal(t,
		"aaaa  prod     db-password  (read)\n"+
			"bbbb  staging  api-key\n",
		out.String(), "the uuid first: it is what every other command takes")
	assert.Empty(t, errOut.String())
}

func TestSecretsPlainSaysSoWhenThereIsNothing(t *testing.T) {
	t.Parallel()
	p, out, errOut := printer()
	require.NoError(t, p.Secrets(nil, Plain))
	assert.Empty(t, out.String(), "commentary must not corrupt a pipe")
	assert.Equal(t, "nothing you can see\n", errOut.String())
}

func TestSecretsJSONIsPrettyPrintedLikeSerde(t *testing.T) {
	t.Parallel()
	p, out, _ := printer()
	require.NoError(t, p.Secrets([]wire.Secret{
		{ID: "aaaa", Store: "prod", Name: "db"},
	}, JSON))

	assert.Equal(t, `[
  {
    "id": "aaaa",
    "store": "prod",
    "name": "db",
    "latest_version": "",
    "level": null,
    "basis": ""
  }
]
`, out.String())
}

func TestSecretsJSONOfAnEmptyListIsStillAList(t *testing.T) {
	t.Parallel()
	p, out, errOut := printer()
	require.NoError(t, p.Secrets([]wire.Secret{}, JSON))
	assert.Equal(t, "[]\n", out.String())
	assert.Empty(t, errOut.String(), "the empty notice belongs to plain output only")
}

func TestSecretPlainSkipsWhatTheAnswerDidNotCarry(t *testing.T) {
	t.Parallel()
	p, out, _ := printer()
	require.NoError(t, p.Secret(wire.Secret{ID: "aaaa", Store: "prod", Name: "db"}, Plain))
	assert.Equal(t, "id      aaaa\nstore   prod\nname    db\n", out.String())
}

func TestSecretPlainShowsEveryFieldItWasGiven(t *testing.T) {
	t.Parallel()
	p, out, _ := printer()
	require.NoError(t, p.Secret(wire.Secret{
		ID: "aaaa", Store: "prod", Name: "db",
		LatestVersion: "v3", Level: str("write"), Basis: "owner",
	}, Plain))
	assert.Equal(t,
		"id      aaaa\nstore   prod\nname    db\n"+
			"version v3\nlevel   write\naccess  owner\n",
		out.String())
}

func TestSecretYAMLEndsWithTheExtraNewlineTheRustCLIPrints(t *testing.T) {
	t.Parallel()
	p, out, _ := printer()
	require.NoError(t, p.Secret(wire.Secret{ID: "aaaa", Store: "prod", Name: "db"}, YAML))
	assert.Equal(t,
		"id: aaaa\nstore: prod\nname: db\nlatest_version: \"\"\nlevel: null\nbasis: \"\"\n\n",
		out.String(), "println of a newline-terminated document leaves a blank line")
}

func TestValuePlainIsBareForPiping(t *testing.T) {
	t.Parallel()
	p, out, _ := printer()
	require.NoError(t, p.Value("s3cret", Plain))
	assert.Equal(t, "s3cret\n", out.String(), "no key, no quotes, no label")
}

func TestValueJSONIsAQuotedString(t *testing.T) {
	t.Parallel()
	p, out, _ := printer()
	require.NoError(t, p.Value("s3cret", JSON))
	assert.Equal(t, "\"s3cret\"\n", out.String())
}

func TestValueJSONDoesNotEscapeHTML(t *testing.T) {
	t.Parallel()
	p, out, _ := printer()
	require.NoError(t, p.Value("a<b>&c", JSON))
	assert.Equal(t, "\"a<b>&c\"\n", out.String(), "serde_json leaves these characters alone")
}

func TestValueYAMLHasNoExtraNewline(t *testing.T) {
	t.Parallel()
	p, out, _ := printer()
	require.NoError(t, p.Value("s3cret", YAML))
	assert.Equal(t, "s3cret\n", out.String(), "the Rust CLI uses print!, not println!, here")
}

func TestVersionPlainIsOneLine(t *testing.T) {
	t.Parallel()
	p, out, _ := printer()
	require.NoError(t, p.Version(wire.Version{ID: "v7", State: "active"}, Plain))
	assert.Equal(t, "version v7 (active)\n", out.String())
}

func TestGrantPlainWithoutKeys(t *testing.T) {
	t.Parallel()
	p, out, _ := printer()
	require.NoError(t, p.Grant(wire.Grant{
		SubjectKind: "user", Subject: "sam", Level: "read",
	}, Plain))
	assert.Equal(t, "granted read to user sam\n", out.String())
}

func TestGrantPlainListsTheKeys(t *testing.T) {
	t.Parallel()
	p, out, _ := printer()
	require.NoError(t, p.Grant(wire.Grant{
		SubjectKind: "group", Subject: "sre", Level: "write",
		Keys: []string{"db_password", "db_user"},
	}, Plain))
	assert.Equal(t, "granted write to group sre (keys: db_password, db_user)\n", out.String())
}

func TestGrantJSONCarriesEveryWireField(t *testing.T) {
	t.Parallel()
	p, out, _ := printer()
	require.NoError(t, p.Grant(wire.Grant{
		ID: "g1", SubjectKind: "user", Subject: "sam", Level: "read",
		Keys: []string{}, GrantedBy: "ana",
	}, JSON))
	assert.Equal(t, `{
  "id": "g1",
  "subject_kind": "user",
  "subject": "sam",
  "level": "read",
  "keys": [],
  "granted_by": "ana"
}
`, out.String())
}
