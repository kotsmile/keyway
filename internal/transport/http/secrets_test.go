// The wire spellings the Rust server pinned, tested white-box: `basis` is the
// lowercased Debug rendering (view_of in the Rust transport, removed at the
// cutover — see git history), and `?key=` reveal answers exactly what
// serde_json's Value::get answered.
package http

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	accessentity "github.com/kotsmile/keyway/internal/access/entity"
)

func TestBasisWireIsTheLowercasedRustDebugRendering(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		basis accessentity.Basis
		want  string
	}{
		{"nothing", accessentity.BasisNothing, "nothing"},
		{"owner", accessentity.BasisOwner, "owner"},
		{"admin", accessentity.BasisAdmin, "admin"},
		{"delegated", accessentity.BasisDelegated("sre"), `delegated { subject: "sre" }`},
		// The exotic subject: Rust's to_lowercase() lowercased the WHOLE
		// Debug string, subject included — "SRE Team" reads back as
		// "sre team", and the port keeps that, oddity and all.
		{"uppercase and spaces", accessentity.BasisDelegated("SRE Team"),
			`delegated { subject: "sre team" }`},
		// Debug escaping: a quote in the name arrives backslash-escaped.
		{"embedded quote", accessentity.BasisDelegated(`quo"te`),
			`delegated { subject: "quo\"te" }`},
		// json.Marshal would have said < here; Rust's {:?} never did.
		{"html-special characters", accessentity.BasisDelegated("a<b&c>d"),
			`delegated { subject: "a<b&c>d" }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, basisWire(tc.basis))
		})
	}
}

func TestValueForAnswersLikeSerdeValueGet(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		payload    string
		key        string
		hasKey     bool
		want       string
		wantStatus int // 0 means success
	}{
		{name: "no key is the payload verbatim", payload: "not-json-at-all",
			want: "not-json-at-all"},
		{name: "a string value comes back raw", payload: `{"db_password":"hunter2"}`,
			key: "db_password", hasKey: true, want: "hunter2"},
		{name: "a non-string value re-renders as compact json",
			payload: `{"count": 42}`, key: "count", hasKey: true, want: "42"},
		{name: "a null value is the word null", payload: `{"gone": null}`,
			key: "gone", hasKey: true, want: "null"},
		{name: "a missing key is not found", payload: `{"a":"b"}`,
			key: "nope", hasKey: true, wantStatus: http.StatusNotFound},
		// The flagged probe: valid JSON that is not an object has no keys to
		// index. Rust's Value::get answered None there → 404, never 400.
		{name: "a json array is not found", payload: `[1,2,3]`,
			key: "0", hasKey: true, wantStatus: http.StatusNotFound},
		{name: "a json string is not found", payload: `"just text"`,
			key: "x", hasKey: true, wantStatus: http.StatusNotFound},
		{name: "a json number is not found", payload: `42`,
			key: "x", hasKey: true, wantStatus: http.StatusNotFound},
		// Not JSON at all: serde's from_slice failed → 400 with the sentence.
		{name: "a non-json payload has no keys", payload: `hunter2`,
			key: "x", hasKey: true, wantStatus: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := valueFor([]byte(tc.payload), tc.key, tc.hasKey)
			if tc.wantStatus == 0 {
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
				return
			}
			var api *ApiError
			require.True(t, errors.As(err, &api), "expected an ApiError, got %v", err)
			assert.Equal(t, tc.wantStatus, api.Status)
			if tc.wantStatus == http.StatusBadRequest {
				assert.Equal(t, "this secret has no keys", api.Message,
					"the Rust wording carries over")
			}
		})
	}
}
