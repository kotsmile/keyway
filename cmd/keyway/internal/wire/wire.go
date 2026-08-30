// Package wire is what the API looks like from out here.
//
// Its own types rather than the backend's, so the CLI stays a small binary
// that formats output instead of a copy of the server. That is also why this
// package must never import internal/domains or internal/config.
package wire

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/kotsmile/keyway/cmd/keyway/internal/profile"
)

// Secret is a secret as the API describes one. The optional fields default
// rather than fail, because `list` and `view` answers carry different subsets.
type Secret struct {
	ID            string  `json:"id" yaml:"id"`
	Store         string  `json:"store" yaml:"store"`
	Name          string  `json:"name" yaml:"name"`
	LatestVersion string  `json:"latest_version" yaml:"latest_version"`
	Level         *string `json:"level" yaml:"level"`
	Basis         string  `json:"basis" yaml:"basis"`
}

type Version struct {
	ID    string `json:"id" yaml:"id"`
	State string `json:"state" yaml:"state"`
}

type Grant struct {
	ID          string   `json:"id" yaml:"id"`
	SubjectKind string   `json:"subject_kind" yaml:"subject_kind"`
	Subject     string   `json:"subject" yaml:"subject"`
	Level       string   `json:"level" yaml:"level"`
	Keys        []string `json:"keys" yaml:"keys"`
	GrantedBy   string   `json:"granted_by" yaml:"granted_by"`
}

// NewGrant is what `delegate` is being asked to write. A struct rather than
// seven positional arguments, because most of them are strings and an
// argument list nobody can read is one somebody eventually passes in the
// wrong order.
type NewGrant struct {
	Kind    string
	Subject string
	Level   string
	Keys    []string
	Days    int64
	Note    string
}

// Client speaks the HTTP API with a saved (or overridden) profile.
type Client struct {
	profile profile.Profile
	http    *http.Client
}

func NewClient(p profile.Profile) *Client {
	return &Client{profile: p, http: &http.Client{}}
}

func (c *Client) url(path string) string {
	return strings.TrimRight(c.profile.URL, "/") + path
}

func (c *Client) List(ctx context.Context) ([]Secret, error) {
	return getJSON[[]Secret](ctx, c, "/api/secrets")
}

func (c *Client) View(ctx context.Context, id string) (Secret, error) {
	return getJSON[Secret](ctx, c, "/api/secrets/"+id)
}

// Reveal fetches a value. A nil key or version means "not asked for", which
// is different from asking for an empty one.
func (c *Client) Reveal(ctx context.Context, id string, key, version *string) (string, error) {
	path := "/api/secrets/" + id + "/value"
	var query []string
	if key != nil {
		query = append(query, "key="+*key)
	}
	if version != nil {
		query = append(query, "version="+*version)
	}
	if len(query) > 0 {
		path += "?" + strings.Join(query, "&")
	}

	body, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (c *Client) Create(ctx context.Context, store, name, value, note string) (Secret, error) {
	return postJSON[Secret](ctx, c, "/api/secrets", struct {
		Store string `json:"store"`
		Name  string `json:"name"`
		Value string `json:"value"`
		Note  string `json:"note"`
	}{store, name, value, note})
}

func (c *Client) Patch(ctx context.Context, id, value, note string) (Version, error) {
	return postJSON[Version](ctx, c, "/api/secrets/"+id+"/versions", struct {
		Value string `json:"value"`
		Note  string `json:"note"`
	}{value, note})
}

func (c *Client) Delegate(ctx context.Context, id string, grant NewGrant) (Grant, error) {
	keys := grant.Keys
	if keys == nil {
		// The API is sent `[]`, never `null`: no keys means an unrestricted
		// grant, not an absent field.
		keys = []string{}
	}
	granted, err := postJSON[Grant](ctx, c, "/api/secrets/"+id+"/grants", struct {
		SubjectKind string   `json:"subject_kind"`
		Subject     string   `json:"subject"`
		Level       string   `json:"level"`
		Keys        []string `json:"keys"`
		Days        int64    `json:"days"`
		Note        string   `json:"note"`
	}{grant.Kind, grant.Subject, grant.Level, keys, grant.Days, grant.Note})
	if err != nil {
		return Grant{}, err
	}
	if granted.Keys == nil {
		granted.Keys = []string{}
	}
	return granted, nil
}

func getJSON[T any](ctx context.Context, c *Client, path string) (T, error) {
	var out T
	body, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, err
	}
	return out, nil
}

func postJSON[T any](ctx context.Context, c *Client, path string, payload any) (T, error) {
	var out T
	body, err := c.do(ctx, http.MethodPost, path, payload)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, err
	}
	return out, nil
}

// do makes one authenticated request and hands back the body of a successful
// answer, or a failure turned into a sentence worth reading.
func (c *Client) do(ctx context.Context, method, path string, payload any) ([]byte, error) {
	var reader io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, c.url(path), reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+c.profile.Token)
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("reaching keyway: %w", err)
	}
	defer response.Body.Close()

	body, readErr := io.ReadAll(response.Body)
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return body, readErr
	}
	return nil, sentence(response.Status, response.StatusCode, body)
}

// sentence turns a failure into words.
//
// A 404 is reported as "no such secret, or you cannot see it" because that is
// exactly what the server means: it will not distinguish the two, and neither
// should this.
func sentence(status string, code int, body []byte) error {
	message := string(body)
	// The field must be present for the body to count as an API error; an
	// unrelated JSON body falls through as-is.
	var apiError struct {
		Error *string `json:"error"`
	}
	if err := json.Unmarshal(body, &apiError); err == nil && apiError.Error != nil {
		message = *apiError.Error
	}

	switch code {
	case http.StatusUnauthorized:
		return errors.New("not signed in, or the token is no longer valid")
	case http.StatusForbidden:
		return errors.New(message)
	case http.StatusNotFound:
		return errors.New("no such secret, or you cannot see it")
	default:
		return fmt.Errorf("keyway said %s: %s", status, message)
	}
}
