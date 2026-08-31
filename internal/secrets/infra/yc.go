// Yandex Cloud Lockbox.
//
// Over the REST API, as the Rust adapter was: the surface keyway needs is
// small and the mapping is the part worth being able to read. Two things make
// this the odd one out, and both are handled here rather than leaking into
// the interface:
//
//  1. Secrets are addressed by an opaque id, not by name, and Lockbox does
//     not require names to be unique. keyway speaks names to a backend, so
//     this resolves name → id and refuses an ambiguous one rather than
//     picking.
//  2. The payload is natively a key/value list. keyway's interface carries
//     bytes, and a kv secret is JSON by the time it reaches one — so this
//     converts, which is exactly what the interface's "a backend with native
//     kv can serve it natively" note means.

package infra

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kotsmile/keyway/internal/secrets/entity"
)

const (
	ycLockbox = "https://lockbox.api.cloud.yandex.net/lockbox/v1"
	ycPayload = "https://payload.lockbox.api.cloud.yandex.net/lockbox/v1"
	ycIam     = "https://iam.api.cloud.yandex.net/iam/v1/tokens"
)

// ycTokenFor is how long an exchanged IAM token is reused. They last 12
// hours; refreshing well inside that costs nothing and avoids a cliff.
const ycTokenFor = 50 * time.Minute

// YcLockbox serves one Yandex Cloud folder.
type YcLockbox struct {
	folder string
	// authorizedKey is the authorized-key JSON from `yc iam key create`.
	// Empty falls back to the instance service account, which a laptop does
	// not have.
	authorizedKey string
	http          *http.Client
	// now is injectable so the token cache can be tested without waiting 50
	// minutes.
	now func() time.Time

	mu      sync.Mutex
	tokenAt time.Time
	token   string
}

// NewYcLockbox never fails at construction; credentials are exchanged lazily.
func NewYcLockbox(folder, authorizedKey string) *YcLockbox {
	return &YcLockbox{
		folder:        folder,
		authorizedKey: authorizedKey,
		http:          &http.Client{},
		now:           time.Now,
	}
}

type ycIamToken struct {
	IamToken string `json:"iamToken"`
}

type ycSecret struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Labels         entity.Metadata `json:"labels"`
	CurrentVersion *ycVersion      `json:"currentVersion"`
}

type ycVersion struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type ycListSecrets struct {
	Secrets       []ycSecret `json:"secrets"`
	NextPageToken string     `json:"nextPageToken"`
}

type ycListVersions struct {
	Versions      []ycVersion `json:"versions"`
	NextPageToken string      `json:"nextPageToken"`
}

type ycPayloadResponse struct {
	Entries []ycEntry `json:"entries"`
}

type ycEntry struct {
	Key         string `json:"key"`
	TextValue   string `json:"textValue,omitempty"`
	BinaryValue string `json:"binaryValue,omitempty"`

	// hasText distinguishes "textValue absent" from "textValue empty" when
	// reading; writing only ever sets TextValue.
	hasText bool
}

func (e *ycEntry) UnmarshalJSON(data []byte) error {
	var plain struct {
		Key         string  `json:"key"`
		TextValue   *string `json:"textValue"`
		BinaryValue string  `json:"binaryValue"`
	}
	if err := json.Unmarshal(data, &plain); err != nil {
		return err
	}
	e.Key, e.BinaryValue = plain.Key, plain.BinaryValue
	if plain.TextValue != nil {
		e.TextValue, e.hasText = *plain.TextValue, true
	}
	return nil
}

// ycStateOf is Lockbox's version statuses, as keyway means them.
func ycStateOf(word string) entity.VersionState {
	switch word {
	case "ACTIVE":
		return entity.VersionEnabled
	case "SCHEDULED_FOR_DESTRUCTION":
		return entity.VersionDisabled
	default:
		// DESTROYED, and anything added later.
		return entity.VersionDestroyed
	}
}

// ycPayloadToBytes turns a Lockbox payload into the bytes keyway's interface
// carries.
//
// A single entry keyed `value` is a text secret — that is the convention this
// adapter writes, so it round-trips. Anything else is key/value and becomes
// flat JSON, which is the shape every other kv path in keyway expects.
func ycPayloadToBytes(entries []ycEntry) ([]byte, error) {
	m := map[string]string{}
	for _, entry := range entries {
		value := ""
		switch {
		case entry.hasText:
			value = entry.TextValue
		case entry.BinaryValue != "":
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(entry.BinaryValue))
			if err != nil {
				return nil, entity.Backend("decoding a lockbox entry", err)
			}
			value = strings.ToValidUTF8(string(raw), "�")
		}
		m[entry.Key] = value
	}

	if len(m) == 1 {
		if only, ok := m["value"]; ok {
			return []byte(only), nil
		}
	}
	encoded, err := marshalFlat(m)
	if err != nil {
		return nil, entity.Backend("encoding a lockbox payload", err)
	}
	return encoded, nil
}

// marshalFlat writes the flat JSON the Rust server wrote: sorted keys (both
// sides marshal from a sorted map) and no HTML escaping, so the bytes agree.
func marshalFlat(m map[string]string) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(m); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// flatKV reads a payload as the flat JSON object keyway's kv paths speak.
//
// A JSON object is a kv secret; anything else is one text value under the
// `value` key. Reading it back gives the same bytes either way. Shared by the
// two backends with native key/value — Lockbox and Kubernetes.
func flatKV(payload []byte) map[string]string {
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(payload, &parsed); err == nil && parsed != nil {
		out := make(map[string]string, len(parsed))
		for key, value := range parsed {
			var s string
			if err := json.Unmarshal(value, &s); err == nil {
				out[key] = s
				continue
			}
			// A non-string value reads as its compact JSON, the way the Rust
			// adapters' `other.to_string()` rendered it.
			var compact bytes.Buffer
			if err := json.Compact(&compact, value); err == nil {
				out[key] = compact.String()
			} else {
				out[key] = string(bytes.TrimSpace(value))
			}
		}
		return out
	}
	return map[string]string{"value": string(payload)}
}

// ycBytesToEntries is the inverse of ycPayloadToBytes: what to send when
// writing.
func ycBytesToEntries(payload []byte) []ycEntry {
	kv := flatKV(payload)
	entries := make([]ycEntry, 0, len(kv))
	for key, value := range kv {
		entries = append(entries, ycEntry{Key: key, TextValue: value, hasText: true})
	}
	return entries
}

func (y *YcLockbox) iamToken(ctx context.Context) (string, error) {
	y.mu.Lock()
	if y.token != "" && y.now().Sub(y.tokenAt) < ycTokenFor {
		token := y.token
		y.mu.Unlock()
		return token, nil
	}
	y.mu.Unlock()

	if y.authorizedKey == "" {
		return "", entity.Backend("yandex credentials",
			fmt.Errorf("no authorized key configured, and this is not a yandex instance"))
	}

	body, err := json.Marshal(map[string]string{"jwt": y.authorizedKey})
	if err != nil {
		return "", entity.Backend("exchanging a yandex key", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, ycIam, bytes.NewReader(body))
	if err != nil {
		return "", entity.Backend("exchanging a yandex key", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := y.http.Do(request)
	if err != nil {
		return "", entity.Backend("exchanging a yandex key", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return "", entity.Backend("yandex refused the key",
			fmt.Errorf("status %s", response.Status))
	}
	var exchanged ycIamToken
	if err := json.NewDecoder(response.Body).Decode(&exchanged); err != nil {
		return "", entity.Backend("reading a yandex token", err)
	}

	y.mu.Lock()
	y.tokenAt, y.token = y.now(), exchanged.IamToken
	y.mu.Unlock()
	return exchanged.IamToken, nil
}

// send performs one authenticated call and decodes the JSON answer into out.
func (y *YcLockbox) send(ctx context.Context, method, rawURL string, body, out any, doing string) error {
	token, err := y.iamToken(ctx)
	if err != nil {
		return err
	}

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return entity.Backend(doing, err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return entity.Backend(doing, err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := y.http.Do(request)
	if err != nil {
		return entity.Backend(doing, err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		return entity.ErrNotFound
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return entity.Backend(doing, fmt.Errorf("status %s", response.Status))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}
	if err := json.NewDecoder(response.Body).Decode(out); err != nil {
		return entity.Backend(doing, err)
	}
	return nil
}

func (y *YcLockbox) allSecrets(ctx context.Context) ([]ycSecret, error) {
	var out []ycSecret
	page := ""
	for {
		query := url.Values{"folderId": {y.folder}, "pageSize": {"1000"}}
		if page != "" {
			query.Set("pageToken", page)
		}
		var listed ycListSecrets
		if err := y.send(ctx, http.MethodGet, ycLockbox+"/secrets?"+query.Encode(),
			nil, &listed, "listing lockbox secrets"); err != nil {
			return nil, err
		}
		out = append(out, listed.Secrets...)
		page = listed.NextPageToken
		if page == "" {
			return out, nil
		}
	}
}

// idOf resolves a name to Lockbox's opaque id.
//
// Lockbox does not require names to be unique, so two secrets may answer to
// one name. Picking either would mean a reveal that silently reads the wrong
// secret, so this refuses instead.
func (y *YcLockbox) idOf(ctx context.Context, name entity.SecretName) (string, error) {
	all, err := y.allSecrets(ctx)
	if err != nil {
		return "", err
	}
	var matching []ycSecret
	for _, s := range all {
		if s.Name == name.String() {
			matching = append(matching, s)
		}
	}
	switch len(matching) {
	case 0:
		return "", entity.ErrNotFound
	case 1:
		return matching[0].ID, nil
	default:
		return "", &entity.InvalidNameError{
			Name: name,
			Reason: fmt.Sprintf(
				"%d secrets in this folder share this name; lockbox does not require them to be unique",
				len(matching)),
		}
	}
}

func ycIntoSecret(secret ycSecret) entity.Secret {
	latest := ""
	if v := secret.CurrentVersion; v != nil && ycStateOf(v.Status) == entity.VersionEnabled {
		latest = v.ID
	}
	return entity.Secret{
		Name:          entity.SecretName(secret.Name),
		Labels:        secret.Labels,
		LatestVersion: entity.VersionID(latest),
	}
}

// List implements entity.SecretManager.
func (y *YcLockbox) List(ctx context.Context) ([]entity.Secret, error) {
	all, err := y.allSecrets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]entity.Secret, 0, len(all))
	for _, s := range all {
		out = append(out, ycIntoSecret(s))
	}
	return out, nil
}

// Get implements entity.SecretManager.
func (y *YcLockbox) Get(ctx context.Context, name entity.SecretName) (entity.Secret, error) {
	all, err := y.allSecrets(ctx)
	if err != nil {
		return entity.Secret{}, err
	}
	for _, s := range all {
		if s.Name == name.String() {
			return ycIntoSecret(s), nil
		}
	}
	return entity.Secret{}, entity.ErrNotFound
}

// Versions implements entity.SecretManager.
func (y *YcLockbox) Versions(ctx context.Context, name entity.SecretName) ([]entity.Version, error) {
	id, err := y.idOf(ctx, name)
	if err != nil {
		return nil, err
	}
	var out []entity.Version
	page := ""
	for {
		query := url.Values{"pageSize": {"1000"}}
		if page != "" {
			query.Set("pageToken", page)
		}
		var listed ycListVersions
		if err := y.send(ctx, http.MethodGet,
			ycLockbox+"/secrets/"+url.PathEscape(id)+"/versions?"+query.Encode(),
			nil, &listed, "listing lockbox versions"); err != nil {
			return nil, err
		}
		for _, v := range listed.Versions {
			out = append(out, entity.Version{ID: entity.VersionID(v.ID), State: ycStateOf(v.Status)})
		}
		page = listed.NextPageToken
		if page == "" {
			return out, nil
		}
	}
}

// Access implements entity.SecretManager.
func (y *YcLockbox) Access(
	ctx context.Context, name entity.SecretName, version entity.VersionID,
) ([]byte, error) {
	id, err := y.idOf(ctx, name)
	if err != nil {
		return nil, err
	}
	address := ycPayload + "/secrets/" + url.PathEscape(id) + "/payload"
	if !version.IsLatest() {
		address += "?" + url.Values{"versionId": {version.String()}}.Encode()
	}
	var payload ycPayloadResponse
	if err := y.send(ctx, http.MethodGet, address, nil, &payload, "reading a lockbox payload"); err != nil {
		return nil, err
	}
	return ycPayloadToBytes(payload.Entries)
}

// SetLabels implements entity.SecretManager. Lockbox has labels but no
// separate annotations, so this replaces labels — which is what the
// interface promises.
func (y *YcLockbox) SetLabels(ctx context.Context, name entity.SecretName, labels entity.Metadata) error {
	id, err := y.idOf(ctx, name)
	if err != nil {
		return err
	}
	return y.send(ctx, http.MethodPatch, ycLockbox+"/secrets/"+url.PathEscape(id),
		map[string]any{"updateMask": "labels", "labels": labels},
		nil, "setting labels on a lockbox secret")
}

// Create implements entity.SecretManager. Lockbox creates a secret and its
// first version together, so keyway's split shape becomes a secret with one
// empty entry that the first AddVersion replaces.
func (y *YcLockbox) Create(ctx context.Context, name entity.SecretName, labels entity.Metadata) error {
	return y.send(ctx, http.MethodPost, ycLockbox+"/secrets",
		map[string]any{
			"folderId":              y.folder,
			"name":                  name.String(),
			"labels":                labels,
			"versionPayloadEntries": []map[string]string{{"key": "value", "textValue": ""}},
		},
		nil, "creating a lockbox secret")
}

// AddVersion implements entity.SecretManager.
func (y *YcLockbox) AddVersion(ctx context.Context, name entity.SecretName, payload []byte) (entity.Version, error) {
	id, err := y.idOf(ctx, name)
	if err != nil {
		return entity.Version{}, err
	}
	entries := ycBytesToEntries(payload)
	wire := make([]map[string]string, 0, len(entries))
	for _, e := range entries {
		wire = append(wire, map[string]string{"key": e.Key, "textValue": e.TextValue})
	}
	if err := y.send(ctx, http.MethodPost,
		ycLockbox+"/secrets/"+url.PathEscape(id)+":addVersion",
		map[string]any{"payloadEntries": wire},
		nil, "adding a lockbox version"); err != nil {
		return entity.Version{}, err
	}

	// The add is asynchronous and returns an operation rather than the
	// version, so the id is read back rather than guessed.
	versions, err := y.Versions(ctx, name)
	if err != nil {
		return entity.Version{}, err
	}
	for _, v := range versions {
		if v.State == entity.VersionEnabled {
			return v, nil
		}
	}
	return entity.Version{}, &entity.NoSuchVersionError{Version: "the version just written"}
}

// Delete implements entity.SecretManager.
func (y *YcLockbox) Delete(ctx context.Context, name entity.SecretName) error {
	id, err := y.idOf(ctx, name)
	if err != nil {
		return err
	}
	return y.send(ctx, http.MethodDelete, ycLockbox+"/secrets/"+url.PathEscape(id),
		nil, nil, "deleting a lockbox secret")
}

var _ entity.SecretManager = (*YcLockbox)(nil)
