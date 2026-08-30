// A Directory backed by Keycloak's admin API.
//
// Optional, and off unless configured. What it buys back is the one property
// keyway loses by not asking an identity provider on every request: disabling
// an account cuts every API token it issued, within a cache window (ADR-0004).
//
// It is Keycloak-specific because the admin REST API is Keycloak's, not
// OIDC's — which is exactly why this is an interface with an implementation
// rather than something baked into the identity domain.

package infra

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	identityservice "github.com/kotsmile/keyway/internal/identity/service"
)

// cacheFor is how long a resolved subject is trusted.
//
// The same window a copied claim gets, and for the same reason: it is the
// longest a change may take to bite. Shortening it does not make the system
// safer so much as it makes the identity provider a hard dependency of every
// request; lengthening it quietly reintroduces the stale-membership problem
// this exists to avoid.
const cacheFor = 5 * time.Minute

// KeycloakDirectory answers who somebody is right now, from Keycloak.
type KeycloakDirectory struct {
	adminBase    string
	clientID     string
	clientSecret string
	tokenURL     string
	http         *http.Client
	// now is injectable so a test can age the cache without sleeping.
	now func() time.Time

	mu    sync.Mutex
	cache map[string]cacheEntry
}

// cacheEntry distinguishes "we know they are gone" (a nil answer that IS in
// the map) from "we do not know yet" (no entry, or one gone stale).
type cacheEntry struct {
	at     time.Time
	answer *identityservice.DirectoryAnswer
}

type accessToken struct {
	AccessToken string `json:"access_token"`
}

type kcUser struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

type kcGroup struct {
	Path string `json:"path"`
}

// NewKeycloakDirectory builds a Directory from the same confidential client
// keyway already uses to sign people in.
//
// The admin base is DERIVED from the issuer rather than configured
// separately: the two can only ever disagree by mistake, and a service
// pointed at one realm for login and another for identity would authorise
// against the wrong population without anything looking misconfigured.
//
// It errors when the issuer is not a realm url.
func NewKeycloakDirectory(issuer, clientID, clientSecret string) (*KeycloakDirectory, error) {
	issuer = strings.TrimRight(issuer, "/")
	split := strings.LastIndex(issuer, "/realms/")
	if split < 0 {
		return nil, fmt.Errorf("%s is not a Keycloak realm url (no /realms/ in it)", issuer)
	}
	host, realm := issuer[:split], issuer[split+len("/realms/"):]

	return &KeycloakDirectory{
		adminBase:    fmt.Sprintf("%s/admin/realms/%s", host, realm),
		clientID:     clientID,
		clientSecret: clientSecret,
		tokenURL:     fmt.Sprintf("%s/protocol/openid-connect/token", issuer),
		http:         &http.Client{},
		now:          time.Now,
		cache:        map[string]cacheEntry{},
	}, nil
}

// cached is what the cache had. The second return is false for "we do not
// know yet"; a true beside a nil answer means "we know they are gone".
func (d *KeycloakDirectory) cached(handle string) (*identityservice.DirectoryAnswer, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	entry, ok := d.cache[handle]
	if !ok || d.now().Sub(entry.at) >= cacheFor {
		return nil, false
	}
	if entry.answer == nil {
		return nil, true
	}
	// A copy, so a caller mutating the answer cannot poison what the next
	// request reads.
	return &identityservice.DirectoryAnswer{
		Enabled: entry.answer.Enabled,
		Groups:  slices.Clone(entry.answer.Groups),
	}, true
}

func (d *KeycloakDirectory) remember(handle string, answer *identityservice.DirectoryAnswer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cache[handle] = cacheEntry{at: d.now(), answer: answer}
}

// adminToken is the client's own access token, via the service account.
//
// Needs `serviceAccountsEnabled` on the client and `view-users` from
// `realm-management` — one flag and one role mapping on a client keyway
// already holds, so no second credential to rotate.
func (d *KeycloakDirectory) adminToken(ctx context.Context) (string, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {d.clientID},
		"client_secret": {d.clientSecret},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, d.tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("asking keycloak for a service-account token: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := d.http.Do(request)
	if err != nil {
		return "", fmt.Errorf("asking keycloak for a service-account token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return "", fmt.Errorf("keycloak refused the service-account grant: %s", response.Status)
	}
	var token accessToken
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil {
		return "", fmt.Errorf("reading the service-account token: %w", err)
	}
	return token.AccessToken, nil
}

// getJSON reads one admin endpoint into out, with the bearer token attached.
func (d *KeycloakDirectory) getJSON(ctx context.Context, endpoint, token string, out any, doing string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", doing, err)
	}
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := d.http.Do(request)
	if err != nil {
		return fmt.Errorf("%s: %w", doing, err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return fmt.Errorf("%s: keycloak answered %s", doing, response.Status)
	}
	if err := json.NewDecoder(response.Body).Decode(out); err != nil {
		return fmt.Errorf("%s: %w", doing, err)
	}
	return nil
}

// Resolve implements identityservice.Directory.
func (d *KeycloakDirectory) Resolve(ctx context.Context, handle string) (*identityservice.DirectoryAnswer, error) {
	if answer, known := d.cached(handle); known {
		return answer, nil
	}

	token, err := d.adminToken(ctx)
	if err != nil {
		return nil, err
	}

	// `exact` matters: without it Keycloak substring-matches, and `alice`
	// would return `alice2` as well.
	lookup := fmt.Sprintf("%s/users?%s", d.adminBase, url.Values{
		"username": {handle},
		"exact":    {"true"},
	}.Encode())
	var users []kcUser
	if err := d.getJSON(ctx, lookup, token, &users, "looking up a user"); err != nil {
		return nil, err
	}

	if len(users) == 0 {
		// Gone from the directory entirely. Remembered as absent so a
		// departed account does not cost a lookup on every request.
		d.remember(handle, nil)
		return nil, nil
	}
	user := users[0]

	if !user.Enabled {
		d.remember(handle, &identityservice.DirectoryAnswer{Enabled: false})
		return &identityservice.DirectoryAnswer{Enabled: false}, nil
	}

	var groups []kcGroup
	memberships := fmt.Sprintf("%s/users/%s/groups", d.adminBase, user.ID)
	if err := d.getJSON(ctx, memberships, token, &groups, "listing a user's groups"); err != nil {
		return nil, err
	}

	answer := &identityservice.DirectoryAnswer{
		Enabled: true,
		// Paths, matched exactly. keyway parses no structure out of a group
		// name (ADR-0003), so a realm wanting a grant to a parent group to
		// cover the teams inside it emits the ancestors.
		Groups: make([]string, len(groups)),
	}
	for i, group := range groups {
		answer.Groups[i] = group.Path
	}
	// A copy goes into the cache so a caller mutating the answer cannot
	// poison what the next request reads.
	d.remember(handle, &identityservice.DirectoryAnswer{
		Enabled: true,
		Groups:  slices.Clone(answer.Groups),
	})
	return answer, nil
}
