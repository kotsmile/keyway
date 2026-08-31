// How stale a directory answer may be.
//
// This is a policy about how fast a revocation bites, not a detail of any one
// identity provider's REST API — so it lives here rather than inside the
// Keycloak client, which now asks its provider every time it is called and
// decides nothing. Written down in one place, it can be reasoned about once:
// "disabling an account cuts every API token it issued, within this window"
// is the sentence ADR-0004 has to be able to make.

package service

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/kotsmile/keyway/internal/identity/entity"
)

// DefaultStaleness is how long a resolved subject is trusted.
//
// The same window a copied claim gets, and for the same reason: it is the
// longest a change may take to bite. Shortening it does not make the system
// safer so much as it makes the identity provider a hard dependency of every
// request; lengthening it quietly reintroduces the stale-membership problem
// the Directory exists to avoid.
const DefaultStaleness = 5 * time.Minute

// CachedDirectory is a Directory that keeps each answer for a while.
//
// It is a Directory itself, so nothing above it knows whether an answer came
// from the provider or from the last few minutes — which is the point: the
// service's authorisation path must not branch on where an answer came from.
//
// Safe for concurrent use: keyway serves several requests at once and holds
// one of these for the process's life.
type CachedDirectory struct {
	inner Directory
	// staleness is how long an entry is trusted. Injected rather than read
	// from the constant so a test can pick its own window.
	staleness time.Duration
	// now is injectable so a test can age the cache without sleeping.
	now func() time.Time

	mu      sync.Mutex
	entries map[entity.Handle]cacheEntry
}

// cacheEntry distinguishes "we know they are gone" (a nil answer that IS in
// the map) from "we do not know yet" (no entry, or one gone stale).
type cacheEntry struct {
	at     time.Time
	answer *DirectoryAnswer
}

var _ Directory = (*CachedDirectory)(nil)

// NewCachedDirectory wraps a Directory with a staleness window.
//
// A nil clock means the wall clock. A zero or negative staleness would make
// every entry stale on arrival, so it is read as DefaultStaleness — a caller
// that wants no caching passes the inner Directory instead.
func NewCachedDirectory(inner Directory, staleness time.Duration, now func() time.Time) *CachedDirectory {
	if staleness <= 0 {
		staleness = DefaultStaleness
	}
	if now == nil {
		now = time.Now
	}
	return &CachedDirectory{
		inner:     inner,
		staleness: staleness,
		now:       now,
		entries:   map[entity.Handle]cacheEntry{},
	}
}

// Resolve answers from the window when it can, and asks the directory when it
// cannot.
//
// An answer of "gone from the directory entirely" is remembered as such, so a
// departed account does not cost a lookup on every request its old tokens
// make — which, for a token a reconcile loop presents every minute, is the
// difference between a dead account and a load test.
func (d *CachedDirectory) Resolve(ctx context.Context, handle entity.Handle) (*DirectoryAnswer, error) {
	if answer, known := d.cached(handle); known {
		return answer, nil
	}
	answer, err := d.inner.Resolve(ctx, handle)
	if err != nil {
		// Deliberately not cached: a provider that is down must not fix its
		// answer in place for the next five minutes.
		return nil, err
	}
	d.remember(handle, answer)
	return answer, nil
}

// cached is what the window had. The second return is false for "we do not
// know yet"; a true beside a nil answer means "we know they are gone".
func (d *CachedDirectory) cached(handle entity.Handle) (*DirectoryAnswer, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	entry, ok := d.entries[handle]
	if !ok || d.now().Sub(entry.at) >= d.staleness {
		return nil, false
	}
	return copyAnswer(entry.answer), true
}

func (d *CachedDirectory) remember(handle entity.Handle, answer *DirectoryAnswer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	// A copy goes in, so a caller mutating the answer it was handed cannot
	// poison what the next request reads.
	d.entries[handle] = cacheEntry{at: d.now(), answer: copyAnswer(answer)}
}

func copyAnswer(answer *DirectoryAnswer) *DirectoryAnswer {
	if answer == nil {
		return nil
	}
	return &DirectoryAnswer{
		Enabled: answer.Enabled,
		Groups:  slices.Clone(answer.Groups),
	}
}
