package repository

// inmemory_webauthn_session_repository.go — in-process
// implementation of WebAuthnSessionRepository. Used by tests and by
// OSS local-demo deployments that have no Redis wiring.
//
// Single-process only. A multi-replica OSS deployment that needs
// challenge consistency across replicas must wire a shared store
// (e.g. Redis) via the same WebAuthnSessionRepository seam. CE
// composition may supply that wiring without changes here.
//
// Safety notes:
//   - Consume is the ATOMIC single-use read (get+remove under one lock)
//     the finish paths use; a Get-then-Delete pair is NOT atomic and
//     would let two concurrent finishes replay one challenge (P2-11).
//   - The map is BOUNDED (P2-11): Save opportunistically sweeps expired
//     entries AND enforces maxWebAuthnSessions with oldest-expiry
//     eviction, so abandoned/never-finished ceremonies cannot grow
//     process memory without limit (the 5-min TTL alone does not cap it,
//     since nothing sweeps un-Got keys). This is a single-process guard,
//     not a shared/distributed store — single-replica IS the OSS
//     boundary (A-2); distributed WebAuthn is A-2b/commercial.
//   - Save always overwrites — the upstream go-webauthn library is
//     free to re-issue a session under the same id.
//   - All errors are deliberately generic ("session not found" /
//     "session expired") so the wire response cannot disambiguate
//     between an absent and an expired challenge.

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// ErrWebAuthnSessionNotFound is returned from
// InMemoryWebAuthnSessionRepository.Get when the supplied key has
// no live entry. Service-side callers may errors.Is against this
// sentinel; HTTP handlers MUST collapse it onto a generic 401 so
// the wire cannot distinguish missing vs expired vs already-
// consumed.
var ErrWebAuthnSessionNotFound = errors.New("webauthn session not found")

// ErrWebAuthnSessionExpired is returned from
// InMemoryWebAuthnSessionRepository.Get when the entry exists but
// its expiry has elapsed. Treated equivalently to "not found" at
// the HTTP boundary.
var ErrWebAuthnSessionExpired = errors.New("webauthn session expired")

// maxWebAuthnSessions caps the in-memory ceremony map (P2-11). A
// registered relying-party client (or an attacker) starting many
// never-finished ceremonies would otherwise grow process memory without
// limit, since nothing sweeps un-Got keys. A few thousand comfortably
// covers legitimate concurrent-ceremony load (5-min TTL) while capping
// the abuse surface; Save evicts the oldest-expiring entry once the cap
// is reached.
const maxWebAuthnSessions = 4096

type inMemoryWebAuthnSession struct {
	data      *webauthn.SessionData
	expiresAt time.Time
}

// InMemoryWebAuthnSessionRepository is the default OSS
// implementation of WebAuthnSessionRepository.
type InMemoryWebAuthnSessionRepository struct {
	mu       sync.Mutex
	sessions map[string]inMemoryWebAuthnSession
	now      func() time.Time
}

// NewInMemoryWebAuthnSessionRepository constructs an in-process
// session store. Safe for concurrent use.
func NewInMemoryWebAuthnSessionRepository() *InMemoryWebAuthnSessionRepository {
	return &InMemoryWebAuthnSessionRepository{
		sessions: make(map[string]inMemoryWebAuthnSession),
		now:      time.Now,
	}
}

// Save stores data under key with the supplied TTL. It also BOUNDS the
// map (P2-11): it opportunistically sweeps expired entries, then — for a
// NEW key — evicts the oldest-expiring entries until the map is under
// maxWebAuthnSessions, so never-finished ceremonies cannot grow memory
// without limit. All under the existing mu; no new locks.
func (r *InMemoryWebAuthnSessionRepository) Save(_ context.Context, key string, data *webauthn.SessionData, ttl time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()

	// Opportunistic expiry sweep — nothing else prunes un-Got keys.
	for k, e := range r.sessions {
		if now.After(e.expiresAt) {
			delete(r.sessions, k)
		}
	}

	// Hard cap. Overwriting an existing key does not grow the map, so
	// only a NEW key needs to make room. Evict the oldest-expiring entry
	// each pass until there is room for the insert.
	if _, exists := r.sessions[key]; !exists {
		for len(r.sessions) >= maxWebAuthnSessions {
			var oldestKey string
			var oldestExp time.Time
			first := true
			for k, e := range r.sessions {
				if first || e.expiresAt.Before(oldestExp) {
					oldestKey, oldestExp, first = k, e.expiresAt, false
				}
			}
			if first { // map empty (defensive) — nothing to evict
				break
			}
			delete(r.sessions, oldestKey)
		}
	}

	r.sessions[key] = inMemoryWebAuthnSession{
		data:      data,
		expiresAt: now.Add(ttl),
	}
	return nil
}

// Get retrieves the entry for key, returning ErrWebAuthnSessionNotFound
// when absent and ErrWebAuthnSessionExpired when present-but-stale.
// Expired entries are evicted under the same lock.
func (r *InMemoryWebAuthnSessionRepository) Get(_ context.Context, key string) (*webauthn.SessionData, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.sessions[key]
	if !ok {
		return nil, ErrWebAuthnSessionNotFound
	}
	if r.now().After(entry.expiresAt) {
		delete(r.sessions, key)
		return nil, ErrWebAuthnSessionExpired
	}
	return entry.data, nil
}

// Consume ATOMICALLY reads and removes the entry for key in a SINGLE
// lock acquisition — the single-use primitive the finish paths use.
// Same sentinels as Get: ErrWebAuthnSessionNotFound when absent,
// ErrWebAuthnSessionExpired when present-but-stale. The entry is removed
// on EVERY hit (live or expired), so two concurrent Consume calls for
// the same key yield exactly one winner and a replay finds nothing.
func (r *InMemoryWebAuthnSessionRepository) Consume(_ context.Context, key string) (*webauthn.SessionData, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.sessions[key]
	if !ok {
		return nil, ErrWebAuthnSessionNotFound
	}
	// Remove under the SAME lock BEFORE returning — this is what makes
	// single-use atomic: a racing Consume of the same key sees it gone.
	delete(r.sessions, key)
	if r.now().After(entry.expiresAt) {
		return nil, ErrWebAuthnSessionExpired
	}
	return entry.data, nil
}

// Delete removes the entry for key. Idempotent.
func (r *InMemoryWebAuthnSessionRepository) Delete(_ context.Context, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, key)
	return nil
}

// Static interface assertion — keep WebAuthnSessionRepository and
// this concrete type wired together so a future seam change breaks
// the build at the implementation site.
var _ WebAuthnSessionRepository = (*InMemoryWebAuthnSessionRepository)(nil)
