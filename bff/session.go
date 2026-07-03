package bff

import (
	"sync"
	"time"

	"github.com/ovander/backendkit/socrate"
)

// UserInfo is the identity surfaced to the SPA (e.g. via /bff/session). It is
// derived from the token response and access-token claims — never the raw
// tokens.
type UserInfo struct {
	Sub   string   `json:"sub"`
	Email string   `json:"email,omitempty"`
	Name  string   `json:"name,omitempty"`
	Roles []string `json:"roles"`
}

// Session is the server-side state for one logged-in browser. The browser holds
// only the opaque ID (the cookie value); the tokens never leave the BFF.
//
// All field access must go through the accessor methods, which hold mu. The
// in-memory store returns the live *Session pointer, so concurrent requests for
// the same session (an SSE stream alongside API calls, a proactive refresh)
// would otherwise race on the token fields — the methods below make that
// access safe.
type Session struct {
	mu sync.Mutex

	id           string
	accessToken  string
	refreshToken string
	idToken      string
	accessExpiry time.Time
	csrf         string
	created      time.Time
	lastSeen     time.Time
	user         UserInfo
}

// NewSession builds a session from a token set at login time. id and csrf
// should be freshly generated with RandomToken(32).
func NewSession(id, csrf string, ts *socrate.TokenSet, user UserInfo, now time.Time) *Session {
	s := &Session{
		id:      id,
		csrf:    csrf,
		created: now,
	}
	s.applyTokens(ts, now)
	s.user = user
	s.lastSeen = now
	return s
}

// ID returns the opaque session id (immutable, safe without the lock but read
// through the method for consistency).
func (s *Session) ID() string { return s.id }

func (s *Session) applyTokens(ts *socrate.TokenSet, now time.Time) {
	if ts == nil {
		return
	}
	s.accessToken = ts.AccessToken
	if ts.RefreshToken != "" {
		s.refreshToken = ts.RefreshToken
	}
	if ts.IDToken != "" {
		s.idToken = ts.IDToken
	}
	if ts.ExpiresIn > 0 {
		s.accessExpiry = now.Add(time.Duration(ts.ExpiresIn) * time.Second)
	}
}

// SetTokens applies a refreshed token set under the lock.
func (s *Session) SetTokens(ts *socrate.TokenSet, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applyTokens(ts, now)
}

// Touch updates the idle timestamp.
func (s *Session) Touch(now time.Time) {
	s.mu.Lock()
	s.lastSeen = now
	s.mu.Unlock()
}

// AccessValid reports whether the access token is still valid at now, keeping
// leeway seconds of head-room so a proactive refresh happens before expiry.
func (s *Session) AccessValid(now time.Time, leeway time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accessToken != "" && now.Add(leeway).Before(s.accessExpiry)
}

// AccessToken returns the current access token.
func (s *Session) AccessToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accessToken
}

// RefreshToken returns the current refresh token.
func (s *Session) RefreshToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshToken
}

// IDToken returns the current ID token.
func (s *Session) IDToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.idToken
}

// CSRF returns the session's CSRF token.
func (s *Session) CSRF() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.csrf
}

// MatchCSRF reports whether token equals the session's CSRF token, in constant
// time.
func (s *Session) MatchCSRF(token string) bool {
	s.mu.Lock()
	want := s.csrf
	s.mu.Unlock()
	return ConstantTimeEqual(token, want)
}

// User returns a copy of the session's identity.
func (s *Session) User() UserInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.user
	u.Roles = append([]string(nil), s.user.Roles...)
	return u
}

// SetUser replaces the session's identity.
func (s *Session) SetUser(u UserInfo) {
	s.mu.Lock()
	s.user = u
	s.mu.Unlock()
}

// SessionSnapshot is a serializable view of a Session's full state, for
// durable stores (e.g. Postgres) that need to persist a session across
// restarts. Session's fields are private (accessed only through the
// concurrency-safe methods above), so a store that outlives the process uses
// Session.Snapshot() to capture state to marshal and NewSessionFromSnapshot to
// rehydrate a *Session after unmarshalling. All fields are JSON-tagged for
// convenience; a store is free to use a different encoding.
type SessionSnapshot struct {
	ID           string    `json:"id"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	AccessExpiry time.Time `json:"access_expiry"`
	CSRF         string    `json:"csrf"`
	Created      time.Time `json:"created"`
	LastSeen     time.Time `json:"last_seen"`
	User         UserInfo  `json:"user"`
}

// Snapshot captures the session's full state for persistence.
func (s *Session) Snapshot() SessionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SessionSnapshot{
		ID:           s.id,
		AccessToken:  s.accessToken,
		RefreshToken: s.refreshToken,
		IDToken:      s.idToken,
		AccessExpiry: s.accessExpiry,
		CSRF:         s.csrf,
		Created:      s.created,
		LastSeen:     s.lastSeen,
		User:         s.user,
	}
}

// NewSessionFromSnapshot rehydrates a *Session from a previously captured
// SessionSnapshot (e.g. read back from a durable store after a restart).
func NewSessionFromSnapshot(snap SessionSnapshot) *Session {
	return &Session{
		id:           snap.ID,
		accessToken:  snap.AccessToken,
		refreshToken: snap.RefreshToken,
		idToken:      snap.IDToken,
		accessExpiry: snap.AccessExpiry,
		csrf:         snap.CSRF,
		created:      snap.Created,
		lastSeen:     snap.LastSeen,
		user:         snap.User,
	}
}

// SessionStore persists authenticated sessions. The in-memory implementation
// is the default; a Postgres-backed store can implement the same interface,
// using SessionSnapshot to (de)serialize each Session.
type SessionStore interface {
	Get(id string) (*Session, bool)
	Put(s *Session)
	Delete(id string)
	// Sweep evicts expired sessions; a background ticker should call it.
	Sweep()
}

// MemoryStore is a mutex-guarded in-memory SessionStore. Expiry is a sliding
// idle window OR an absolute lifetime, enforced lazily on Get and by Sweep.
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	idle     time.Duration
	absolute time.Duration
	now      func() time.Time
}

// NewMemoryStore builds a store with the given idle and absolute lifetimes. A
// zero duration disables that bound.
func NewMemoryStore(idle, absolute time.Duration) *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]*Session),
		idle:     idle,
		absolute: absolute,
		now:      time.Now,
	}
}

func (m *MemoryStore) expired(s *Session) bool {
	now := m.now()
	s.mu.Lock()
	created, lastSeen := s.created, s.lastSeen
	s.mu.Unlock()
	if m.absolute > 0 && now.Sub(created) >= m.absolute {
		return true
	}
	if m.idle > 0 && now.Sub(lastSeen) >= m.idle {
		return true
	}
	return false
}

// Get returns the live session for id, or (nil, false) if it is missing or
// expired (expired entries are deleted).
func (m *MemoryStore) Get(id string) (*Session, bool) {
	m.mu.RLock()
	s, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if m.expired(s) {
		m.Delete(id)
		return nil, false
	}
	return s, true
}

// Put stores or replaces a session.
func (m *MemoryStore) Put(s *Session) {
	m.mu.Lock()
	m.sessions[s.id] = s
	m.mu.Unlock()
}

// Delete removes a session.
func (m *MemoryStore) Delete(id string) {
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()
}

// Sweep removes all expired sessions.
func (m *MemoryStore) Sweep() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if m.expired(s) {
			delete(m.sessions, id)
		}
	}
}
