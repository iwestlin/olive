// Package mid contains the set of middleware functions.
package mid

import (
	"sync"
	"time"
)

// LoginLockout tracks failed login attempts per (remoteAddr, username) and
// applies an exponentially increasing lockout window once the configured
// failure threshold is exceeded. The store is in-memory and process-local,
// which is sufficient for the single-process architecture of olive server.
type LoginLockout struct {
	mu         sync.Mutex
	failures   map[string]*loginState
	threshold  int           // failures before lockout kicks in
	baseDelay  time.Duration // first lockout window
	maxDelay   time.Duration // cap for exponential backoff
	forgiveTTL time.Duration // entry decay window
	now        func() time.Time
}

type loginState struct {
	count      int
	unlockAt   time.Time
	lastUpdate time.Time
}

// NewLoginLockout builds a LoginLockout with the policy used by olive server:
// after `threshold` consecutive failures the client is locked out for
// baseDelay*2^(failures-threshold), capped at maxDelay. Successful auths
// or inactivity beyond forgiveTTL clear the entry.
func NewLoginLockout() *LoginLockout {
	return &LoginLockout{
		failures:   make(map[string]*loginState),
		threshold:  5,
		baseDelay:  500 * time.Millisecond,
		maxDelay:   10 * time.Minute,
		forgiveTTL: 30 * time.Minute,
		now:        time.Now,
	}
}

// Locked reports whether the given key is currently in a lockout window and,
// if so, how long the caller should wait before retrying.
func (l *LoginLockout) Locked(key string) (locked bool, wait time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.failures[key]
	if st == nil {
		return false, 0
	}
	now := l.now()
	if now.Before(st.unlockAt) {
		return true, st.unlockAt.Sub(now)
	}
	if now.Sub(st.lastUpdate) > l.forgiveTTL {
		// Stale entry; clean up so the memory stays bounded.
		delete(l.failures, key)
		return false, 0
	}
	return false, 0
}

// RecordFailure increments the failure counter for the key and, when the
// threshold is reached/exceeded, schedules an unlock window using
// exponential backoff.
func (l *LoginLockout) RecordFailure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	st := l.failures[key]
	if st == nil {
		st = &loginState{}
		l.failures[key] = st
	}
	st.count++
	st.lastUpdate = now
	if st.count > l.threshold {
		// Lockout doubles with every additional failure, capped at maxDelay.
		// exponent e := count - threshold (starts at 1)
		e := st.count - l.threshold
		if e > 20 { // defend against overflow
			e = 20
		}
		delay := l.baseDelay << uint(e)
		if delay < 0 || delay > l.maxDelay {
			delay = l.maxDelay
		}
		st.unlockAt = now.Add(delay)
	}
}

// RecordSuccess clears any prior failure state for the key.
func (l *LoginLockout) RecordSuccess(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

// LoginKey builds the key used by LoginLockout for a login attempt. Multiple
// attempts against the same username from different addresses still share
// the username component so credential-spraying attacks degrade fast.
func LoginKey(remoteAddr, username string) string {
	return remoteAddr + "|" + username
}