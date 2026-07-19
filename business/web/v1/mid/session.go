// Package mid contains the set of middleware functions.
package mid

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SessionCookieName is the name of the signed session cookie issued by the
// portal login endpoint. The portal frontend is expected to be served from
// the same origin as the olive-api so the browser ships this cookie
// automatically on subsequent XHR/fetch calls (it is HttpOnly, SameSite=Lax).
const SessionCookieName = "olive_session"

// altSessionHeader allows non-browser clients to present the same signed
// session value when cookies can't be used.
const altSessionHeader = "X-Olive-Session"

// SessionTTL is the lifetime of an issued session.
const SessionTTL = 12 * time.Hour

// ErrInvalidSession is returned by SessionStore.Verify when a session value
// is malformed, expired or has a bad signature.
var ErrInvalidSession = errors.New("invalid session")

// SessionStore issues and verifies HMAC-SHA256 signed session tokens. A new
// store generates its own random secret at construction time so existing
// sessions become invalid on process restart. The secret never leaves the
// process (it is not part of engine/config.Config and so cannot leak through
// core_config hot-swap).
type SessionStore struct {
	secret []byte
	now    func() time.Time
}

// NewSessionStore constructs a SessionStore seeded with a random 32-byte
// secret.
func NewSessionStore() (*SessionStore, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generating session secret: %w", err)
	}
	return &SessionStore{secret: secret, now: time.Now}, nil
}

// Issue signs the given subject (username) and expiry into an opaque cookie
// value: base64url(user).expiryUnix.base64url(hmac).
func (s *SessionStore) Issue(username string, ttl time.Duration) string {
	expiry := s.now().Add(ttl).Unix()
	payload := username + "|" + fmt.Sprintf("%d", expiry)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString([]byte(username)) +
		"." +
		fmt.Sprintf("%d", expiry) +
		"." +
		base64.RawURLEncoding.EncodeToString(sig)
}

// Verify validates an opaque session value previously produced by Issue.
// On success the subject (username) is returned. On any failure
// ErrInvalidSession is returned.
func (s *SessionStore) Verify(value string) (string, error) {
	parts := strings.SplitN(value, ".", 3)
	if len(parts) != 3 {
		return "", ErrInvalidSession
	}
	username, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ErrInvalidSession
	}
	var expiry int64
	if _, err := fmt.Sscanf(parts[1], "%d", &expiry); err != nil {
		return "", ErrInvalidSession
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", ErrInvalidSession
	}

	// Recompute the HMAC and compare in constant time.
	payload := string(username) + "|" + fmt.Sprintf("%d", expiry)
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, sig) {
		return "", ErrInvalidSession
	}
	if s.now().Unix() >= expiry {
		return "", ErrInvalidSession
	}
	return string(username), nil
}

// SessionCookie builds the http.Cookie to be Set-Cookie'd on a successful
// login. HttpOnly blocks JS access, SameSite=Lax allows the cookie to
// travel with same-origin top-level navigations and XHR.
func SessionCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false, // set true at deployment behind TLS
		MaxAge:   int(SessionTTL.Seconds()),
	}
}

// ClearedSessionCookie returns a cookie that immediately expires the session
// cookie on the client.
func ClearedSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

// SessionFromRequest extracts a session token from request cookie or the
// alternate header.
func SessionFromRequest(r *http.Request) string {
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	if v := r.Header.Get(altSessionHeader); v != "" {
		return v
	}
	return ""
}

// ConstantTimeEqual exposes subtle.ConstantTimeCompare as a small helper so
// callers can compare credentials without timing leaks.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}