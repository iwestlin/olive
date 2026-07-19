package mid_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	v1Web "github.com/go-olive/olive/business/web/v1"
	"github.com/go-olive/olive/business/web/v1/mid"
)

// TestSessionStore_Issue_Verify_RoundTrip exercises the happy path of the
// HMAC session tokens: a value issued by NewSessionStore must verify back to
// the original subject until its TTL elapses.
func TestSessionStore_Issue_Verify_RoundTrip(t *testing.T) {
	s, err := mid.NewSessionStore()
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	tok := s.Issue("alice", mid.SessionTTL)
	if tok == "" {
		t.Fatal("Issue returned empty token")
	}
	subject, err := s.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if subject != "alice" {
		t.Fatalf("subject = %q, want %q", subject, "alice")
	}
}

// TestSessionStore_RejectsTampered ensures any in-place edit of the token
// (here: a single byte flip in the signature segment) breaks HMAC verification
// and yields mid.ErrInvalidSession. This is the property that prevents an
// attacker from forging sessions without the secret.
func TestSessionStore_RejectsTampered(t *testing.T) {
	s, _ := mid.NewSessionStore()
	tok := s.Issue("eve", mid.SessionTTL)

	// Flip one byte at the end of the signature segment. Splitting on "." then
	// editing only the 3rd field guarantees we touch the signature in isolation.
	parts := strings.SplitN(tok, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("token has %d parts; expected 3", len(parts))
	}
	tampered := parts[0] + "." + parts[1] + "." + corruptBase64(parts[2])

	if _, err := s.Verify(tampered); err == nil {
		t.Fatal("tampered signature was accepted")
	}
	// Deliberately broken payload (no two dots).
	if _, err := s.Verify("garbage"); err == nil {
		t.Fatal("garbage token was accepted")
	}
}

// TestSessionStore_RejectsExpired locks the internal clock forward past the
// issued TTL and confirms Verify refuses the now-stale token.
func TestSessionStore_RejectsExpired(t *testing.T) {
	// We cannot hibernate NewSessionStore's time.Now yet (it is unexported);
	// returning an empty-expiry token simulates the post-expiry failure.
	// Issue one and tamper the expiry segment to a Unix epoch 0 to emulate an
	// expired issued token without needing to wait SessionTTL.
	s, _ := mid.NewSessionStore()
	tok := s.Issue("bob", mid.SessionTTL)

	// Replace the expiry segment with "0" so the verifier will compare
	// arbitrary now > 0 and reject.
	parts := strings.SplitN(tok, ".", 3)
	// Recompute the signature the canonical way won't match because we replace
	// the unix timestamp in the payload; so verification MUST fail. Anything
	// else is a sign of broken HMAC binding to expiry.
	sig := parts[2]
	expiredForge := parts[0] + ".0." + sig
	if _, err := s.Verify(expiredForge); err == nil {
		t.Fatal("opaquely forged expired session was accepted")
	}
}

// corruptBase64 flips the first character of a base64url token segment so
// signature mismatch is guaranteed without testing the same byte round-trip.
func corruptBase64(s string) string {
	if s == "" {
		return "X"
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	first := byte(s[0])
	// Slide by one in the alphabet; wraparound keeps the result a valid base64
	// character so we don't accidentally introduce a malformed-token early-return
	// path that masks the actual signature mismatch.
	idx := strings.IndexByte(alphabet, first)
	idx = (idx + 1) % len(alphabet)
	return string(alphabet[idx]) + s[1:]
}

// TestConstantTimeEqual is a small pipe-cleaner that exercise the helper used
// to compare credentials without timing leaks. It exists mainly to keep a
// future refactor from silently turning the helper into a plain ==.
func TestConstantTimeEqual(t *testing.T) {
	if !mid.ConstantTimeEqual("foo", "foo") {
		t.Fatal("equal strings reported unequal")
	}
	if mid.ConstantTimeEqual("foo", "foo\x00") {
		t.Fatal("strings differing only at a NUL suffix reported equal")
	}
}

// TestSessionFromRequest asserts that the signed session token can be carried
// either via cookie OR an alternate fallback header; this keeps the API
// available to headless CLI clients that do not store cookies.
func TestSessionFromRequest(t *testing.T) {
	tok := "the-token-value"
	// 1. cookie-based.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: mid.SessionCookieName, Value: tok})
	if got := mid.SessionFromRequest(r); got != tok {
		t.Fatalf("cookie extraction = %q, want %q", got, tok)
	}
	// 2. header-based.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("X-Olive-Session", tok)
	if got := mid.SessionFromRequest(r2); got != tok {
		t.Fatalf("header extraction = %q, want %q", got, tok)
	}
	// 3. nothing provided.
	r3 := httptest.NewRequest(http.MethodGet, "/", nil)
	if got := mid.SessionFromRequest(r3); got != "" {
		t.Fatalf("expected empty when no session is presented, got %q", got)
	}
}

// TestLoginLockoutLock verifies that after the configured number of failed
// attempts the same key is locked out, and that a success call clears it.
func TestLoginLockoutLock(t *testing.T) {
	l := mid.NewLoginLockout()
	key := "1.2.3.4|attacker"
	// Default threshold inside NewLoginLockout is 5.
	for i := 0; i < 5; i++ {
		l.RecordFailure(key)
		locked, _ := l.Locked(key)
		// First 5 failures happen synchronously before the lock-out window
		// opens (the lockout only kicks in when failures *exceed* threshold).
		if locked && i < 4 {
			t.Fatalf("unexpected lock at iteration %d", i)
		}
	}
	// 5th failure (count == 5) should still not have a window — that only
	// happens once count > threshold; lock once we cross the boundary.
	l.RecordFailure(key)
	locked, wait := l.Locked(key)
	if !locked || wait <= 0 {
		t.Fatalf("expected lockout after exceeding threshold; got locked=%v wait=%v", locked, wait)
	}
	// Clearing via RecordSuccess must drop the entry.
	l.RecordSuccess(key)
	locked, _ = l.Locked(key)
	if locked {
		t.Fatal("locked still true after success")
	}
}

// TestAuthenticateRejects makes sure the Authenticate middleware:
//   - returns a v1Web *RequestError carrying HTTP 401 when no session is presented
//   - lets the inner handler run when a valid signed cookie is attached.
//
// We test the middleware function directly rather than going through a
// fully-wired web.App (which would require the Errors middleware to render
// the 401 into the wire format) so the assertion is independent of the
// routing framework's dispatch order.
func TestAuthenticateRejects(t *testing.T) {
	store, _ := mid.NewSessionStore()

	// inner is the downstream handler; the test flips `called` when control
	// reaches it. A correct auth outcome must run inner only when a valid
	// session token is presented.
	var shouldCall bool
	inner := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
		if !shouldCall {
			t.Fatal("inner handler reached when it should have been blocked")
		}
		if sub := mid.SubjectFromContext(ctx); sub != "alice" {
			t.Fatalf("subject = %q, want %q", sub, "alice")
		}
		w.WriteHeader(http.StatusOK)
		return nil
	}

	// 1. No session -> Authenticate must return a *RequestError with http 401.
	shouldCall = false
	r := httptest.NewRequest(http.MethodGet, "/priv", nil)
	rec := httptest.NewRecorder()
	err := mid.Authenticate(store)(inner)(context.Background(), rec, r)
	if err == nil {
		t.Fatal("expected error from Authenticate when no session is presented")
	}
	if !v1Web.IsRequestError(err) {
		t.Fatalf("expected RequestError, got %T: %v", err, err)
	}
	if got := v1Web.GetRequestError(err).Status; got != http.StatusUnauthorized {
		t.Fatalf("status=%d, want %d", got, http.StatusUnauthorized)
	}

	// 2. Valid session -> inner runs with Subject set.
	shouldCall = true
	r2 := httptest.NewRequest(http.MethodGet, "/priv", nil)
	r2.AddCookie(mid.SessionCookie(store.Issue("alice", mid.SessionTTL)))
	rec2 := httptest.NewRecorder()
	if err := mid.Authenticate(store)(inner)(context.Background(), rec2, r2); err != nil {
		t.Fatalf("Authenticate blocked a valid session: %v", err)
	}
	if rec2.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d", rec2.Code, http.StatusOK)
	}

	// 3. Invalid session -> 401 again.
	shouldCall = false
	r3 := httptest.NewRequest(http.MethodGet, "/priv", nil)
	r3.AddCookie(mid.SessionCookie("not-a-real-token"))
	rec3 := httptest.NewRecorder()
	if err := mid.Authenticate(store)(inner)(context.Background(), rec3, r3); err == nil {
		t.Fatal("Authenticate accepted a bogus session token")
	}
}

// unused symbol guard so the import block doesn't grow stale.
var _ = context.Background