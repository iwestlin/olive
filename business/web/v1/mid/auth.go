// Package mid contains the set of middleware functions.
package mid

import (
	"context"
	"net/http"

	v1Web "github.com/go-olive/olive/business/web/v1"
	"github.com/go-olive/olive/foundation/web"
)

// ctxKeySession is the context key under which the authenticated subject is
// stored for handlers downstream.
type ctxKeySession struct{}

// SubjectFromContext returns the authenticated subject (username) stored by
// the Authenticate middleware. Returns an empty string when no session is
// attached.
func SubjectFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeySession{}).(string)
	return v
}

// withSubject stores the authenticated subject on the request context.
func withSubject(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, ctxKeySession{}, subject)
}

// Authenticate returns a web.Middleware that rejects any request that is not
// carrying a valid signed session issued by /v1/user/login. On success the
// subject is stored in the request context.
func Authenticate(store *SessionStore) web.Middleware {
	return func(handler web.Handler) web.Handler {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
			if store == nil {
				// Defensive: a deployment that turned auth off shouldn't allow
				// privileged operations through zero value.
				return v1Web.NewRequestError(
					errAuthDisabled, http.StatusUnauthorized)
			}
			value := SessionFromRequest(r)
			if value == "" {
				return v1Web.NewRequestError(
					errNoSession, http.StatusUnauthorized)
			}
			subject, err := store.Verify(value)
			if err != nil {
				return v1Web.NewRequestError(
					errBadSession, http.StatusUnauthorized)
			}
			return handler(withSubject(ctx, subject), w, r)
		}
	}
}