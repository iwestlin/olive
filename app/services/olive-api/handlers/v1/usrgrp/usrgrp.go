package usrgrp

import (
	"context"
	"net/http"
	"time"

	v1Web "github.com/go-olive/olive/business/web/v1"
	"github.com/go-olive/olive/business/web/v1/mid"
	"github.com/go-olive/olive/engine/kernel"
	"github.com/go-olive/olive/foundation/web"
	"go.uber.org/zap"
)

// Handlers manages the set of check enpoints.
type Handlers struct {
	Log     *zap.SugaredLogger
	K       *kernel.Kernel
	Sessions *mid.SessionStore
	Lockout  *mid.LoginLockout
}

// Login handler is for User logins. On success it issues an HttpOnly signed
// session cookie (SessionCookieName) and returns the permissions payload
// the portal expects. Failures are rate-limited per (IP, username) by the
// LoginLockout.
func (h Handlers) Login(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	var req LoginRequest
	if err := web.Decode(r, &req); err != nil {
		return v1Web.NewRequestError(err, http.StatusBadRequest)
	}

	key := mid.LoginKey(r.RemoteAddr, req.Username)

	// 1. Honor lockout window before doing any work.
	if locked, wait := h.Lockout.Locked(key); locked {
		return v1Web.NewRequestError(
			&lockedErr{wait: wait}, http.StatusTooManyRequests)
	}

	// 2. Validate credentials.
	if !h.K.IsValidPortalUser(req.Username, req.Password) {
		if h.Lockout != nil {
			h.Lockout.RecordFailure(key)
		}
		return v1Web.NewRequestError(
			errInvalidCredentials, http.StatusBadRequest)
	}
	if h.Lockout != nil {
		h.Lockout.RecordSuccess(key)
	}

	// 3. Issue signed session cookie.
	var token string
	if h.Sessions != nil {
		token = h.Sessions.Issue(req.Username, mid.SessionTTL)
		http.SetCookie(w, mid.SessionCookie(token))
	}

	status := struct {
		Permissions []string `json:"permissions"`
	}{
		Permissions: []string{"*.*.*"},
	}

	return mid.Respond(ctx, w, status, http.StatusOK)
}

// Logout handler is for User logouts. It clears the session cookie on the
// client. The server stays stateless so a "lost" cookie simply remains
// valid until its TTL even if a logout call failed to reach us; the client
// can call logout at any time.
func (h Handlers) Logout(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	http.SetCookie(w, mid.ClearedSessionCookie())
	return mid.Respond(ctx, w, nil, http.StatusOK)
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// lockedErr carries the remaining lockout window so the log/error path can
// surface it without leaking the int figure in the wire payload.
type lockedErr struct {
	wait time.Duration
}

func (e *lockedErr) Error() string { return "too many failed login attempts; try again later" }