// Package handlers contains the full set of handler functions and routes
// supported by the web api.
package handlers

import (
	"expvar"
	"net/http"
	"net/http/pprof"
	"os"

	"github.com/go-olive/olive/app/services/olive-api/handlers/debug/checkgrp"
	v1 "github.com/go-olive/olive/app/services/olive-api/handlers/v1"
	"github.com/go-olive/olive/business/web/v1/mid"
	"github.com/go-olive/olive/engine/kernel"
	"github.com/go-olive/olive/foundation/web"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
)

// DebugStandardLibraryMux registers all the debug routes from the standard lib
// into a new mux, bypassing the use of the DefaultServerMux.
func DebugStandardLibraryMux() *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.Handle("/debug/vars", expvar.Handler())

	return mux
}

// DebugMux registers all the debug standard library routes and then custom
// debug application routes for the service. If basicUser/basicPass are both
// non-empty the mux is wrapped in HTTP Basic-Auth so pprof/expvar are not
// exposed unauthenticated.
func DebugMux(build string, log *zap.SugaredLogger, db *sqlx.DB, basicUser, basicPass string) http.Handler {
	mux := DebugStandardLibraryMux()

	cgh := checkgrp.Handlers{
		Build: build,
		Log:   log,
		DB:    db,
	}
	mux.HandleFunc("/debug/readiness", cgh.Readiness)
	mux.HandleFunc("/debug/liveness", cgh.Liveness)

	if basicUser != "" && basicPass != "" {
		return basicAuth(mux, basicUser, basicPass)
	}
	return mux
}

// basicAuth wraps h with HTTP Basic authentication using constant-time
// comparison. An empty u/p pair means: do not gate (assume operator bound
// the debug listener to a loopback address only).
func basicAuth(h http.Handler, user, pass string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || !mid.ConstantTimeEqual(u, user) || !mid.ConstantTimeEqual(p, pass) {
			w.Header().Set("WWW-Authenticate", `Basic realm="olive-debug"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// APIMuxConfig contains all the mandatory systems required by handlers.
type APIMuxConfig struct {
	Shutdown chan os.Signal
	Log      *zap.SugaredLogger
	DB       *sqlx.DB
	K        *kernel.Kernel

	// Sessions signs and verifies login session cookies.
	Sessions *mid.SessionStore
	// Lockout rate-limits brute-force attempts on /v1/user/login.
	Lockout *mid.LoginLockout
}

// APIMux constructs an http.Handler with all application routes defined. The
// outer middleware chain runs Logger -> Errors -> Panics, then the v1
// route group attaches Authenticate to the routes that require a valid
// session.
func APIMux(cfg APIMuxConfig) *web.App {
	app := web.NewApp(
		cfg.Shutdown,
		mid.Logger(cfg.Log),
		mid.Errors(cfg.Log),
		mid.Panics(),
	)

	v1.Routes(app, v1.Config{
		Log:      cfg.Log,
		DB:       cfg.DB,
		K:        cfg.K,
		Sessions: cfg.Sessions,
		Lockout:  cfg.Lockout,
		Auth:     mid.Authenticate(cfg.Sessions),
	})

	return app
}