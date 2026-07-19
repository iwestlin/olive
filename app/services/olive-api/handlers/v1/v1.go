// Package v1 contains the full set of handler functions and routes
// supported by the v1 web api.
package v1

import (
	"net/http"

	"github.com/go-olive/olive/app/services/olive-api/handlers/v1/configgrp"
	"github.com/go-olive/olive/app/services/olive-api/handlers/v1/showgrp"
	"github.com/go-olive/olive/app/services/olive-api/handlers/v1/testgrp"
	"github.com/go-olive/olive/app/services/olive-api/handlers/v1/usrgrp"
	"github.com/go-olive/olive/business/core/config"
	"github.com/go-olive/olive/business/core/show"
	"github.com/go-olive/olive/business/web/v1/mid"
	"github.com/go-olive/olive/engine/kernel"
	"github.com/go-olive/olive/foundation/web"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
)

// Config contains all the mandatory systems required by handlers.
type Config struct {
	Log      *zap.SugaredLogger
	DB       *sqlx.DB
	K        *kernel.Kernel
	Sessions *mid.SessionStore
	Lockout  *mid.LoginLockout

	// Auth is the middleware applied to all routes that mutate state or
	// return privileged data. It is nil-safe: an empty Authenticate store
	// simply rejects every protected request.
	Auth web.Middleware
}

// Routes binds all the version 1 routes. Routes that carry privileged data
// (shows, configs) are wrapped with the Authenticate middleware; the public
// routes (/user/login, /user/logout, /test) intentionally remain open.
func Routes(app *web.App, cfg Config) {
	const version = "v1"

	auth := cfg.Auth

	// ---------------------------------------------------------------------------
	// show management - PRIVILEGED
	// ---------------------------------------------------------------------------
	sgh := showgrp.Handlers{
		Show: show.NewCore(cfg.Log, cfg.DB),
		K:    cfg.K,
	}
	app.Handle(http.MethodGet, version, "/shows/:pageIndex/:pageSize", sgh.Query, auth)
	app.Handle(http.MethodGet, version, "/shows/:id", sgh.QueryByID, auth)
	app.Handle(http.MethodPost, version, "/shows", sgh.Create, auth)
	app.Handle(http.MethodPut, version, "/shows/:id", sgh.Update, auth)
	app.Handle(http.MethodDelete, version, "/shows/:id", sgh.Delete, auth)

	// ---------------------------------------------------------------------------
	// test endpoints - PUBLIC (no state)
	// ---------------------------------------------------------------------------
	tgh := testgrp.Handlers{
		Log: cfg.Log,
	}
	app.Handle(http.MethodGet, version, "/test", tgh.Test)

	// ---------------------------------------------------------------------------
	// user endpoints - PUBLIC login/logout; everything else is gated by the
	// signed cookie issued here.
	// ---------------------------------------------------------------------------
	ugh := usrgrp.Handlers{
		Log:      cfg.Log,
		K:        cfg.K,
		Sessions: cfg.Sessions,
		Lockout:  cfg.Lockout,
	}
	app.Handle(http.MethodPost, version, "/user/login", ugh.Login)
	app.Handle(http.MethodGet, version, "/user/logout", ugh.Logout)

	// ---------------------------------------------------------------------------
	// config endpoints - PRIVILEGED (full control of engine core_config)
	// ---------------------------------------------------------------------------
	cgh := configgrp.Handlers{
		Config: config.NewCore(cfg.Log, cfg.DB),
		K:      cfg.K,
	}
	app.Handle(http.MethodGet, version, "/configs/:key", cgh.QueryByKey, auth)
	app.Handle(http.MethodPost, version, "/configs", cgh.Create, auth)
	app.Handle(http.MethodPut, version, "/configs/:key", cgh.Update, auth)
	app.Handle(http.MethodDelete, version, "/configs/:key", cgh.Delete, auth)
}