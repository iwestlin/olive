package main

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ardanlabs/conf/v3"
	"github.com/go-olive/olive/app/services/olive-api/handlers"
	"github.com/go-olive/olive/business/core/config"
	"github.com/go-olive/olive/business/core/show"
	"github.com/go-olive/olive/business/sys/database"
	"github.com/go-olive/olive/business/web/v1/mid"
	"github.com/go-olive/olive/engine/kernel"
	l "github.com/go-olive/olive/engine/log"
	"github.com/go-olive/olive/foundation/logger"
	"go.uber.org/zap"
)

// build is the git version of this program. It is set using build flags in the makefile.
var build = "develop"

func main() {

	// Construct the application logger.
	log, err := logger.New("OLIVE-API")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer log.Sync()

	// Perform the startup and shutdown sequence.
	if err := run(log); err != nil {
		log.Errorw("startup", "ERROR", err)
		log.Sync()
		os.Exit(1)
	}
}

func run(log *zap.SugaredLogger) error {

	// =========================================================================
	// Configuration

	cfg := struct {
		conf.Version
		Web struct {
			ReadTimeout     time.Duration `conf:"default:5s"`
			WriteTimeout    time.Duration `conf:"default:10s"`
			IdleTimeout     time.Duration `conf:"default:120s"`
			ShutdownTimeout time.Duration `conf:"default:20s"`
			// Defaults bind to loopback so a fresh deployment refuses remote
			// connections until an operator opts in with an explicit
			// 0.0.0.0:* address.
			APIHost   string `conf:"default:127.0.0.1:3000"`
			DebugHost string `conf:"default:127.0.0.1:4000"`
			TLSCert   string `conf:"default:"`
			TLSKey    string `conf:"default:"`
			// When set together, the debug listener is gated with HTTP
			// Basic-Auth; if either is empty AND DebugHost is loopback the
			// debug surface remains open only to local callers.
			DebugUser string `conf:"default:"`
			DebugPass string `conf:"default:,mask"`
		}
		DB struct {
			User         string `conf:"default:postgres"`
			Password     string `conf:"default:postgres,mask"`
			Host         string `conf:"default:localhost"`
			Name         string `conf:"default:postgres"`
			MaxIdleConns int    `conf:"default:0"`
			MaxOpenConns int    `conf:"default:0"`
			DisableTLS   bool   `conf:"default:true"`
		}
	}{
		Version: conf.Version{
			Build: build,
			Desc:  "Copyright 2022 luxcgo",
		},
	}

	const prefix = "OLIVE"
	help, err := conf.Parse(prefix, &cfg)
	if err != nil {
		if errors.Is(err, conf.ErrHelpWanted) {
			fmt.Println(help)
			return nil
		}
		return fmt.Errorf("parsing config: %w", err)
	}

	// =========================================================================
	// App Starting

	log.Infow("starting service", "version", build)
	defer log.Infow("shutdown complete")

	out, err := conf.String(&cfg)
	if err != nil {
		return fmt.Errorf("generating config for output: %w", err)
	}
	log.Infow("startup", "config", out)

	expvar.NewString("build").Set(build)

	// =========================================================================
	// Database Support

	// Create connectivity to the database.
	log.Infow("startup", "status", "initializing database support", "host", cfg.DB.Host)

	db, err := database.Open(database.Config{
		User:         cfg.DB.User,
		Password:     cfg.DB.Password,
		Host:         cfg.DB.Host,
		Name:         cfg.DB.Name,
		MaxIdleConns: cfg.DB.MaxIdleConns,
		MaxOpenConns: cfg.DB.MaxOpenConns,
		DisableTLS:   cfg.DB.DisableTLS,
	})
	if err != nil {
		return fmt.Errorf("connecting to db: %w", err)
	}
	defer func() {
		log.Infow("shutdown", "status", "stopping database support", "host", cfg.DB.Host)
		db.Close()
	}()

	// =========================================================================
	// Start Engine
	log.Infow("startup", "status", "initializing olive engine")

	configCore := config.NewCore(log, db)
	ctx1, cancel := context.WithTimeout(context.Background(), cfg.Web.ReadTimeout)
	defer cancel()
	engineConfig, err := configCore.QueryEngineConfig(ctx1)
	if err != nil {
		return fmt.Errorf("query engine config: %w", err)
	}
	engineConfig.CheckAndFix()
	engineLogger := l.InitLogger(engineConfig.LogDir)
	engineLogger.Infof("Powered by go-olive/olive %s", build)

	showCore := show.NewCore(log, db)
	ctx2, cancel := context.WithTimeout(context.Background(), cfg.Web.ReadTimeout)
	defer cancel()
	showsEnabled, err := showCore.QueryAllEnabled(ctx2)
	if err != nil {
		return fmt.Errorf("query shows enabled: %w", err)
	}

	k := kernel.New(engineLogger, engineConfig, showsEnabled)
	go func() {
		k.Run()
	}()

	// todo(lc): timing is somewhat wrong
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Web.ShutdownTimeout)
		defer cancel()
		k.Shutdown(ctx)
	}()

	// =========================================================================
	// Start Debug Service

	log.Infow("startup", "status", "debug v1 router started", "host", cfg.Web.DebugHost)

	// Refuse to expose pprof / expvar without authentication on a
	// non-loopback interface: those endpoints leak goroutine snapshots, heap
	// data and live connection credentials, and offer trivial DoS via expensive
	// profiles.
	if !isLoopbackHost(cfg.Web.DebugHost) && (cfg.Web.DebugUser == "" || cfg.Web.DebugPass == "") {
		return errors.New("debug listener bound to a non-loopback address without OLIVE_WEB_DEBUGUSER / OLIVE_WEB_DEBUGPASS; refusing to start")
	}

	// The Debug function returns a mux to listen and serve on for all the debug
	// related endpoints. This includes the standard library endpoints.

	// Construct the mux for the debug calls.
	debugMux := handlers.DebugMux(build, log, db, cfg.Web.DebugUser, cfg.Web.DebugPass)

	// Start the service listening for debug requests.
	// Not concerned with shutting this down with load shedding.
	go func() {
		if err := http.ListenAndServe(cfg.Web.DebugHost, debugMux); err != nil {
			log.Errorw("shutdown", "status", "debug v1 router closed", "host", cfg.Web.DebugHost, "ERROR", err)
		}
	}()

	// =========================================================================
	// Start API Service

	log.Infow("startup", "status", "initializing API support")

	// Warn if the API listener is exposed without TLS so operators get a
	// nudge toward running the service behind TLS termination.
	if !isLoopbackHost(cfg.Web.APIHost) && cfg.Web.TLSCert == "" && cfg.Web.TLSKey == "" {
		log.Warnw("startup", "WARNING", "API listening on a non-loopback address without TLS; consider setting TLSCert/TLSKey or fronting olive-api with a TLS-terminating reverse proxy")
	}

	// Make a channel to listen for an interrupt or terminate signal from the OS.
	// Use a buffered channel because the signal package requires it.
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	// Build the auth subsystem: a per-process secret for HMAC-signed session
	// cookies plus a brute-force lockout tracker.
	sessions, err := mid.NewSessionStore()
	if err != nil {
		return fmt.Errorf("initializing session store: %w", err)
	}
	lockout := mid.NewLoginLockout()

	// Construct the mux for the API calls.
	apiMux := handlers.APIMux(handlers.APIMuxConfig{
		Shutdown: shutdown,
		Log:      log,
		DB:       db,
		K:        k,
		Sessions: sessions,
		Lockout:  lockout,
	})

	// Construct a server to service the requests against the mux.
	api := http.Server{
		Addr:         cfg.Web.APIHost,
		Handler:      apiMux,
		ReadTimeout:  cfg.Web.ReadTimeout,
		WriteTimeout: cfg.Web.WriteTimeout,
		IdleTimeout:  cfg.Web.IdleTimeout,
		ErrorLog:     zap.NewStdLog(log.Desugar()),
	}

	// Make a channel to listen for errors coming from the listener. Use a
	// buffered channel so the goroutine can exit if we don't collect this error.
	serverErrors := make(chan error, 1)

	// Start the service listening for api requests. Honor TLS when the
	// operator supplied a cert/key pair so admin credentials don't travel
	// over plaintext HTTP at the perimeter.
	go func() {
		log.Infow("startup", "status", "api router started", "host", api.Addr, "tls", cfg.Web.TLSCert != "")
		if cfg.Web.TLSCert != "" && cfg.Web.TLSKey != "" {
			serverErrors <- api.ListenAndServeTLS(cfg.Web.TLSCert, cfg.Web.TLSKey)
		} else {
			serverErrors <- api.ListenAndServe()
		}
	}()

	// =========================================================================
	// Shutdown

	// Blocking main and waiting for shutdown.
	select {
	case err := <-serverErrors:
		return fmt.Errorf("server error: %w", err)

	case sig := <-shutdown:
		log.Infow("shutdown", "status", "shutdown started", "signal", sig)
		defer log.Infow("shutdown", "status", "shutdown complete", "signal", sig)

		// Give outstanding requests a deadline for completion.
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Web.ShutdownTimeout)
		defer cancel()

		// Asking listener to shut down and shed load.
		if err := api.Shutdown(ctx); err != nil {
			api.Close()
			return fmt.Errorf("could not stop server gracefully: %w", err)
		}
	}

	return nil
}

// isLoopbackHost reports whether the host portion of an "ip:port" listen
// address refers to a loopback address. Extraneous whitespace and IPv6
// "[::1]:port" forms are normalized before the comparison.
func isLoopbackHost(addr string) bool {
	host := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		host = addr[:i]
	}
	host = strings.TrimSpace(host)
	host = strings.Trim(host, "[]")
	switch host {
	case "", "localhost", "127.0.0.1", "::1":
		return true
	default:
		return strings.HasPrefix(host, "127.")
	}
}
