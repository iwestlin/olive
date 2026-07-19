package command

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
	"github.com/go-olive/olive/app/tooling/olive-admin/commands"
	"github.com/go-olive/olive/business/core/config"
	"github.com/go-olive/olive/business/core/show"
	"github.com/go-olive/olive/business/sys/database"
	"github.com/go-olive/olive/business/web/v1/mid"
	"github.com/go-olive/olive/engine/kernel"
	l "github.com/go-olive/olive/engine/log"
	"github.com/go-olive/olive/foundation/logger"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var _ cmder = (*serverCmd)(nil)

type serverCmd struct {
	Web
	DB

	logDir  string
	saveDir string

	*baseBuilderCmd
}

type Web struct {
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	APIHost         string
	DebugHost       string
	TLSCert         string
	TLSKey          string
	DebugUser       string
	DebugPass       string
}

type DB struct {
	User         string
	Password     string `conf:"mask"`
	Host         string
	Name         string
	MaxIdleConns int
	MaxOpenConns int
	DisableTLS   bool
}

func (b *commandsBuilder) newServerCmd() *serverCmd {
	cc := &serverCmd{}
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Server provides olive-api support.",
		Long:  "Server provides olive-api support.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cc.run()
		},
	}
	cc.baseBuilderCmd = b.newBuilderCmd(cmd)

	// Web server tuning. Defaults now bind to loopback so a fresh deployment
	// rejects remote connections until an operator opts in with an explicit
	// 0.0.0.0:* address. Previous code bound the same field (ReadTimeout)
	// for four different flags by mistake, leaving write/idle/shutdown
	// timeouts silently fixed at their zero values. Each flag is now wired
	// to its own field so the config actually takes effect.
	cmd.Flags().DurationVar(&cc.ReadTimeout, "web-read-timeout", 5*time.Second, "HTTP request read timeout")
	cmd.Flags().DurationVar(&cc.WriteTimeout, "web-write-timeout", 10*time.Second, "HTTP response write timeout")
	cmd.Flags().DurationVar(&cc.IdleTimeout, "web-idle-timeout", 120*time.Second, "HTTP keep-alive idle timeout")
	cmd.Flags().DurationVar(&cc.ShutdownTimeout, "web-shutdown-timeout", 20*time.Second, "graceful shutdown timeout")
	cmd.Flags().StringVar(&cc.APIHost, "web-api-host", "127.0.0.1:3000", "API service listen address (loopback by default; use 0.0.0.0:3000 to expose)")
	cmd.Flags().StringVar(&cc.DebugHost, "web-debug-host", "127.0.0.1:4000", "debug/pprof listen address (loopback by default)")
	cmd.Flags().StringVar(&cc.TLSCert, "web-tls-cert", "", "path to TLS certificate (PEM). When set with --web-tls-key, API serves HTTPS")
	cmd.Flags().StringVar(&cc.TLSKey, "web-tls-key", "", "path to TLS private key (PEM). When set with --web-tls-cert, API serves HTTPS")
	cmd.Flags().StringVar(&cc.DebugUser, "web-debug-user", "", "basic-auth user for the debug listener; empty = no basic auth (loopback only)")
	cmd.Flags().StringVar(&cc.DebugPass, "web-debug-pass", "", "basic-auth password for the debug listener; empty = no basic auth (loopback only)")

	cmd.Flags().StringVar(&cc.User, "db-user", "postgres", "")
	cmd.Flags().StringVar(&cc.Password, "db-password", "postgres", "")
	cmd.Flags().StringVar(&cc.Host, "db-host", "localhost", "")
	cmd.Flags().StringVar(&cc.Name, "db-name", "postgres", "")
	cmd.Flags().IntVar(&cc.MaxIdleConns, "db-max-idle-conns", 0, "")
	cmd.Flags().IntVar(&cc.MaxOpenConns, "db-max-open-conns", 0, "")
	cmd.Flags().BoolVar(&cc.DisableTLS, "db-disable-tls", true, "")

	cmd.Flags().StringVarP(&cc.logDir, "logdir", "l", "", "log file directory")
	cmd.Flags().StringVarP(&cc.saveDir, "savedir", "s", "", "video file directory")

	return cc
}

func (c *serverCmd) run() error {
	log, err := logger.New("OLIVE-API")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer log.Sync()

	cfg := cfg{
		Web: c.Web,
		DB:  c.DB,
	}
	if err := c.serve(log, cfg); err != nil {
		log.Errorw("startup", "ERROR", err)
		log.Sync()
		os.Exit(1)
	}
	return nil
}

type cfg struct {
	Web
	DB
}

func (c *serverCmd) serve(log *zap.SugaredLogger, cfg cfg) (err error) {

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
	// Hazardous-host guard
	// Refuse to expose the debug listener on a non-loopback address unless the
	// operator explicitly configured HTTP Basic-Auth. pprof exposes goroutine
	// dumps and memory that can leak secrets and acts as a DoS amplification
	// endpoint when reachable from the internet.
	if !isLoopbackHost(cfg.Web.DebugHost) && (cfg.Web.DebugUser == "" || cfg.Web.DebugPass == "") {
		return errors.New("debug listener bound to a non-loopback address without --web-debug-user/--web-debug-pass; refusing to start")
	}
	// Likewise refuse to expose the API on a non-loopback address when TLS
	// is not configured, unless the operator has opted in via explicit
	// configuration. This keeps admin credentials off plaintext HTTP at the
	// perimeter of deployments that don't realize the default binding has
	// changed.
	if !isLoopbackHost(cfg.Web.APIHost) && cfg.Web.TLSCert == "" && cfg.Web.TLSKey == "" {
		log.Warnw("startup", "WARNING", "API listening on a non-loopback address without TLS; consider --web-tls-cert/--web-tls-key or a reverse proxy with TLS termination")
	}

	// =========================================================================
	// Database Support
	log.Infow("startup", "status", "initializing database support", "host", cfg.DB.Host)

	dbConfig := database.Config{
		User:         cfg.DB.User,
		Password:     cfg.DB.Password,
		Host:         cfg.DB.Host,
		Name:         cfg.DB.Name,
		MaxIdleConns: cfg.DB.MaxIdleConns,
		MaxOpenConns: cfg.DB.MaxOpenConns,
		DisableTLS:   cfg.DB.DisableTLS,
	}
	db, err := database.Open(dbConfig)
	if err != nil {
		return fmt.Errorf("connecting to db: %w", err)
	}
	defer func() {
		log.Infow("shutdown", "status", "stopping database support", "host", cfg.DB.Host)
		db.Close()
	}()

	if err := commands.Migrate(dbConfig); err != nil {
		return fmt.Errorf("migrating database: %w", err)
	}

	if err := commands.Seed(dbConfig); err != nil {
		return fmt.Errorf("seeding database: %w", err)
	}

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
	if c.logDir != "" {
		engineConfig.LogDir = c.logDir
	}
	if c.saveDir != "" {
		engineConfig.SaveDir = c.saveDir
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

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Web.ShutdownTimeout)
		defer cancel()
		go func(ctx context.Context) {
			k.Shutdown(ctx)
		}(ctx)

		select {
		case <-ctx.Done():
			newErr := errors.New("engine timeout, force quit")
			if err != nil {
				err = fmt.Errorf("%v\n%v", err, newErr)
			} else {
				err = newErr
			}
		case <-k.Done():
		}
	}()

	// =========================================================================
	// Auth subsystem (sessions + brute-force lockout)
	sessions, err := mid.NewSessionStore()
	if err != nil {
		return fmt.Errorf("initializing session store: %w", err)
	}
	lockout := mid.NewLoginLockout()

	// =========================================================================
	// Start Debug Service
	log.Infow("startup", "status", "debug v1 router started", "host", cfg.Web.DebugHost)

	debugMux := handlers.DebugMux(build, log, db, cfg.Web.DebugUser, cfg.Web.DebugPass)

	go func() {
		if err := http.ListenAndServe(cfg.Web.DebugHost, debugMux); err != nil {
			log.Errorw("shutdown", "status", "debug v1 router closed", "host", cfg.Web.DebugHost, "ERROR", err)
		}
	}()

	// =========================================================================
	// Start API Service
	log.Infow("startup", "status", "initializing API support")

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	apiMux := handlers.APIMux(handlers.APIMuxConfig{
		Shutdown: shutdown,
		Log:      log,
		DB:       db,
		K:        k,
		Sessions: sessions,
		Lockout:  lockout,
	})

	api := http.Server{
		Addr:         cfg.Web.APIHost,
		Handler:      apiMux,
		ReadTimeout:  cfg.Web.ReadTimeout,
		WriteTimeout: cfg.Web.WriteTimeout,
		IdleTimeout:  cfg.Web.IdleTimeout,
		ErrorLog:     zap.NewStdLog(log.Desugar()),
	}

	serverErrors := make(chan error, 1)
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

	select {
	case err := <-serverErrors:
		return fmt.Errorf("server error: %w", err)

	case sig := <-shutdown:
		engineLogger.WithField("signal", sig.String()).
			Info("handle request")

		log.Infow("shutdown", "status", "shutdown started", "signal", sig)
		defer log.Infow("shutdown", "status", "shutdown complete", "signal", sig)

		ctx, cancel := context.WithTimeout(context.Background(), cfg.Web.ShutdownTimeout)
		defer cancel()

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