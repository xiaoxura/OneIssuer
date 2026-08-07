// Package app assembles concrete dependencies and owns OneIssuer's startup and
// bounded shutdown lifecycle.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/oneissuer/oneissuer/internal/admin"
	"github.com/oneissuer/oneissuer/internal/audit"
	"github.com/oneissuer/oneissuer/internal/authflow"
	"github.com/oneissuer/oneissuer/internal/authn"
	"github.com/oneissuer/oneissuer/internal/authorization"
	clientdomain "github.com/oneissuer/oneissuer/internal/client"
	"github.com/oneissuer/oneissuer/internal/config"
	"github.com/oneissuer/oneissuer/internal/consent"
	"github.com/oneissuer/oneissuer/internal/httpserver"
	"github.com/oneissuer/oneissuer/internal/identity"
	"github.com/oneissuer/oneissuer/internal/keystore"
	logoutdomain "github.com/oneissuer/oneissuer/internal/logout"
	"github.com/oneissuer/oneissuer/internal/observability"
	"github.com/oneissuer/oneissuer/internal/session"
	"github.com/oneissuer/oneissuer/internal/storage/postgres"
	"github.com/oneissuer/oneissuer/internal/token"
)

const (
	startupTimeout            = 10 * time.Second
	protocolArtifactRetention = 24 * time.Hour
	refreshArtifactRetention  = 30 * 24 * time.Hour
	cleanupOperationTimeout   = 5 * time.Second
)

// ErrShutdownTimeout indicates that in-flight HTTP work exceeded the configured
// graceful-shutdown budget and had to be force-closed.
var ErrShutdownTimeout = errors.New("graceful shutdown timed out")

// Serve assembles PostgreSQL, migration checks, metrics, and HTTP in the
// documented order. No listener is opened before all startup checks pass.
func Serve(ctx context.Context, cfg config.Config, build observability.BuildInfo, logger *slog.Logger) error {
	keyStore, err := keystore.Load(cfg.OIDC.SigningKeyFile, cfg.OIDC.VerificationKeysFile)
	if err != nil {
		return fmt.Errorf("signing key store startup check: %w", err)
	}
	if logger != nil {
		logger.InfoContext(ctx, "signing key store loaded",
			slog.String("algorithm", keystore.Algorithm),
			slog.Int("published_keys", keyStore.Metadata().PublishedKeys),
		)
	}

	startupCtx, cancelStartup := context.WithTimeout(ctx, startupTimeout)
	store, err := postgres.Open(startupCtx, cfg.Database.URL.UnsafeValue(), cfg.Database.MaxConns)
	cancelStartup()
	if err != nil {
		return fmt.Errorf("database startup check: %w", err)
	}
	defer store.Close()

	migrationCtx, cancelMigrationCheck := context.WithTimeout(ctx, startupTimeout)
	err = store.CheckMigrations(migrationCtx)
	cancelMigrationCheck()
	if err != nil {
		return fmt.Errorf("database migration check: %w", err)
	}

	metrics := observability.NewMetrics(build)
	if err := metrics.RegisterDatabasePool(store.Stats); err != nil {
		return fmt.Errorf("register database metrics: %w", err)
	}
	store.SetAuditObserver(metrics)
	auditCtx, cancelStartupAudit := context.WithTimeout(ctx, startupTimeout)
	err = appendSigningKeyLoaded(auditCtx, store, time.Now().UTC())
	cancelStartupAudit()
	if err != nil {
		return fmt.Errorf("record signing key startup audit: %w", err)
	}
	identityService, err := identity.NewService(ctx, cfg.Password, nil)
	if err != nil {
		return fmt.Errorf("initialize identity service: %w", err)
	}
	tokenManager, err := session.NewTokenManager(nil, cfg.Browser.SessionTTL, cfg.Browser.SessionIdleTimeout, cfg.Browser.CSRFTTL)
	if err != nil {
		return fmt.Errorf("initialize session service: %w", err)
	}
	clientService := clientdomain.NewService(store, nil, cfg.Environment != config.EnvironmentProduction, metrics)
	authflowService, err := authflow.NewService(store, nil, cfg.Browser.AuthTransactionTTL, metrics)
	if err != nil {
		return fmt.Errorf("initialize authorization transaction service: %w", err)
	}
	consentService, err := consent.NewService(store)
	if err != nil {
		return fmt.Errorf("initialize consent service: %w", err)
	}
	authorizationService, err := authorization.NewService(store, nil, cfg.OIDC.AuthorizationCodeTTL, metrics)
	if err != nil {
		return fmt.Errorf("initialize authorization service: %w", err)
	}
	protocolTokenService, err := token.NewService(
		store, keyStore, nil, cfg.Issuer.String(), cfg.OIDC.IDTokenTTL,
		cfg.OIDC.AccessTokenTTL, cfg.OIDC.ClockSkew, metrics,
		token.WithRefreshLifetimes(cfg.Lifecycle.RefreshTokenTTL, cfg.Lifecycle.RefreshTokenAbsoluteTTL),
	)
	if err != nil {
		return fmt.Errorf("initialize token service: %w", err)
	}
	logoutService, err := logoutdomain.NewService(
		store, clientService, keyStore, cfg.Issuer.String(),
		cfg.Lifecycle.LogoutTransactionTTL, cfg.Lifecycle.LogoutIDTokenHintMaxAge,
		cfg.OIDC.ClockSkew, cfg.Lifecycle.LogoutMaxActivePerSession, nil, metrics,
	)
	if err != nil {
		return fmt.Errorf("initialize RP logout service: %w", err)
	}
	authnService := authn.NewService(store, identityService, tokenManager, authflowService, clientService, cfg.Browser.RegistrationEnabled, metrics)
	sessionService := session.NewService(store, tokenManager, metrics)
	adminService := admin.NewService(store, identityService, clientService, cfg.Browser.LoginReauthWindow)
	cookies := session.NewCookieManager(cfg.Browser.CookieName, cfg.Browser.CookieSecure, cfg.Browser.SessionTTL, cfg.Browser.CSRFTTL)
	application, err := httpserver.NewApplicationHandler(httpserver.ApplicationOptions{
		Authn: authnService, Sessions: sessionService, Admin: adminService,
		Clients: clientService, Transactions: authflowService,
		Consents: consentService, Authorization: authorizationService, Tokens: protocolTokenService,
		Logout: logoutService, LogoutCookies: logoutdomain.NewCookieManager(cfg.Browser.CookieName, cfg.Browser.CookieSecure, cfg.Lifecycle.LogoutTransactionTTL),
		Cookies: cookies, Issuer: cfg.Issuer, PublicKeys: keyStore,
		AuthRateLimit: httpserver.AuthenticationRateLimitConfig{
			PerMinute: cfg.Browser.AuthRatePerMinute, Burst: cfg.Browser.AuthRateBurst,
			GlobalPerSecond: cfg.Browser.AuthGlobalRate, GlobalBurst: cfg.Browser.AuthGlobalBurst,
		},
		OAuthRateLimit: httpserver.AuthenticationRateLimitConfig{
			PerMinute: cfg.Lifecycle.OAuthRatePerMinute, Burst: cfg.Lifecycle.OAuthRateBurst,
			GlobalPerSecond: cfg.Lifecycle.OAuthGlobalRate, GlobalBurst: cfg.Lifecycle.OAuthGlobalBurst,
		},
	})
	if err != nil {
		return fmt.Errorf("initialize application HTTP routes: %w", err)
	}
	bootstrapCtx, cancelBootstrapCheck := context.WithTimeout(ctx, startupTimeout)
	hasAdmin, adminErr := store.HasAdmin(bootstrapCtx)
	cancelBootstrapCheck()
	if adminErr != nil {
		return fmt.Errorf("check bootstrap state: %w", adminErr)
	} else if !hasAdmin && logger != nil {
		logger.Warn("OneIssuer has no administrator; self-service registration remains policy controlled")
	}
	readiness := httpserver.NewReadiness(metrics.SetReady)
	handler := httpserver.NewHandler(httpserver.HandlerOptions{
		Logger:             logger,
		Readiness:          readiness,
		Database:           store,
		DatabaseErrorClass: postgres.ErrorClass,
		Metrics:            metrics,
		Gatherer:           metrics.Gatherer(),
		TrustedProxies:     cfg.TrustedProxies,
		Application:        application,
	})
	server := httpserver.NewServer(httpserver.ServerConfig{
		Addr:              cfg.HTTP.Addr,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
		MaxHeaderBytes:    cfg.HTTP.MaxHeaderBytes,
	}, handler, logger)

	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.HTTP.Addr)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("listen on configured HTTP address: %w", err)
	}

	if logger != nil {
		logger.InfoContext(ctx, "OneIssuer HTTP server starting",
			slog.String("address", cfg.HTTP.Addr),
			slog.String("issuer", cfg.Issuer.String()),
		)
	}
	cleanupCtx, cancelCleanup := context.WithCancel(ctx)
	cleanupDone := startCleanupLoop(cleanupCtx, cfg.Browser.CleanupInterval, store, sessionService, authflowService, metrics, logger)
	serveErr := superviseHTTP(ctx, server, listener, readiness, cfg.ShutdownTimeout, logger)
	cancelCleanup()
	<-cleanupDone
	return serveErr
}

type startupAuditStore interface {
	AppendAudit(context.Context, audit.Event) error
}

func appendSigningKeyLoaded(ctx context.Context, store startupAuditStore, now time.Time) error {
	event, err := audit.New(audit.SigningKeyLoaded, audit.ResultSuccess, nil, "", nil, "", nil, now)
	if err != nil {
		return err
	}
	return store.AppendAudit(ctx, event)
}

type cleanupStore interface {
	CountActiveSessions(context.Context, time.Time) (int64, error)
	CleanupProtocolArtifacts(context.Context, time.Time) (int64, error)
	CleanupRefreshArtifacts(context.Context, time.Time) (int64, error)
	CleanupLogoutTransactions(context.Context, time.Time, time.Time) (int64, error)
}

func startCleanupLoop(
	ctx context.Context,
	interval time.Duration,
	store cleanupStore,
	sessions *session.Service,
	transactions *authflow.Service,
	metrics *observability.Metrics,
	logger *slog.Logger,
) <-chan struct{} {
	done := make(chan struct{})
	run := func() {
		now := time.Now().UTC()
		runCleanupOperation(ctx, cleanupOperationTimeout, "sessions", metrics, logger, "session cleanup failed", func(operationCtx context.Context) (int64, error) {
			return sessions.Cleanup(operationCtx, now)
		})
		runCleanupOperation(ctx, cleanupOperationTimeout, "auth_transactions", metrics, logger, "authorization transaction cleanup failed", func(operationCtx context.Context) (int64, error) {
			return transactions.Cleanup(operationCtx, now)
		})
		runCleanupOperation(ctx, cleanupOperationTimeout, "protocol_artifacts", metrics, logger, "OIDC protocol metadata cleanup failed", func(operationCtx context.Context) (int64, error) {
			return store.CleanupProtocolArtifacts(operationCtx, now.Add(-protocolArtifactRetention))
		})
		runCleanupOperation(ctx, cleanupOperationTimeout, "refresh_artifacts", metrics, logger, "Refresh lifecycle metadata cleanup failed", func(operationCtx context.Context) (int64, error) {
			return store.CleanupRefreshArtifacts(operationCtx, now.Add(-refreshArtifactRetention))
		})
		runCleanupOperation(ctx, cleanupOperationTimeout, "logout_transactions", metrics, logger, "RP logout transaction cleanup failed", func(operationCtx context.Context) (int64, error) {
			return store.CleanupLogoutTransactions(operationCtx, now, now.Add(-protocolArtifactRetention))
		})
		runCleanupOperation(ctx, cleanupOperationTimeout, "active_sessions", metrics, logger, "active session count failed", func(operationCtx context.Context) (int64, error) {
			count, err := store.CountActiveSessions(operationCtx, now)
			if err == nil && metrics != nil {
				metrics.SetActiveSessions(count)
			}
			return 0, err
		})
	}
	go func() {
		defer close(done)
		run()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	}()
	return done
}

func runCleanupOperation(
	ctx context.Context,
	timeout time.Duration,
	operation string,
	metrics *observability.Metrics,
	logger *slog.Logger,
	message string,
	run func(context.Context) (int64, error),
) {
	started := time.Now()
	operationCtx, cancel := context.WithTimeout(ctx, timeout)
	rows, err := run(operationCtx)
	cancel()
	result := "success"
	if err != nil {
		result = "failure"
		if errors.Is(err, context.Canceled) && ctx.Err() != nil {
			result = "canceled"
		}
	}
	if metrics != nil {
		metrics.Cleanup(operation, result, rows, time.Since(started))
	}
	if err != nil && result != "canceled" && logger != nil {
		logger.Warn(message, slog.String("error_class", postgres.ErrorClass(err)))
	}
}

type managedHTTPServer interface {
	Serve(net.Listener) error
	Shutdown(context.Context) error
	Close() error
}

func superviseHTTP(
	ctx context.Context,
	server managedHTTPServer,
	listener net.Listener,
	readiness *httpserver.Readiness,
	shutdownTimeout time.Duration,
	logger *slog.Logger,
) error {
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- server.Serve(listener)
	}()
	readiness.Set(true)

	select {
	case serveErr := <-serveErrors:
		readiness.Set(false)
		if serveErr == nil || errors.Is(serveErr, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("HTTP server stopped unexpectedly: %w", serveErr)
	case <-ctx.Done():
		readiness.Set(false)
		if logger != nil {
			logger.Info("shutdown signal received; readiness disabled")
		}
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	shutdownErr := server.Shutdown(shutdownCtx)
	cancelShutdown()
	if shutdownErr != nil {
		_ = server.Close()
		<-serveErrors
		if errors.Is(shutdownErr, context.DeadlineExceeded) {
			if logger != nil {
				logger.Error("graceful shutdown deadline exceeded",
					slog.String("timeout", shutdownTimeout.String()),
				)
			}
			return ErrShutdownTimeout
		}
		return fmt.Errorf("graceful HTTP shutdown: %w", shutdownErr)
	}

	serveErr := <-serveErrors
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("HTTP server shutdown: %w", serveErr)
	}
	if logger != nil {
		logger.Info("graceful shutdown complete")
	}
	return nil
}
