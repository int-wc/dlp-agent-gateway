package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/int-wc/dlp-agent-gateway/internal/access"
	"github.com/int-wc/dlp-agent-gateway/internal/config"
	"github.com/int-wc/dlp-agent-gateway/internal/httpapi"
	"github.com/int-wc/dlp-agent-gateway/internal/policy"
	"github.com/int-wc/dlp-agent-gateway/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(2)
	}
	if err := cfg.EnsureDBDir(); err != nil {
		logger.Error("create database directory", "error", err)
		os.Exit(2)
	}
	startup, cancelStartup := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelStartup()
	var repository store.Repository
	if cfg.DatabaseURL != "" {
		repository, err = store.OpenPostgres(startup, cfg.DatabaseURL)
	} else {
		repository, err = store.Open(cfg.DBPath)
	}
	if err != nil {
		logger.Error("open database", "backend", cfg.StorageBackend(), "error", err)
		os.Exit(2)
	}
	defer repository.Close()
	identity, err := access.New(startup, access.Options{
		IssuerURL: cfg.OIDCIssuerURL, ClientID: cfg.OIDCClientID, Secret: cfg.OIDCSecret,
		RedirectURL: cfg.OIDCRedirect, RoleClaim: cfg.OIDCRoleClaim,
		AdminRole: cfg.OIDCAdminRole, OperatorRole: cfg.OIDCOperatorRole, ViewerRole: cfg.OIDCViewerRole,
		SessionSecret: cfg.SessionSecret, CookieSecure: cfg.CookieSecure,
	})
	if err != nil {
		logger.Error("configure OIDC", "error", err)
		os.Exit(2)
	}
	engine := policy.New(cfg)
	handler, err := httpapi.New(cfg, repository, engine, identity)
	if err != nil {
		logger.Error("configure HTTP API", "error", err)
		os.Exit(2)
	}
	server := &http.Server{Addr: cfg.ListenAddress, Handler: handler.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	if cfg.TLSCertFile != "" {
		server.TLSConfig, err = access.ServerTLSConfig(cfg)
		if err != nil {
			logger.Error("configure TLS", "error", err)
			os.Exit(2)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		logger.Info("gateway listening", "address", cfg.ListenAddress, "analyzer", cfg.AnalyzerURL != "", "storage", cfg.StorageBackend(), "oidc", cfg.OIDCEnabled(), "tls", cfg.TLSCertFile != "")
		var serveErr error
		if cfg.TLSCertFile != "" {
			serveErr = server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			serveErr = server.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			logger.Error("server stopped", "error", serveErr)
			stop()
		}
	}()
	<-ctx.Done()
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
}
