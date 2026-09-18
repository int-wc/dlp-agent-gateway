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
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		logger.Error("open database", "error", err)
		os.Exit(2)
	}
	defer db.Close()
	engine := policy.New(cfg)
	server := &http.Server{Addr: cfg.ListenAddress, Handler: httpapi.New(cfg, db, engine).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		logger.Info("gateway listening", "address", cfg.ListenAddress, "analyzer", cfg.AnalyzerURL != "")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "error", err)
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
