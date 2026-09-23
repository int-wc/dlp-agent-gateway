package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/int-wc/dlp-agent-gateway/internal/feishu"
	"github.com/int-wc/dlp-agent-gateway/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("Feishu behavior-audit sync failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	databaseURL := os.Getenv("DLP_DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DLP_DATABASE_URL is required")
	}
	client, err := feishu.New(os.Getenv("DLP_FEISHU_APP_ID"), os.Getenv("DLP_FEISHU_APP_SECRET"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	repository, err := store.OpenPostgres(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer repository.Close()
	status, err := repository.FeishuSyncStatus()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	end := now.Add(-time.Minute).Truncate(time.Second)
	start := end.Add(-time.Hour)
	if status.LastEnd != "" {
		lastEnd, err := time.Parse(time.RFC3339, status.LastEnd)
		if err != nil {
			return err
		}
		start = lastEnd.Add(-2 * time.Minute)
	}
	if !start.Before(end) {
		logger.Info("Feishu behavior-audit sync has no completed window")
		return nil
	}
	if start.Before(now.Add(-180 * 24 * time.Hour)) {
		return errors.New("Feishu audit cursor exceeds provider 180-day retention; manual gap review required")
	}
	if end.Sub(start) > 24*time.Hour {
		end = start.Add(24 * time.Hour)
	}
	items, pages, err := client.Fetch(ctx, start, end)
	if err != nil {
		return err
	}
	inserted, err := repository.SaveFeishuEvents(ctx, items, end)
	if err != nil {
		return err
	}
	logger.Info("Feishu behavior-audit sync completed", "window_start", start.Format(time.RFC3339), "window_end", end.Format(time.RFC3339), "pages", pages, "selected_events", len(items), "inserted_events", inserted)
	return nil
}
