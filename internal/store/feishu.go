package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// FeishuEvent is a minimal projection of a Feishu behavior-audit record.
// File contents, titles, IP addresses, and full provider payloads are not stored.
type FeishuEvent struct {
	UniqueID      string `json:"unique_id"`
	EventTime     string `json:"event_time"`
	EventName     string `json:"event_name"`
	EventModule   int    `json:"event_module"`
	OperatorType  int    `json:"operator_type"`
	OperatorValue string `json:"operator_value"`
	ObjectType    string `json:"object_type"`
	ObjectValue   string `json:"object_value"`
}

type FeishuSyncStatus struct {
	LastEnd       string `json:"last_end,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
	ImportedTotal int64  `json:"imported_total"`
}

func (s *Store) FeishuEvents(int) ([]FeishuEvent, error) {
	return []FeishuEvent{}, nil
}

func (s *Store) FeishuSyncStatus() (FeishuSyncStatus, error) {
	return FeishuSyncStatus{}, nil
}

func (s *Store) SaveFeishuEvents(context.Context, []FeishuEvent, time.Time) (int64, error) {
	return 0, errors.New("Feishu audit sync requires PostgreSQL")
}

func (p *Postgres) FeishuEvents(limit int) ([]FeishuEvent, error) {
	if limit < 1 {
		limit = 1
	}
	if limit > 200 {
		limit = 200
	}
	ctx, cancel := dbContext()
	defer cancel()
	rows, err := p.pool.Query(ctx, "SELECT unique_id,event_time,event_name,event_module,operator_type,operator_value,object_type,object_value FROM feishu_audit_events ORDER BY event_time DESC,unique_id DESC LIMIT $1", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []FeishuEvent{}
	for rows.Next() {
		var item FeishuEvent
		var eventTime time.Time
		if err := rows.Scan(&item.UniqueID, &eventTime, &item.EventName, &item.EventModule, &item.OperatorType, &item.OperatorValue, &item.ObjectType, &item.ObjectValue); err != nil {
			return nil, err
		}
		item.EventTime = eventTime.UTC().Format(time.RFC3339)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (p *Postgres) FeishuSyncStatus() (FeishuSyncStatus, error) {
	ctx, cancel := dbContext()
	defer cancel()
	result := FeishuSyncStatus{}
	var lastEnd, updatedAt time.Time
	err := p.pool.QueryRow(ctx, "SELECT last_end,updated_at FROM feishu_sync_state WHERE source='behavior_audit'").Scan(&lastEnd, &updatedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if err == nil {
		result.LastEnd = lastEnd.UTC().Format(time.RFC3339)
		result.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
	}
	if err := p.pool.QueryRow(ctx, "SELECT count(*) FROM feishu_audit_events").Scan(&result.ImportedTotal); err != nil {
		return FeishuSyncStatus{}, err
	}
	return result, nil
}

// SaveFeishuEvents commits projected events and the completed window cursor
// together. Repeated windows are safe because unique_id is idempotent.
func (p *Postgres) SaveFeishuEvents(ctx context.Context, items []FeishuEvent, windowEnd time.Time) (int64, error) {
	if windowEnd.IsZero() {
		return 0, errors.New("window end is required")
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var inserted int64
	for _, item := range items {
		eventTime, err := time.Parse(time.RFC3339, item.EventTime)
		if err != nil || item.UniqueID == "" || item.EventName == "" {
			return 0, errors.New("invalid Feishu audit event")
		}
		tag, err := tx.Exec(ctx, "INSERT INTO feishu_audit_events(unique_id,event_time,event_name,event_module,operator_type,operator_value,object_type,object_value) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(unique_id) DO NOTHING", item.UniqueID, eventTime, item.EventName, item.EventModule, item.OperatorType, item.OperatorValue, item.ObjectType, item.ObjectValue)
		if err != nil {
			return 0, err
		}
		inserted += tag.RowsAffected()
	}
	_, err = tx.Exec(ctx, "INSERT INTO feishu_sync_state(source,last_end) VALUES('behavior_audit',$1) ON CONFLICT(source) DO UPDATE SET last_end=GREATEST(feishu_sync_state.last_end,excluded.last_end),updated_at=now()", windowEnd)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return inserted, nil
}
