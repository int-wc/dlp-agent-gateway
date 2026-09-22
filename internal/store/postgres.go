package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type Postgres struct {
	pool *pgxpool.Pool
}

func OpenPostgres(ctx context.Context, databaseURL string) (*Postgres, error) {
	if databaseURL == "" {
		return nil, errors.New("database URL is required")
	}
	migrationDB, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}
	defer migrationDB.Close()
	goose.SetBaseFS(migrationFS)
	if err := goose.SetDialect("postgres"); err != nil {
		return nil, err
	}
	if err := goose.UpContext(ctx, migrationDB, "migrations"); err != nil {
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Close() error {
	p.pool.Close()
	return nil
}

func (p *Postgres) Ready(ctx context.Context) error { return p.pool.Ping(ctx) }

func dbContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

func (p *Postgres) UserStatus(actor string) (string, error) {
	ctx, cancel := dbContext()
	defer cancel()
	var status string
	if err := p.pool.QueryRow(ctx, "SELECT status FROM user_statuses WHERE actor=$1", actor).Scan(&status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "normal", nil
		}
		return "", err
	}
	return status, nil
}

func (p *Postgres) SetUserStatus(actor, status string) error {
	ctx, cancel := dbContext()
	defer cancel()
	_, err := p.pool.Exec(ctx, "INSERT INTO user_statuses(actor,status) VALUES($1,$2) ON CONFLICT(actor) DO UPDATE SET status=excluded.status, updated_at=now()", actor, status)
	return err
}

func (p *Postgres) Users(actors map[string]string) ([]map[string]string, error) {
	ctx, cancel := dbContext()
	defer cancel()
	statuses := map[string]string{}
	rows, err := p.pool.Query(ctx, "SELECT actor,status FROM user_statuses")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var actor, status string
		if err := rows.Scan(&actor, &status); err != nil {
			return nil, err
		}
		statuses[actor] = status
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return usersFromStatuses(actors, statuses), nil
}

func usersFromStatuses(actors map[string]string, statuses map[string]string) []map[string]string {
	names := make([]string, 0, len(actors))
	for actor := range actors {
		names = append(names, actor)
	}
	sortStrings(names)
	result := make([]map[string]string, 0, len(names))
	for _, actor := range names {
		status := statuses[actor]
		if status == "" {
			status = "normal"
		}
		result = append(result, map[string]string{"actor": actor, "status": status})
	}
	return result
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func (p *Postgres) Policies() ([]Policy, error) {
	ctx, cancel := dbContext()
	defer cancel()
	rows, err := p.pool.Query(ctx, "SELECT id,keyword,action,scope,mode,enabled FROM policies ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Policy{}
	for rows.Next() {
		var item Policy
		if err := rows.Scan(&item.ID, &item.Keyword, &item.Action, &item.Scope, &item.Mode, &item.Enabled); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (p *Postgres) AddPolicy(item Policy) (int64, error) {
	ctx, cancel := dbContext()
	defer cancel()
	normalizePolicy(&item)
	var id int64
	err := p.pool.QueryRow(ctx, "INSERT INTO policies(keyword,action,scope,mode,enabled) VALUES($1,$2,$3,$4,$5) RETURNING id", item.Keyword, item.Action, item.Scope, item.Mode, item.Enabled).Scan(&id)
	return id, err
}

func (p *Postgres) UpdatePolicy(id int64, item Policy) error {
	ctx, cancel := dbContext()
	defer cancel()
	normalizePolicy(&item)
	result, err := p.pool.Exec(ctx, "UPDATE policies SET keyword=$2,action=$3,scope=$4,mode=$5,enabled=$6,updated_at=now() WHERE id=$1", id, item.Keyword, item.Action, item.Scope, item.Mode, item.Enabled)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return errors.New("policy not found")
	}
	return nil
}

func (p *Postgres) Approved(actor, destination, sha string) (bool, error) {
	ctx, cancel := dbContext()
	defer cancel()
	var approved bool
	err := p.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM exceptions WHERE actor=$1 AND destination=$2 AND sha256=$3 AND status='approved' AND expires_at>now())", actor, destination, sha).Scan(&approved)
	return approved, err
}

func (p *Postgres) InsertAudit(item Audit) (int64, error) {
	ctx, cancel := dbContext()
	defer cancel()
	if item.Reasons == nil {
		item.Reasons = []string{}
	}
	if item.Signals == nil {
		item.Signals = []string{}
	}
	if item.TransferStatus == "" {
		item.TransferStatus = "not_requested"
	}
	var id int64
	err := p.pool.QueryRow(ctx, "INSERT INTO audits(actor,destination,filename,sha256,size_bytes,action,reasons,signals,model_status,forwarded,transfer_status,upstream_status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id", item.Actor, item.Destination, item.Filename, item.SHA256, item.Size, item.Action, item.Reasons, item.Signals, item.ModelStatus, item.Forwarded, item.TransferStatus, item.UpstreamStatus).Scan(&id)
	return id, err
}

func (p *Postgres) MarkDelivery(id int64, status *int, forwarded bool, transferStatus string) error {
	ctx, cancel := dbContext()
	defer cancel()
	result, err := p.pool.Exec(ctx, "UPDATE audits SET upstream_status=$2,forwarded=$3,transfer_status=$4 WHERE id=$1", id, status, forwarded, transferStatus)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return errors.New("audit not found")
	}
	return nil
}

type auditScanner interface {
	Scan(...any) error
}

func scanAudit(row auditScanner) (Audit, error) {
	var item Audit
	var created time.Time
	err := row.Scan(&item.ID, &created, &item.Actor, &item.Destination, &item.Filename, &item.SHA256, &item.Size, &item.Action, &item.Reasons, &item.Signals, &item.ModelStatus, &item.Forwarded, &item.TransferStatus, &item.UpstreamStatus)
	item.CreatedAt = created.UTC().Format(time.RFC3339)
	return item, err
}

const auditColumns = "id,created_at,actor,destination,filename,sha256,size_bytes,action,reasons,signals,model_status,forwarded,transfer_status,upstream_status"

func (p *Postgres) Audits(limit int) ([]Audit, error) {
	if limit < 1 {
		limit = 1
	}
	if limit > 500 {
		limit = 500
	}
	ctx, cancel := dbContext()
	defer cancel()
	rows, err := p.pool.Query(ctx, "SELECT "+auditColumns+" FROM audits ORDER BY id DESC LIMIT $1", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectAudits(rows)
}

func collectAudits(rows pgx.Rows) ([]Audit, error) {
	result := []Audit{}
	for rows.Next() {
		item, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (p *Postgres) AuditsSince(since time.Time) ([]Audit, error) {
	ctx, cancel := dbContext()
	defer cancel()
	rows, err := p.pool.Query(ctx, "SELECT "+auditColumns+" FROM audits WHERE created_at >= $1 ORDER BY id", since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectAudits(rows)
}

func (p *Postgres) AuditByID(id int64) (Audit, error) {
	ctx, cancel := dbContext()
	defer cancel()
	return scanAudit(p.pool.QueryRow(ctx, "SELECT "+auditColumns+" FROM audits WHERE id=$1", id))
}

func (p *Postgres) AuditForActor(id int64, actor string) (Audit, error) {
	ctx, cancel := dbContext()
	defer cancel()
	return scanAudit(p.pool.QueryRow(ctx, "SELECT "+auditColumns+" FROM audits WHERE id=$1 AND actor=$2", id, actor))
}

func (p *Postgres) CreateException(audit Audit, actor, justification string) (int64, error) {
	ctx, cancel := dbContext()
	defer cancel()
	var id int64
	err := p.pool.QueryRow(ctx, "INSERT INTO exceptions(audit_id,actor,destination,sha256,justification,status) VALUES($1,$2,$3,$4,$5,'pending') RETURNING id", audit.ID, actor, audit.Destination, audit.SHA256, justification).Scan(&id)
	return id, err
}

func (p *Postgres) Exceptions() ([]Exception, error) {
	ctx, cancel := dbContext()
	defer cancel()
	rows, err := p.pool.Query(ctx, "SELECT id,audit_id,actor,destination,sha256,justification,status,created_at,expires_at FROM exceptions ORDER BY id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Exception{}
	for rows.Next() {
		var item Exception
		var created time.Time
		var expires *time.Time
		if err := rows.Scan(&item.ID, &item.AuditID, &item.Actor, &item.Destination, &item.SHA256, &item.Justification, &item.Status, &created, &expires); err != nil {
			return nil, err
		}
		item.CreatedAt = created.UTC().Format(time.RFC3339)
		if expires != nil {
			item.ExpiresAt = expires.UTC().Format(time.RFC3339)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (p *Postgres) ApproveException(id int64, hours int) error {
	ctx, cancel := dbContext()
	defer cancel()
	result, err := p.pool.Exec(ctx, "UPDATE exceptions SET status='approved',expires_at=now()+($2 * interval '1 hour') WHERE id=$1 AND status='pending'", id, hours)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return errors.New("pending exception not found")
	}
	return nil
}

func (p *Postgres) RejectException(id int64) error {
	ctx, cancel := dbContext()
	defer cancel()
	result, err := p.pool.Exec(ctx, "UPDATE exceptions SET status='rejected',expires_at=NULL WHERE id=$1 AND status='pending'", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return errors.New("pending exception not found")
	}
	return nil
}

func (p *Postgres) Feedback(auditID int64, verdict, note string) error {
	ctx, cancel := dbContext()
	defer cancel()
	_, err := p.pool.Exec(ctx, "INSERT INTO feedback(audit_id,verdict,note) VALUES($1,$2,$3) ON CONFLICT(audit_id) DO UPDATE SET verdict=excluded.verdict,note=excluded.note,created_at=now()", auditID, verdict, note)
	return err
}

func (p *Postgres) Feedbacks() ([]Feedback, error) {
	ctx, cancel := dbContext()
	defer cancel()
	rows, err := p.pool.Query(ctx, "SELECT audit_id,verdict,note,created_at FROM feedback ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Feedback{}
	for rows.Next() {
		var item Feedback
		var created time.Time
		if err := rows.Scan(&item.AuditID, &item.Verdict, &item.Note, &created); err != nil {
			return nil, err
		}
		item.CreatedAt = created.UTC().Format(time.RFC3339)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (p *Postgres) Incidents() ([]Incident, error) {
	ctx, cancel := dbContext()
	defer cancel()
	rows, err := p.pool.Query(ctx, "SELECT audit_id,status,assignee,updated_at FROM incidents ORDER BY updated_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Incident{}
	for rows.Next() {
		var item Incident
		var updated time.Time
		if err := rows.Scan(&item.AuditID, &item.Status, &item.Assignee, &updated); err != nil {
			return nil, err
		}
		item.UpdatedAt = updated.UTC().Format(time.RFC3339)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (p *Postgres) UpsertIncident(auditID int64, status, assignee string) error {
	ctx, cancel := dbContext()
	defer cancel()
	_, err := p.pool.Exec(ctx, `
		INSERT INTO incidents(audit_id,status,assignee) VALUES($1,$2,$3)
		ON CONFLICT(audit_id) DO UPDATE SET status=excluded.status,assignee=excluded.assignee,updated_at=now()
	`, auditID, status, assignee)
	return err
}

func (p *Postgres) IncidentNotes(auditID int64) ([]IncidentNote, error) {
	ctx, cancel := dbContext()
	defer cancel()
	rows, err := p.pool.Query(ctx, "SELECT id,audit_id,author,body,created_at FROM incident_notes WHERE audit_id=$1 ORDER BY created_at DESC", auditID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []IncidentNote{}
	for rows.Next() {
		var item IncidentNote
		var created time.Time
		if err := rows.Scan(&item.ID, &item.AuditID, &item.Author, &item.Body, &created); err != nil {
			return nil, err
		}
		item.CreatedAt = created.UTC().Format(time.RFC3339)
		result = append(result, item)
	}
	return result, rows.Err()
}

func (p *Postgres) AddIncidentNote(auditID int64, author, body string) (int64, error) {
	ctx, cancel := dbContext()
	defer cancel()
	var id int64
	err := p.pool.QueryRow(ctx, "INSERT INTO incident_notes(audit_id,author,body) VALUES($1,$2,$3) RETURNING id", auditID, author, body).Scan(&id)
	return id, err
}

func (p *Postgres) Event(event, target string) error {
	ctx, cancel := dbContext()
	defer cancel()
	_, err := p.pool.Exec(ctx, "INSERT INTO admin_events(event,target) VALUES($1,$2)", event, target)
	return err
}

func (p *Postgres) Events() ([]map[string]any, error) {
	ctx, cancel := dbContext()
	defer cancel()
	rows, err := p.pool.Query(ctx, "SELECT id,created_at,event,target FROM admin_events ORDER BY id DESC LIMIT 500")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []map[string]any{}
	for rows.Next() {
		var id int64
		var created time.Time
		var event, target string
		if err := rows.Scan(&id, &created, &event, &target); err != nil {
			return nil, err
		}
		result = append(result, map[string]any{"id": id, "created_at": created.UTC().Format(time.RFC3339), "event": event, "target": target})
	}
	return result, rows.Err()
}
