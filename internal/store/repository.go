package store

import (
	"context"
	"time"
)

// Repository is the persistence boundary used by the policy and HTTP layers.
// The JSON implementation remains useful for a zero-dependency demo, while
// PostgreSQL is the durable multi-process implementation.
type Repository interface {
	Close() error
	Ready(context.Context) error
	UserStatus(actor string) (string, error)
	SetUserStatus(actor, status string) error
	Users(actors map[string]string) ([]map[string]string, error)
	Policies() ([]Policy, error)
	AddPolicy(Policy) (int64, error)
	UpdatePolicy(int64, Policy) error
	Approved(actor, destination, sha string) (bool, error)
	InsertAudit(Audit) (int64, error)
	MarkDelivery(id int64, upstreamStatus *int, forwarded bool, transferStatus string) error
	Audits(limit int) ([]Audit, error)
	AuditsSince(time.Time) ([]Audit, error)
	AuditByID(int64) (Audit, error)
	AuditForActor(id int64, actor string) (Audit, error)
	CreateException(Audit, string, string) (int64, error)
	Exceptions() ([]Exception, error)
	ApproveException(id int64, hours int) error
	RejectException(id int64) error
	Feedback(auditID int64, verdict, note string) error
	Feedbacks() ([]Feedback, error)
	Incidents() ([]Incident, error)
	UpsertIncident(auditID int64, status, assignee string) error
	IncidentNotes(auditID int64) ([]IncidentNote, error)
	AddIncidentNote(auditID int64, author, body string) (int64, error)
	Event(event, target string) error
	Events() ([]map[string]any, error)
}
