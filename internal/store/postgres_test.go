package store

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestPostgresRepositoryWorkflow(t *testing.T) {
	databaseURL := os.Getenv("DLP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DLP_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	repository, err := OpenPostgres(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	if _, err := repository.pool.Exec(ctx, "TRUNCATE incident_notes,incidents,admin_events,feedback,exceptions,audits,policies,user_statuses RESTART IDENTITY CASCADE"); err != nil {
		t.Fatal(err)
	}

	if err := repository.SetUserStatus("synthetic-user", "privileged"); err != nil {
		t.Fatal(err)
	}
	status, err := repository.UserStatus("synthetic-user")
	if err != nil || status != "privileged" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	policyID, err := repository.AddPolicy(Policy{Keyword: "synthetic canary", Action: "review", Scope: "external", Enabled: true})
	if err != nil || policyID != 1 {
		t.Fatalf("policy id=%d err=%v", policyID, err)
	}
	auditID, err := repository.InsertAudit(Audit{Actor: "synthetic-user", Destination: "external", Filename: "synthetic.txt", SHA256: "abc", Size: 12, Action: "review", Reasons: []string{"policy_1"}, Signals: []string{}, ModelStatus: "disabled"})
	if err != nil || auditID != 1 {
		t.Fatalf("audit id=%d err=%v", auditID, err)
	}
	audit, err := repository.AuditForActor(auditID, "synthetic-user")
	if err != nil || audit.TransferStatus != "not_requested" {
		t.Fatalf("audit=%v err=%v", audit, err)
	}
	exceptionID, err := repository.CreateException(audit, "synthetic-user", "synthetic business requirement")
	if err != nil || exceptionID != 1 {
		t.Fatalf("exception id=%d err=%v", exceptionID, err)
	}
	if err := repository.ApproveException(exceptionID, 1); err != nil {
		t.Fatal(err)
	}
	approved, err := repository.Approved("synthetic-user", "external", "abc")
	if err != nil || !approved {
		t.Fatalf("approved=%v err=%v", approved, err)
	}
	if err := repository.Feedback(auditID, "false_positive", "synthetic review"); err != nil {
		t.Fatal(err)
	}
	if err := repository.UpsertIncident(auditID, "investigating", "synthetic-analyst"); err != nil {
		t.Fatal(err)
	}
	if noteID, err := repository.AddIncidentNote(auditID, "synthetic-analyst", "synthetic investigation note"); err != nil || noteID != 1 {
		t.Fatalf("note id=%d err=%v", noteID, err)
	}
	if incidents, err := repository.Incidents(); err != nil || len(incidents) != 1 || incidents[0].Status != "investigating" {
		t.Fatalf("incidents=%v err=%v", incidents, err)
	}
	if notes, err := repository.IncidentNotes(auditID); err != nil || len(notes) != 1 || notes[0].Author != "synthetic-analyst" {
		t.Fatalf("notes=%v err=%v", notes, err)
	}
	if err := repository.Event("test_event", "synthetic-target"); err != nil {
		t.Fatal(err)
	}
	if audits, err := repository.AuditsSince(time.Now().Add(-time.Hour)); err != nil || len(audits) != 1 {
		t.Fatalf("audits=%v err=%v", audits, err)
	}
	if events, err := repository.Events(); err != nil || len(events) != 1 {
		t.Fatalf("events=%v err=%v", events, err)
	}
}
