package store

// Store is a small atomic JSON implementation for the standalone demo binary.
// PostgreSQL is available through OpenPostgres for durable deployments.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Store struct {
	mu    sync.RWMutex
	path  string
	state state
}
type state struct {
	NextIDs    map[string]int64   `json:"next_ids"`
	Users      map[string]string  `json:"users"`
	Policies   []Policy           `json:"policies"`
	Audits     []Audit            `json:"audits"`
	Exceptions []Exception        `json:"exceptions"`
	Feedback   map[int64]Feedback `json:"feedback"`
	Incidents  map[int64]Incident `json:"incidents"`
	Notes      []IncidentNote     `json:"incident_notes"`
	Events     []map[string]any   `json:"events"`
}
type Policy struct {
	ID      int64  `json:"id"`
	Keyword string `json:"keyword"`
	Action  string `json:"action"`
	Scope   string `json:"scope"`
	Mode    string `json:"mode"`
	// Enabled is kept in the JSON and SQL stores for compatibility with
	// pre-0.6 data. Mode is the authoritative lifecycle field.
	Enabled bool `json:"enabled"`
}
type Audit struct {
	ID             int64    `json:"id"`
	CreatedAt      string   `json:"created_at"`
	Actor          string   `json:"actor"`
	Destination    string   `json:"destination"`
	Filename       string   `json:"filename"`
	SHA256         string   `json:"sha256"`
	Size           int64    `json:"size"`
	Action         string   `json:"action"`
	Reasons        []string `json:"reasons"`
	Signals        []string `json:"signals"`
	ModelStatus    string   `json:"model_status"`
	Forwarded      bool     `json:"forwarded"`
	TransferStatus string   `json:"transfer_status"`
	UpstreamStatus *int     `json:"upstream_status,omitempty"`
}
type Exception struct {
	ID            int64  `json:"id"`
	AuditID       int64  `json:"audit_id"`
	Actor         string `json:"actor"`
	Destination   string `json:"destination"`
	SHA256        string `json:"sha256"`
	Justification string `json:"justification"`
	Status        string `json:"status"`
	CreatedAt     string `json:"created_at"`
	ExpiresAt     string `json:"expires_at,omitempty"`
}
type Feedback struct {
	AuditID   int64  `json:"audit_id"`
	Verdict   string `json:"verdict"`
	Note      string `json:"note"`
	CreatedAt string `json:"created_at"`
}
type Incident struct {
	AuditID   int64  `json:"audit_id"`
	Status    string `json:"status"`
	Assignee  string `json:"assignee"`
	UpdatedAt string `json:"updated_at"`
}
type IncidentNote struct {
	ID        int64  `json:"id"`
	AuditID   int64  `json:"audit_id"`
	Author    string `json:"author"`
	Body      string `json:"body"`
	CreatedAt string `json:"created_at"`
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, state: state{NextIDs: map[string]int64{}, Users: map[string]string{}, Feedback: map[int64]Feedback{}, Incidents: map[int64]Incident{}}}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(data, &s.state); err != nil {
			return nil, err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s.normalize()
	return s, nil
}
func (s *Store) Close() error                { return nil }
func (s *Store) Ready(context.Context) error { return nil }
func (s *Store) normalize() {
	if s.state.NextIDs == nil {
		s.state.NextIDs = map[string]int64{}
	}
	if s.state.Users == nil {
		s.state.Users = map[string]string{}
	}
	if s.state.Feedback == nil {
		s.state.Feedback = map[int64]Feedback{}
	}
	if s.state.Incidents == nil {
		s.state.Incidents = map[int64]Incident{}
	}
	if s.state.Notes == nil {
		s.state.Notes = []IncidentNote{}
	}
	if s.state.Policies == nil {
		s.state.Policies = []Policy{}
	}
	if s.state.Audits == nil {
		s.state.Audits = []Audit{}
	}
	if s.state.Exceptions == nil {
		s.state.Exceptions = []Exception{}
	}
	if s.state.Events == nil {
		s.state.Events = []map[string]any{}
	}
	for i := range s.state.Policies {
		normalizePolicy(&s.state.Policies[i])
	}
	for i := range s.state.Audits {
		if s.state.Audits[i].TransferStatus == "" {
			switch {
			case s.state.Audits[i].Forwarded:
				s.state.Audits[i].TransferStatus = "forwarded"
			case s.state.Audits[i].UpstreamStatus != nil:
				s.state.Audits[i].TransferStatus = "failed"
			default:
				s.state.Audits[i].TransferStatus = "not_requested"
			}
		}
	}
}
func (s *Store) persistLocked() error {
	s.normalize()
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".dlp-store-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, s.path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func (s *Store) nextIDLocked(kind string) int64 {
	s.state.NextIDs[kind]++
	return s.state.NextIDs[kind]
}
func (s *Store) UserStatus(actor string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if v, ok := s.state.Users[actor]; ok {
		return v, nil
	}
	return "normal", nil
}
func (s *Store) SetUserStatus(actor, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Users[actor] = status
	return s.persistLocked()
}
func (s *Store) Users(actors map[string]string) ([]map[string]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]map[string]string, 0, len(actors))
	names := make([]string, 0, len(actors))
	for actor := range actors {
		names = append(names, actor)
	}
	sort.Strings(names)
	for _, actor := range names {
		status := s.state.Users[actor]
		if status == "" {
			status = "normal"
		}
		result = append(result, map[string]string{"actor": actor, "status": status})
	}
	return result, nil
}
func (s *Store) Policies() ([]Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Policy, len(s.state.Policies))
	copy(result, s.state.Policies)
	return result, nil
}
func (s *Store) AddPolicy(p Policy) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalizePolicy(&p)
	p.ID = s.nextIDLocked("policy")
	s.state.Policies = append(s.state.Policies, p)
	return p.ID, s.persistLocked()
}
func (s *Store) UpdatePolicy(id int64, p Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalizePolicy(&p)
	for i := range s.state.Policies {
		if s.state.Policies[i].ID == id {
			p.ID = id
			s.state.Policies[i] = p
			return s.persistLocked()
		}
	}
	return errors.New("policy not found")
}

func normalizePolicy(p *Policy) {
	switch p.Mode {
	case "draft":
		p.Enabled = false
	case "monitor", "enforce":
		p.Enabled = true
	default:
		if p.Enabled {
			p.Mode = "enforce"
		} else {
			p.Mode = "draft"
		}
	}
}
func (s *Store) Approved(actor, destination, sha string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	current := time.Now().UTC()
	for _, x := range s.state.Exceptions {
		if x.Actor == actor && x.Destination == destination && x.SHA256 == sha && x.Status == "approved" {
			expires, err := time.Parse(time.RFC3339, x.ExpiresAt)
			if err == nil && expires.After(current) {
				return true, nil
			}
		}
	}
	return false, nil
}
func (s *Store) InsertAudit(a Audit) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.Reasons == nil {
		a.Reasons = []string{}
	}
	if a.Signals == nil {
		a.Signals = []string{}
	}
	if a.TransferStatus == "" {
		a.TransferStatus = "not_requested"
	}
	a.ID = s.nextIDLocked("audit")
	a.CreatedAt = now()
	s.state.Audits = append(s.state.Audits, a)
	return a.ID, s.persistLocked()
}
func (s *Store) MarkDelivery(id int64, status *int, forwarded bool, transferStatus string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Audits {
		if s.state.Audits[i].ID == id {
			s.state.Audits[i].Forwarded = forwarded
			s.state.Audits[i].UpstreamStatus = status
			s.state.Audits[i].TransferStatus = transferStatus
			return s.persistLocked()
		}
	}
	return errors.New("audit not found")
}
func (s *Store) Audits(limit int) ([]Audit, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit < 1 {
		limit = 1
	}
	if limit > 500 {
		limit = 500
	}
	start := len(s.state.Audits) - limit
	if start < 0 {
		start = 0
	}
	result := make([]Audit, len(s.state.Audits)-start)
	copy(result, s.state.Audits[start:])
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result, nil
}
func (s *Store) AuditsSince(since time.Time) ([]Audit, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Audit, 0)
	for _, audit := range s.state.Audits {
		created, err := time.Parse(time.RFC3339, audit.CreatedAt)
		if err == nil && !created.Before(since) {
			result = append(result, audit)
		}
	}
	return result, nil
}
func (s *Store) AuditByID(id int64) (Audit, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, audit := range s.state.Audits {
		if audit.ID == id {
			return audit, nil
		}
	}
	return Audit{}, errors.New("audit not found")
}
func (s *Store) AuditForActor(id int64, actor string) (Audit, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.state.Audits {
		if a.ID == id && a.Actor == actor {
			return a, nil
		}
	}
	return Audit{}, errors.New("audit not found")
}
func (s *Store) CreateException(a Audit, actor, justification string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.state.Exceptions {
		if x.AuditID == a.ID {
			return 0, errors.New("exception exists")
		}
	}
	x := Exception{ID: s.nextIDLocked("exception"), AuditID: a.ID, Actor: actor, Destination: a.Destination, SHA256: a.SHA256, Justification: justification, Status: "pending", CreatedAt: now()}
	s.state.Exceptions = append(s.state.Exceptions, x)
	return x.ID, s.persistLocked()
}
func (s *Store) Exceptions() ([]Exception, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Exception, len(s.state.Exceptions))
	copy(result, s.state.Exceptions)
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result, nil
}
func (s *Store) ApproveException(id int64, hours int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Exceptions {
		if s.state.Exceptions[i].ID == id && s.state.Exceptions[i].Status == "pending" {
			s.state.Exceptions[i].Status = "approved"
			s.state.Exceptions[i].ExpiresAt = time.Now().UTC().Add(time.Duration(hours) * time.Hour).Format(time.RFC3339)
			return s.persistLocked()
		}
	}
	return errors.New("pending exception not found")
}
func (s *Store) RejectException(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Exceptions {
		if s.state.Exceptions[i].ID == id && s.state.Exceptions[i].Status == "pending" {
			s.state.Exceptions[i].Status = "rejected"
			return s.persistLocked()
		}
	}
	return errors.New("pending exception not found")
}
func (s *Store) Feedback(auditID int64, verdict, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Feedback[auditID] = Feedback{AuditID: auditID, Verdict: verdict, Note: note, CreatedAt: now()}
	return s.persistLocked()
}
func (s *Store) Feedbacks() ([]Feedback, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Feedback, 0, len(s.state.Feedback))
	for _, f := range s.state.Feedback {
		result = append(result, f)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt > result[j].CreatedAt
	})
	return result, nil
}
func (s *Store) Incidents() ([]Incident, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Incident, 0, len(s.state.Incidents))
	for _, item := range s.state.Incidents {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UpdatedAt > result[j].UpdatedAt })
	return result, nil
}
func (s *Store) UpsertIncident(auditID int64, status, assignee string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for _, audit := range s.state.Audits {
		if audit.ID == auditID {
			found = true
			break
		}
	}
	if !found {
		return errors.New("audit not found")
	}
	s.state.Incidents[auditID] = Incident{AuditID: auditID, Status: status, Assignee: assignee, UpdatedAt: now()}
	return s.persistLocked()
}
func (s *Store) IncidentNotes(auditID int64) ([]IncidentNote, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := []IncidentNote{}
	for _, note := range s.state.Notes {
		if note.AuditID == auditID {
			result = append(result, note)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt > result[j].CreatedAt })
	return result, nil
}
func (s *Store) AddIncidentNote(auditID int64, author, body string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for _, audit := range s.state.Audits {
		if audit.ID == auditID {
			found = true
			break
		}
	}
	if !found {
		return 0, errors.New("audit not found")
	}
	note := IncidentNote{ID: s.nextIDLocked("incident_note"), AuditID: auditID, Author: author, Body: body, CreatedAt: now()}
	s.state.Notes = append(s.state.Notes, note)
	return note.ID, s.persistLocked()
}
func (s *Store) Event(event, target string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Events = append(s.state.Events, map[string]any{"id": s.nextIDLocked("event"), "created_at": now(), "event": event, "target": target})
	return s.persistLocked()
}
func (s *Store) Events() ([]map[string]any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]map[string]any, len(s.state.Events))
	copy(result, s.state.Events)
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result, nil
}
func now() string { return time.Now().UTC().Format(time.RFC3339) }
