package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/int-wc/dlp-agent-gateway/internal/access"
	"github.com/int-wc/dlp-agent-gateway/internal/config"
	"github.com/int-wc/dlp-agent-gateway/internal/connector"
	"github.com/int-wc/dlp-agent-gateway/internal/policy"
	"github.com/int-wc/dlp-agent-gateway/internal/store"
	"github.com/int-wc/dlp-agent-gateway/internal/webui"
)

type Server struct {
	cfg       config.Config
	store     store.Repository
	engine    *policy.Engine
	access    *access.Manager
	rbac      *access.RBAC
	connector *connector.Connector
	mux       *http.ServeMux
}
type writerContextKey struct{}

func New(cfg config.Config, repository store.Repository, engine *policy.Engine, manager ...*access.Manager) (*Server, error) {
	outbound, err := connector.New(cfg.Destinations)
	if err != nil {
		return nil, err
	}
	rbac, err := access.NewRBAC()
	if err != nil {
		return nil, err
	}
	var identityManager *access.Manager
	if len(manager) > 0 {
		identityManager = manager[0]
	}
	srv := &Server{cfg: cfg, store: repository, engine: engine, access: identityManager, rbac: rbac, connector: outbound, mux: http.NewServeMux()}
	srv.routes()
	return srv, nil
}
func (s *Server) Handler() http.Handler {
	return securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), writerContextKey{}, w)
		s.mux.ServeHTTP(w, r.WithContext(ctx))
	}))
}
func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", s.health)
	s.mux.HandleFunc("GET /ready", s.ready)
	s.mux.HandleFunc("GET /auth/login", s.login)
	s.mux.HandleFunc("GET /auth/callback", s.callback)
	s.mux.HandleFunc("POST /auth/logout", s.logout)
	s.mux.HandleFunc("GET /v1/auth/session", s.authSession)
	s.mux.HandleFunc("GET /console", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/console/", http.StatusMovedPermanently)
	})
	s.mux.Handle("GET /console/", webui.Handler())
	s.mux.HandleFunc("GET /v1/destinations", s.destinations)
	s.mux.HandleFunc("POST /v1/check/{destination}", s.check)
	s.mux.HandleFunc("POST /v1/forward/{destination}", s.forward)
	s.mux.HandleFunc("POST /v1/exceptions", s.requestException)
	s.mux.HandleFunc("GET /v1/admin/audits", s.adminAudits)
	s.mux.HandleFunc("GET /v1/admin/audits/query", s.queryAudits)
	s.mux.HandleFunc("GET /v1/admin/audits/export", s.exportAudits)
	s.mux.HandleFunc("GET /v1/admin/policies", s.adminPolicies)
	s.mux.HandleFunc("POST /v1/admin/policies", s.addPolicy)
	s.mux.HandleFunc("PUT /v1/admin/policies/{id}", s.updatePolicy)
	s.mux.HandleFunc("GET /v1/admin/users", s.adminUsers)
	s.mux.HandleFunc("PUT /v1/admin/users/{actor}", s.updateUser)
	s.mux.HandleFunc("GET /v1/admin/exceptions", s.adminExceptions)
	s.mux.HandleFunc("POST /v1/admin/exceptions/{id}/approve", s.approveException)
	s.mux.HandleFunc("POST /v1/admin/exceptions/{id}/reject", s.rejectException)
	s.mux.HandleFunc("GET /v1/admin/feedback", s.adminFeedback)
	s.mux.HandleFunc("GET /v1/admin/incidents", s.adminIncidents)
	s.mux.HandleFunc("PUT /v1/admin/incidents/{id}", s.updateIncident)
	s.mux.HandleFunc("GET /v1/admin/incidents/{id}/notes", s.incidentNotes)
	s.mux.HandleFunc("POST /v1/admin/incidents/{id}/notes", s.addIncidentNote)
	s.mux.HandleFunc("PUT /v1/admin/audits/{id}/feedback", s.feedback)
	s.mux.HandleFunc("GET /v1/admin/report", s.report)
	s.mux.HandleFunc("GET /v1/admin/events", s.events)
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"status": "ok", "version": "0.7.0", "analyzer_enabled": s.cfg.AnalyzerURL != "", "model_enabled": s.cfg.OllamaModel != "",
		"storage": s.cfg.StorageBackend(), "oidc_enabled": s.cfg.OIDCEnabled(), "mtls_required": s.cfg.RequireMTLS,
	})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ready(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "degraded", "database": "unavailable"})
		return
	}
	if s.cfg.AnalyzerURL == "" {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "database": "ready", "analyzer": "disabled"})
		return
	}
	if !s.engine.AnalyzerReady(ctx) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "degraded", "database": "ready", "analyzer": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "database": "ready", "analyzer": "ready"})
}
func (s *Server) destinations(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.clientActor(w, r); !ok {
		return
	}
	result := map[string]any{}
	for name, d := range s.cfg.Destinations {
		authMode := "none"
		if d.ClientCertFile != "" {
			authMode = "mtls"
		} else if d.CredentialEnv != "" {
			authMode = "bearer"
		}
		result[name] = map[string]any{"kind": d.Kind, "forwarding_configured": d.URL != "", "upstream_auth": authMode}
	}
	writeJSON(w, 200, result)
}
func (s *Server) check(w http.ResponseWriter, r *http.Request)   { s.upload(w, r, false) }
func (s *Server) forward(w http.ResponseWriter, r *http.Request) { s.upload(w, r, true) }

func (s *Server) upload(w http.ResponseWriter, r *http.Request, doForward bool) {
	actor, ok := s.clientActor(w, r)
	if !ok {
		return
	}
	destinationName := r.PathValue("destination")
	destination, exists := s.cfg.Destinations[destinationName]
	if !exists {
		s.writeRejectedUpload(w, http.StatusNotFound, actor, safeAuditLabel(destinationName, 80), "unavailable", 0, "unknown_destination")
		return
	}
	// Allow bounded multipart framing overhead while enforcing the exact file
	// limit again when reading the selected part below.
	r.Body = http.MaxBytesReader(w, r.Body, config.MaxUploadBytes+1024*1024)
	if err := r.ParseMultipartForm(config.MaxUploadBytes); err != nil {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			s.writeRejectedUpload(w, http.StatusRequestEntityTooLarge, actor, destinationName, "unavailable", 0, "file_too_large")
		} else {
			s.writeRejectedUpload(w, http.StatusBadRequest, actor, destinationName, "unavailable", 0, "invalid_multipart")
		}
		return
	}
	defer r.MultipartForm.RemoveAll()
	file, header, err := r.FormFile("file")
	if err != nil {
		s.writeRejectedUpload(w, http.StatusBadRequest, actor, destinationName, "unavailable", 0, "file_required")
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, config.MaxUploadBytes+1))
	if err != nil {
		s.writeRejectedUpload(w, http.StatusBadRequest, actor, destinationName, safeFilename(header.Filename), 0, "file_read_failed")
		return
	}
	filename := safeFilename(header.Filename)
	size := int64(len(data))
	digest := ""
	if size <= config.MaxUploadBytes {
		sum := sha256.Sum256(data)
		digest = hex.EncodeToString(sum[:])
	}
	if len(data) == 0 || size > config.MaxUploadBytes {
		reason := "empty_file"
		status := 400
		if size > config.MaxUploadBytes {
			reason = "file_too_large"
			status = 413
		}
		id, err := s.store.InsertAudit(store.Audit{Actor: actor, Destination: destinationName, Filename: filename, SHA256: digest, Size: size, Action: "block", Reasons: []string{reason}, ModelStatus: "skipped", TransferStatus: "not_attempted"})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "audit_failed")
			return
		}
		writeJSON(w, status, map[string]any{"audit_id": id, "reason": reason})
		return
	}
	policies, err := s.store.Policies()
	if err != nil {
		s.writeRejectedUpload(w, http.StatusServiceUnavailable, actor, destinationName, filename, size, "policy_state_unavailable")
		return
	}
	actorStatus, err := s.store.UserStatus(actor)
	if err != nil {
		s.writeRejectedUpload(w, http.StatusServiceUnavailable, actor, destinationName, filename, size, "identity_state_unavailable")
		return
	}
	approved, err := s.store.Approved(actor, destinationName, digest)
	if err != nil {
		s.writeRejectedUpload(w, http.StatusServiceUnavailable, actor, destinationName, filename, size, "exception_state_unavailable")
		return
	}
	decision := s.engine.Inspect(r.Context(), data, filename, destination, actorStatus, policies, approved)
	transferStatus := "not_requested"
	if doForward {
		transferStatus = "not_attempted"
		if decision.Action == "allow" {
			transferStatus = "pending"
		}
	}
	audit := store.Audit{Actor: actor, Destination: destinationName, Filename: filename, SHA256: digest, Size: size, Action: decision.Action, Reasons: decision.Reasons, Signals: decision.Signals, ModelStatus: decision.ModelStatus, TransferStatus: transferStatus}
	id, err := s.store.InsertAudit(audit)
	if err != nil {
		writeError(w, 500, "audit_failed")
		return
	}
	result := map[string]any{"audit_id": id, "destination": destinationName, "sha256": digest, "action": decision.Action, "reasons": decision.Reasons, "signals": decision.Signals, "model_status": decision.ModelStatus, "forwarded": false, "transfer_status": transferStatus}
	if !doForward || decision.Action != "allow" {
		writeJSON(w, 200, result)
		return
	}
	if destination.URL == "" {
		if err := s.store.MarkDelivery(id, nil, false, "not_configured"); err != nil {
			writeErrorWithAudit(w, http.StatusInternalServerError, id, "audit_update_failed")
			return
		}
		writeErrorWithAudit(w, 503, id, "forwarding_not_configured")
		return
	}
	status, reason := s.connector.Forward(r.Context(), destinationName, destination, filename, data, id)
	if reason != "" {
		var upstreamStatus *int
		if status > 0 {
			upstreamStatus = &status
		}
		if err := s.store.MarkDelivery(id, upstreamStatus, false, "failed"); err != nil {
			writeErrorWithAudit(w, http.StatusInternalServerError, id, "audit_update_failed")
			return
		}
		writeErrorWithAudit(w, 502, id, reason)
		return
	}
	if err := s.store.MarkDelivery(id, &status, true, "forwarded"); err != nil {
		writeErrorWithAudit(w, http.StatusInternalServerError, id, "forwarded_audit_update_failed")
		return
	}
	result["forwarded"] = true
	result["transfer_status"] = "forwarded"
	result["upstream_status"] = status
	writeJSON(w, 200, result)
}

func (s *Server) writeRejectedUpload(w http.ResponseWriter, status int, actor, destination, filename string, size int64, reason string) {
	id, err := s.store.InsertAudit(store.Audit{
		Actor: actor, Destination: destination, Filename: filename, Size: size,
		Action: "block", Reasons: []string{reason}, ModelStatus: "skipped", TransferStatus: "not_attempted",
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "audit_failed")
		return
	}
	writeJSON(w, status, map[string]any{"detail": reason, "audit_id": id})
}
func (s *Server) requestException(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.clientActor(w, r)
	if !ok {
		return
	}
	var payload struct {
		AuditID       int64  `json:"audit_id"`
		Justification string `json:"justification"`
	}
	if !decodeJSON(r, &payload) || len([]rune(payload.Justification)) < 8 || len([]rune(payload.Justification)) > 240 {
		writeError(w, 400, "invalid_exception")
		return
	}
	audit, err := s.store.AuditForActor(payload.AuditID, actor)
	if err != nil {
		writeError(w, 404, "eligible_audit_not_found")
		return
	}
	policyHit := false
	for _, reason := range audit.Reasons {
		if strings.HasPrefix(reason, "policy_") {
			policyHit = true
		}
	}
	if !policyHit {
		writeError(w, 400, "only_policy_decisions_are_eligible")
		return
	}
	id, err := s.store.CreateException(audit, actor, payload.Justification)
	if err != nil {
		writeError(w, 409, "exception_already_exists")
		return
	}
	_ = s.store.Event("exception_requested", strconv.FormatInt(id, 10))
	writeJSON(w, 201, map[string]any{"id": id, "status": "pending"})
}
func (s *Server) adminAudits(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	limit := queryInt(r, "limit", 50)
	if limit < 1 || limit > 500 {
		writeError(w, http.StatusBadRequest, "limit_must_be_1_to_500")
		return
	}
	items, err := s.store.Audits(limit)
	if err != nil {
		writeError(w, 500, "query_failed")
		return
	}
	writeJSON(w, 200, items)
}
func (s *Server) queryAudits(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	if page < 1 || page > 1_000_000 || pageSize < 1 || pageSize > 100 {
		writeError(w, http.StatusBadRequest, "invalid_pagination")
		return
	}
	query, ok := auditFilters(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_audit_filters")
		return
	}
	query.Limit = pageSize
	query.Offset = (page - 1) * pageSize
	result, err := s.store.QueryAudits(query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed")
		return
	}
	writeJSON(w, http.StatusOK, result)
}
func (s *Server) exportAudits(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	query, ok := auditFilters(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_audit_filters")
		return
	}
	query.Limit = 5000
	result, err := s.store.QueryAudits(query)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="dlp-audits.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"id", "created_at", "action", "actor", "destination", "filename", "size_bytes", "reasons", "signals", "transfer_status"})
	for _, item := range result.Items {
		_ = writer.Write([]string{
			strconv.FormatInt(item.ID, 10), item.CreatedAt, item.Action, csvSafe(item.Actor), csvSafe(item.Destination), csvSafe(item.Filename),
			strconv.FormatInt(item.Size, 10), csvSafe(strings.Join(item.Reasons, "|")), csvSafe(strings.Join(item.Signals, "|")), item.TransferStatus,
		})
	}
	writer.Flush()
	_ = s.store.Event("audits_exported", strconv.Itoa(len(result.Items)))
}

func auditFilters(r *http.Request) (store.AuditQuery, bool) {
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	if action != "" && action != "allow" && action != "review" && action != "block" {
		return store.AuditQuery{}, false
	}
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	if len([]rune(search)) > 120 {
		return store.AuditQuery{}, false
	}
	window := r.URL.Query().Get("window")
	if window == "" {
		window = "all"
	}
	var since *time.Time
	durations := map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour, "90d": 90 * 24 * time.Hour}
	if window != "all" {
		duration, exists := durations[window]
		if !exists {
			return store.AuditQuery{}, false
		}
		value := time.Now().UTC().Add(-duration)
		since = &value
	}
	return store.AuditQuery{Action: action, Search: search, Since: since}, true
}

func csvSafe(value string) string {
	trimmed := strings.TrimLeft(value, " \t\r\n")
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}
func (s *Server) adminPolicies(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	items, err := s.store.Policies()
	if err != nil {
		writeError(w, 500, "query_failed")
		return
	}
	writeJSON(w, 200, items)
}
func (s *Server) addPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	p, ok := readPolicy(r)
	if !ok {
		writeError(w, 400, "invalid_policy")
		return
	}
	id, err := s.store.AddPolicy(p)
	if err != nil {
		writeError(w, 500, "policy_failed")
		return
	}
	_ = s.store.Event("policy_created", strconv.FormatInt(id, 10))
	writeJSON(w, 201, map[string]any{"id": id, "mode": p.Mode})
}
func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		writeError(w, 400, "invalid_id")
		return
	}
	p, ok := readPolicy(r)
	if !ok {
		writeError(w, 400, "invalid_policy")
		return
	}
	if err := s.store.UpdatePolicy(id, p); err != nil {
		writeError(w, 404, "policy_not_found")
		return
	}
	_ = s.store.Event("policy_updated", strconv.FormatInt(id, 10)+":"+p.Mode)
	writeJSON(w, 200, map[string]any{"id": id, "mode": p.Mode, "updated": true})
}

func readPolicy(r *http.Request) (store.Policy, bool) {
	var payload struct {
		Keyword string `json:"keyword"`
		Action  string `json:"action"`
		Scope   string `json:"scope"`
		Mode    string `json:"mode"`
		Enabled *bool  `json:"enabled"`
	}
	if !decodeJSON(r, &payload) || len([]rune(strings.TrimSpace(payload.Keyword))) < 2 || !validActionScope(payload.Action, payload.Scope) {
		return store.Policy{}, false
	}
	mode := payload.Mode
	if mode == "" {
		mode = "enforce"
		if payload.Enabled != nil && !*payload.Enabled {
			mode = "draft"
		}
	}
	if !validPolicyMode(mode) {
		return store.Policy{}, false
	}
	return store.Policy{Keyword: strings.TrimSpace(payload.Keyword), Action: payload.Action, Scope: payload.Scope, Mode: mode, Enabled: mode != "draft"}, true
}
func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	items, err := s.store.Users(s.cfg.Actors())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed")
		return
	}
	writeJSON(w, 200, items)
}
func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	actor := r.PathValue("actor")
	if _, ok := s.cfg.Actors()[actor]; !ok {
		writeError(w, 404, "unknown_actor")
		return
	}
	var payload struct {
		Status string `json:"status"`
	}
	if !decodeJSON(r, &payload) || !validStatus(payload.Status) {
		writeError(w, 400, "invalid_status")
		return
	}
	if err := s.store.SetUserStatus(actor, payload.Status); err != nil {
		writeError(w, 500, "user_failed")
		return
	}
	_ = s.store.Event("user_status_updated", actor)
	writeJSON(w, 200, map[string]any{"actor": actor, "status": payload.Status})
}
func (s *Server) adminExceptions(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	items, err := s.store.Exceptions()
	if err != nil {
		writeError(w, 500, "query_failed")
		return
	}
	writeJSON(w, 200, items)
}
func (s *Server) approveException(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		writeError(w, 400, "invalid_id")
		return
	}
	var payload struct {
		Hours int `json:"hours"`
	}
	if !decodeJSON(r, &payload) || payload.Hours < 1 || payload.Hours > 24 {
		writeError(w, 400, "invalid_hours")
		return
	}
	if err := s.store.ApproveException(id, payload.Hours); err != nil {
		writeError(w, 404, "pending_exception_not_found")
		return
	}
	_ = s.store.Event("exception_approved", strconv.FormatInt(id, 10))
	writeJSON(w, 200, map[string]any{"id": id, "status": "approved"})
}
func (s *Server) rejectException(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		writeError(w, 400, "invalid_id")
		return
	}
	if err := s.store.RejectException(id); err != nil {
		writeError(w, 404, "pending_exception_not_found")
		return
	}
	_ = s.store.Event("exception_rejected", strconv.FormatInt(id, 10))
	writeJSON(w, 200, map[string]any{"id": id, "status": "rejected"})
}
func (s *Server) feedback(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		writeError(w, 400, "invalid_id")
		return
	}
	var payload struct {
		Verdict string `json:"verdict"`
		Note    string `json:"note"`
	}
	if !decodeJSON(r, &payload) || (payload.Verdict != "true_positive" && payload.Verdict != "false_positive") || len([]rune(payload.Note)) > 240 {
		writeError(w, 400, "invalid_feedback")
		return
	}
	if _, err := s.store.AuditByID(id); err != nil {
		writeError(w, 404, "audit_not_found")
		return
	}
	if err := s.store.Feedback(id, payload.Verdict, payload.Note); err != nil {
		writeError(w, 500, "feedback_failed")
		return
	}
	_ = s.store.Event("feedback_recorded", strconv.FormatInt(id, 10))
	writeJSON(w, 200, map[string]any{"audit_id": id, "verdict": payload.Verdict})
}
func (s *Server) adminFeedback(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	items, err := s.store.Feedbacks()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed")
		return
	}
	writeJSON(w, http.StatusOK, items)
}
func (s *Server) adminIncidents(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	items, err := s.store.Incidents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed")
		return
	}
	writeJSON(w, http.StatusOK, items)
}
func (s *Server) updateIncident(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_id")
		return
	}
	var payload struct {
		Status   string `json:"status"`
		Assignee string `json:"assignee"`
	}
	if !decodeJSON(r, &payload) {
		writeError(w, http.StatusBadRequest, "invalid_incident")
		return
	}
	payload.Assignee = strings.TrimSpace(payload.Assignee)
	if !validIncidentStatus(payload.Status) || len([]rune(payload.Assignee)) > 80 {
		writeError(w, http.StatusBadRequest, "invalid_incident")
		return
	}
	audit, err := s.store.AuditByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "audit_not_found")
		return
	}
	if audit.Action == "allow" {
		writeError(w, http.StatusConflict, "allow_event_is_not_incident")
		return
	}
	if payload.Status == "resolved" {
		feedbacks, err := s.store.Feedbacks()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "query_failed")
			return
		}
		hasVerdict := false
		for _, item := range feedbacks {
			if item.AuditID == id {
				hasVerdict = true
				break
			}
		}
		if !hasVerdict {
			writeError(w, http.StatusConflict, "incident_resolution_requires_verdict")
			return
		}
	}
	if err := s.store.UpsertIncident(id, payload.Status, payload.Assignee); err != nil {
		writeError(w, http.StatusInternalServerError, "incident_failed")
		return
	}
	_ = s.store.Event("incident_updated", strconv.FormatInt(id, 10)+":"+payload.Status)
	writeJSON(w, http.StatusOK, map[string]any{"audit_id": id, "status": payload.Status, "assignee": payload.Assignee})
}
func (s *Server) incidentNotes(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_id")
		return
	}
	audit, err := s.store.AuditByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "audit_not_found")
		return
	}
	if audit.Action == "allow" {
		writeError(w, http.StatusConflict, "allow_event_is_not_incident")
		return
	}
	items, err := s.store.IncidentNotes(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed")
		return
	}
	writeJSON(w, http.StatusOK, items)
}
func (s *Server) addIncidentNote(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_id")
		return
	}
	var payload struct {
		Body string `json:"body"`
	}
	if !decodeJSON(r, &payload) {
		writeError(w, http.StatusBadRequest, "invalid_note")
		return
	}
	payload.Body = strings.TrimSpace(payload.Body)
	if len([]rune(payload.Body)) < 1 || len([]rune(payload.Body)) > 500 {
		writeError(w, http.StatusBadRequest, "invalid_note")
		return
	}
	audit, err := s.store.AuditByID(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "audit_not_found")
		return
	}
	if audit.Action == "allow" {
		writeError(w, http.StatusConflict, "allow_event_is_not_incident")
		return
	}
	_, subject, _ := s.adminPrincipal(r)
	noteID, err := s.store.AddIncidentNote(id, subject, payload.Body)
	if err != nil {
		if _, lookupErr := s.store.AuditByID(id); lookupErr != nil {
			writeError(w, http.StatusNotFound, "audit_not_found")
			return
		}
		writeError(w, http.StatusInternalServerError, "note_failed")
		return
	}
	_ = s.store.Event("incident_note_added", strconv.FormatInt(id, 10))
	writeJSON(w, http.StatusCreated, map[string]any{"id": noteID, "audit_id": id})
}
func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	days := queryInt(r, "days", 7)
	if days < 1 || days > 90 {
		writeError(w, 400, "days_must_be_1_to_90")
		return
	}
	since := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
	audits, err := s.store.AuditsSince(since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query_failed")
		return
	}
	counts := map[string]int{"allow": 0, "review": 0, "block": 0}
	transferCounts := map[string]int{"not_requested": 0, "not_attempted": 0, "pending": 0, "not_configured": 0, "failed": 0, "forwarded": 0}
	top := map[string]int{}
	daily := map[string]map[string]int{}
	for _, a := range audits {
		counts[a.Action]++
		transferCounts[a.TransferStatus]++
		day := "unknown"
		if created, parseErr := time.Parse(time.RFC3339, a.CreatedAt); parseErr == nil {
			day = created.UTC().Format("2006-01-02")
		}
		if daily[day] == nil {
			daily[day] = map[string]int{"allow": 0, "review": 0, "block": 0}
		}
		daily[day][a.Action]++
		for _, reason := range a.Reasons {
			top[reason]++
		}
	}
	feedbacks, _ := s.store.Feedbacks()
	falsePositive := map[int64]bool{}
	feedbackByAudit := map[int64]store.Feedback{}
	for _, f := range feedbacks {
		feedbackByAudit[f.AuditID] = f
		if f.Verdict == "false_positive" {
			falsePositive[f.AuditID] = true
		}
	}
	suggestions := map[string]int{}
	riskActors := map[string]bool{}
	riskCount, remediatedCount, falsePositiveCount, completeInspections := 0, 0, 0, 0
	var remediationSeconds int64
	remediationSamples := int64(0)
	for _, a := range audits {
		complete := true
		for _, reason := range a.Reasons {
			if reason == "unparseable_or_unsupported" || reason == "unsupported_format" || reason == "analyzer_unavailable" || reason == "blank_content" || reason == "file_too_large" {
				complete = false
			}
		}
		if complete {
			completeInspections++
		}
		if a.Action != "allow" {
			riskCount++
			riskActors[a.Actor] = true
			if item, ok := feedbackByAudit[a.ID]; ok {
				remediatedCount++
				if item.Verdict == "false_positive" {
					falsePositiveCount++
				}
				created, auditErr := time.Parse(time.RFC3339, a.CreatedAt)
				resolved, feedbackErr := time.Parse(time.RFC3339, item.CreatedAt)
				if auditErr == nil && feedbackErr == nil && !resolved.Before(created) {
					remediationSeconds += int64(resolved.Sub(created).Seconds())
					remediationSamples++
				}
			}
		}
		if !falsePositive[a.ID] {
			continue
		}
		for _, reason := range a.Reasons {
			if strings.HasPrefix(reason, "policy_") {
				suggestions[reason]++
			}
		}
	}
	var meanRemediationSeconds any
	if remediationSamples > 0 {
		meanRemediationSeconds = remediationSeconds / remediationSamples
	}
	var inspectionCoverage any
	if len(audits) > 0 {
		inspectionCoverage = completeInspections * 100 / len(audits)
	}
	operations := map[string]any{
		"active_risks": riskCount - remediatedCount, "remediated": remediatedCount, "false_positives": falsePositiveCount,
		"mean_time_to_remediate_seconds": meanRemediationSeconds, "inspection_coverage_percent": inspectionCoverage,
		"high_risk_users": len(riskActors), "active_detectors": len(top),
	}
	writeJSON(w, 200, map[string]any{"days": days, "total": len(audits), "counts": counts, "transfer_counts": transferCounts, "daily_counts": daily, "top_reasons": top, "false_positive_policy_candidates": suggestions, "operations": operations, "note": "Feedback generates suggestions only; no automatic policy changes."})
}
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	items, err := s.store.Events()
	if err != nil {
		writeError(w, 500, "query_failed")
		return
	}
	writeJSON(w, 200, items)
}

func (s *Server) clientActor(w http.ResponseWriter, r *http.Request) (string, bool) {
	if actor, ok := access.MTLSActor(r, s.cfg.MTLSActors); ok {
		return actor, true
	}
	if s.cfg.RequireMTLS {
		writeError(w, http.StatusUnauthorized, "verified_client_certificate_required")
		return "", false
	}
	token, ok := bearer(r)
	if !ok {
		writeError(w, 401, "bearer_token_required")
		return "", false
	}
	for actor, key := range s.cfg.ClientKeys {
		if hmac.Equal([]byte(token), []byte(key)) {
			return actor, true
		}
	}
	writeError(w, 401, "invalid_client_token")
	return "", false
}
func (s *Server) adminOK(w http.ResponseWriter, r *http.Request) bool {
	role, _, ok := s.adminPrincipal(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "admin_authentication_required")
		return false
	}
	if !s.rbac.Allowed(role, r.URL.Path, r.Method) {
		writeError(w, http.StatusForbidden, "insufficient_role")
		return false
	}
	return true
}
func (s *Server) adminPrincipal(r *http.Request) (role, subject string, ok bool) {
	if token, present := bearer(r); present && s.cfg.AdminKey != "" && hmac.Equal([]byte(token), []byte(s.cfg.AdminKey)) {
		return "admin", "local-admin", true
	}
	if identity, present := s.access.Identity(r); present {
		subject = identity.Subject
		if subject == "" {
			subject = identity.Email
		}
		if subject == "" {
			subject = identity.Name
		}
		return identity.Role, subject, true
	}
	return "", "", false
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.access == nil {
		writeError(w, http.StatusNotFound, "oidc_not_configured")
		return
	}
	s.access.Login(w, r)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	if s.access == nil {
		writeError(w, http.StatusNotFound, "oidc_not_configured")
		return
	}
	s.access.Callback(w, r)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if s.access == nil {
		writeJSON(w, http.StatusOK, map[string]any{"logged_out": true})
		return
	}
	s.access.Logout(w, r)
}

func (s *Server) authSession(w http.ResponseWriter, r *http.Request) {
	if token, ok := bearer(r); ok && s.cfg.AdminKey != "" && hmac.Equal([]byte(token), []byte(s.cfg.AdminKey)) {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "mode": "static", "identity": access.Identity{Subject: "local-admin", Name: "Local administrator", Role: "admin"}})
		return
	}
	if identity, ok := s.access.Identity(r); ok {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "mode": "oidc", "identity": identity})
		return
	}
	mode := "static"
	if s.cfg.OIDCEnabled() {
		mode = "oidc"
		if s.cfg.AdminKey != "" {
			mode = "oidc_or_static"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": false, "mode": mode})
}
func decodeJSON(r *http.Request, value any) bool {
	w, ok := r.Context().Value(writerContextKey{}).(http.ResponseWriter)
	if !ok {
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	decoder := json.NewDecoder(r.Body)
	if decoder.Decode(value) != nil {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}
func bearer(r *http.Request) (string, bool) {
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(value, "Bearer ")), true
}
func pathID(r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	return id, err == nil && id > 0
}
func queryInt(r *http.Request, name string, fallback int) int {
	value, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || value == 0 {
		return fallback
	}
	return value
}
func validActionScope(action, scope string) bool {
	return (action == "block" || action == "review") && (scope == "all" || scope == "internal" || scope == "external")
}
func validPolicyMode(value string) bool {
	return value == "draft" || value == "monitor" || value == "enforce"
}
func validStatus(value string) bool {
	return value == "normal" || value == "privileged" || value == "departing"
}
func validIncidentStatus(value string) bool {
	return value == "new" || value == "investigating" || value == "pending_business" || value == "resolved"
}
func safeFilename(value string) string {
	value = filepath.Base(strings.ReplaceAll(value, "\\", "/"))
	var b strings.Builder
	for _, r := range value {
		if r < 32 || r == 127 {
			b.WriteRune('_')
		} else {
			b.WriteRune(r)
		}
	}
	result := b.String()
	if !utf8.ValidString(result) || result == "." || result == "" {
		return "unnamed"
	}
	if len([]byte(result)) > 180 {
		var truncated strings.Builder
		for _, r := range result {
			if truncated.Len()+utf8.RuneLen(r) > 180 {
				break
			}
			truncated.WriteRune(r)
		}
		return truncated.String()
	}
	return result
}
func safeAuditLabel(value string, maxRunes int) string {
	value = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return '_'
		}
		return r
	}, value)
	if value == "" {
		return "unavailable"
	}
	runes := []rune(value)
	if len(runes) > maxRunes {
		runes = runes[:maxRunes]
	}
	return string(runes)
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, reason string) {
	writeJSON(w, status, map[string]any{"detail": reason})
}
func writeErrorWithAudit(w http.ResponseWriter, status int, id int64, reason string) {
	writeJSON(w, status, map[string]any{"detail": map[string]any{"audit_id": id, "reason": reason}})
}
