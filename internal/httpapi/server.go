package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/int-wc/dlp-agent-gateway/internal/config"
	"github.com/int-wc/dlp-agent-gateway/internal/policy"
	"github.com/int-wc/dlp-agent-gateway/internal/store"
)

type Server struct {
	cfg    config.Config
	store  *store.Store
	engine *policy.Engine
	mux    *http.ServeMux
}
type writerContextKey struct{}

func New(cfg config.Config, s *store.Store, e *policy.Engine) *Server {
	srv := &Server{cfg: cfg, store: s, engine: e, mux: http.NewServeMux()}
	srv.routes()
	return srv
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
	s.mux.HandleFunc("GET /console", s.console)
	s.mux.HandleFunc("GET /v1/destinations", s.destinations)
	s.mux.HandleFunc("POST /v1/check/{destination}", s.check)
	s.mux.HandleFunc("POST /v1/forward/{destination}", s.forward)
	s.mux.HandleFunc("POST /v1/exceptions", s.requestException)
	s.mux.HandleFunc("GET /v1/admin/audits", s.adminAudits)
	s.mux.HandleFunc("GET /v1/admin/policies", s.adminPolicies)
	s.mux.HandleFunc("POST /v1/admin/policies", s.addPolicy)
	s.mux.HandleFunc("PUT /v1/admin/policies/{id}", s.updatePolicy)
	s.mux.HandleFunc("GET /v1/admin/users", s.adminUsers)
	s.mux.HandleFunc("PUT /v1/admin/users/{actor}", s.updateUser)
	s.mux.HandleFunc("GET /v1/admin/exceptions", s.adminExceptions)
	s.mux.HandleFunc("POST /v1/admin/exceptions/{id}/approve", s.approveException)
	s.mux.HandleFunc("POST /v1/admin/exceptions/{id}/reject", s.rejectException)
	s.mux.HandleFunc("PUT /v1/admin/audits/{id}/feedback", s.feedback)
	s.mux.HandleFunc("GET /v1/admin/report", s.report)
	s.mux.HandleFunc("GET /v1/admin/events", s.events)
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"status": "ok", "version": "0.2.0", "analyzer_enabled": s.cfg.AnalyzerURL != "", "model_enabled": s.cfg.OllamaModel != ""})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AnalyzerURL == "" {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "analyzer": "disabled"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if !s.engine.AnalyzerReady(ctx) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "degraded", "analyzer": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "analyzer": "ready"})
}
func (s *Server) console(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(s.cfg.ConsolePath)
	if err != nil {
		writeError(w, 404, "console_not_found")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}
func (s *Server) destinations(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.clientActor(w, r); !ok {
		return
	}
	result := map[string]any{}
	for name, d := range s.cfg.Destinations {
		result[name] = map[string]any{"kind": d.Kind, "forwarding_configured": d.URL != ""}
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
	policies, _ := s.store.Policies()
	decision := s.engine.Inspect(r.Context(), data, filename, destination, s.store.UserStatus(actor), policies, s.store.Approved(actor, destinationName, digest))
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
	status, reason := s.sendUpstream(r, destination.URL, filename, data, id)
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
func (s *Server) sendUpstream(r *http.Request, url, filename string, data []byte, auditID int64) (int, string) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return 0, err.Error()
	}
	if _, err = part.Write(data); err != nil {
		return 0, err.Error()
	}
	if err = writer.Close(); err != nil {
		return 0, err.Error()
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, url, &body)
	if err != nil {
		return 0, err.Error()
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-DLP-Audit-ID", strconv.FormatInt(auditID, 10))
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "upstream_unavailable"
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, "upstream_rejected"
	}
	return resp.StatusCode, ""
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
	var payload struct {
		Keyword string `json:"keyword"`
		Action  string `json:"action"`
		Scope   string `json:"scope"`
		Enabled *bool  `json:"enabled"`
	}
	if !decodeJSON(r, &payload) || len([]rune(strings.TrimSpace(payload.Keyword))) < 2 || !validActionScope(payload.Action, payload.Scope) {
		writeError(w, 400, "invalid_policy")
		return
	}
	enabled := true
	if payload.Enabled != nil {
		enabled = *payload.Enabled
	}
	p := store.Policy{Keyword: strings.TrimSpace(payload.Keyword), Action: payload.Action, Scope: payload.Scope, Enabled: enabled}
	id, err := s.store.AddPolicy(p)
	if err != nil {
		writeError(w, 500, "policy_failed")
		return
	}
	_ = s.store.Event("policy_created", strconv.FormatInt(id, 10))
	writeJSON(w, 201, map[string]any{"id": id})
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
	var p store.Policy
	if !decodeJSON(r, &p) || len([]rune(strings.TrimSpace(p.Keyword))) < 2 || !validActionScope(p.Action, p.Scope) {
		writeError(w, 400, "invalid_policy")
		return
	}
	p.Keyword = strings.TrimSpace(p.Keyword)
	if err := s.store.UpdatePolicy(id, p); err != nil {
		writeError(w, 404, "policy_not_found")
		return
	}
	_ = s.store.Event("policy_updated", strconv.FormatInt(id, 10))
	writeJSON(w, 200, map[string]any{"id": id, "updated": true})
}
func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	writeJSON(w, 200, s.store.Users(s.cfg.ClientKeys))
}
func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(w, r) {
		return
	}
	actor := r.PathValue("actor")
	if _, ok := s.cfg.ClientKeys[actor]; !ok {
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
	for _, a := range audits {
		counts[a.Action]++
		transferCounts[a.TransferStatus]++
		for _, reason := range a.Reasons {
			top[reason]++
		}
	}
	feedbacks, _ := s.store.Feedbacks()
	falsePositive := map[int64]bool{}
	for _, f := range feedbacks {
		if f.Verdict == "false_positive" {
			falsePositive[f.AuditID] = true
		}
	}
	suggestions := map[string]int{}
	for _, a := range audits {
		if !falsePositive[a.ID] {
			continue
		}
		for _, reason := range a.Reasons {
			if strings.HasPrefix(reason, "policy_") {
				suggestions[reason]++
			}
		}
	}
	writeJSON(w, 200, map[string]any{"days": days, "total": len(audits), "counts": counts, "transfer_counts": transferCounts, "top_reasons": top, "false_positive_policy_candidates": suggestions, "note": "Feedback generates suggestions only; no automatic policy changes."})
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
	token, ok := bearer(r)
	if !ok {
		writeError(w, 401, "bearer_token_required")
		return false
	}
	if !hmac.Equal([]byte(token), []byte(s.cfg.AdminKey)) {
		writeError(w, 401, "invalid_admin_token")
		return false
	}
	return true
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
func validStatus(value string) bool {
	return value == "normal" || value == "privileged" || value == "departing"
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
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
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
