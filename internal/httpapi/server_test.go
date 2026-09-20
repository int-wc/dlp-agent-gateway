package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/int-wc/dlp-agent-gateway/internal/config"
	"github.com/int-wc/dlp-agent-gateway/internal/policy"
	"github.com/int-wc/dlp-agent-gateway/internal/store"
)

type unavailablePolicyRepository struct{ store.Repository }

func (unavailablePolicyRepository) Policies() ([]store.Policy, error) {
	return nil, errors.New("synthetic database outage")
}

const clientKey = "client-go-smoke-key-20260918-abcdefghijklmnopqrstuvwxyz"
const adminKey = "admin-go-smoke-key-20260918-abcdefghijklmnopqrstuvwxyz"

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.json")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{AdminKey: adminKey, ClientKeys: map[string]string{"demo-user": clientKey}, Destinations: map[string]config.Destination{"external": {Kind: "external"}, "internal": {Kind: "internal"}}, DBPath: path, ListenAddress: "127.0.0.1:0"}
	handler, err := New(cfg, db, policy.New(cfg))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler.Handler())
	t.Cleanup(func() { srv.Close(); db.Close() })
	return srv
}

func upload(t *testing.T, base, path, filename string, data []byte, token string) *http.Response {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(data)
	_ = writer.Close()
	req, err := http.NewRequest(http.MethodPost, base+path, &body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
func bodyJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var value map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func bodyJSONArray(t *testing.T, resp *http.Response) []map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var value []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func adminRequest(t *testing.T, method, url string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+adminKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestEmptyAdminCollectionsAndConsoleAreUsable(t *testing.T) {
	srv := newTestServer(t)
	for _, endpoint := range []string{"/v1/admin/audits", "/v1/admin/policies", "/v1/admin/exceptions", "/v1/admin/events"} {
		items := bodyJSONArray(t, adminRequest(t, http.MethodGet, srv.URL+endpoint, nil))
		if items == nil || len(items) != 0 {
			t.Fatalf("%s=%v, want []", endpoint, items)
		}
	}
	report := bodyJSON(t, adminRequest(t, http.MethodGet, srv.URL+"/v1/admin/report", nil))
	if report["total"] != float64(0) {
		t.Fatalf("empty report=%v", report)
	}
	resp, err := http.Get(srv.URL + "/console")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	html, _ := io.ReadAll(resp.Body)
	for _, expected := range []string{"Sentinel Gate", "DLP 运营台", "root"} {
		if !bytes.Contains(html, []byte(expected)) {
			t.Fatalf("console missing %q", expected)
		}
	}
}

func TestGoGatewayHealthAndFailClosedDecisions(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	health := bodyJSON(t, resp)
	if health["status"] != "ok" || health["version"] != "0.3.0" {
		t.Fatalf("health=%v", health)
	}
	resp, err = http.Get(srv.URL + "/ready")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ready status=%d", resp.StatusCode)
	}
	resp.Body.Close()
	result := bodyJSON(t, upload(t, srv.URL, "/v1/check/external", "safe.txt", []byte("synthetic public document"), clientKey))
	if result["action"] != "allow" {
		t.Fatalf("safe=%v", result)
	}
	result = bodyJSON(t, upload(t, srv.URL, "/v1/check/external", "secret.txt", []byte("-----BEGIN PRIVATE KEY-----"), clientKey))
	if result["action"] != "block" {
		t.Fatalf("secret=%v", result)
	}
	result = bodyJSON(t, upload(t, srv.URL, "/v1/check/external", "pii.txt", []byte("Call 13800138000"), clientKey))
	if result["action"] != "review" {
		t.Fatalf("pii=%v", result)
	}
	resp = upload(t, srv.URL, "/v1/check/external", "safe.txt", []byte("x"), "wrong")
	if resp.StatusCode != 401 {
		t.Fatalf("bad auth status=%d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestPolicyStateOutageFailsUploadClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{AdminKey: adminKey, ClientKeys: map[string]string{"demo-user": clientKey}, Destinations: map[string]config.Destination{"external": {Kind: "external"}}, DBPath: path}
	handler, err := New(cfg, unavailablePolicyRepository{Repository: db}, policy.New(cfg))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler.Handler())
	defer srv.Close()
	defer db.Close()

	response := upload(t, srv.URL, "/v1/forward/external", "safe.txt", []byte("synthetic safe content"), clientKey)
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", response.StatusCode)
	}
	result := bodyJSON(t, response)
	if result["detail"] != "policy_state_unavailable" || result["audit_id"] == nil {
		t.Fatalf("response=%v", result)
	}
}

func TestSecurityHeaders(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/console")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	for name, expected := range map[string]string{
		"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
	} {
		if actual := resp.Header.Get(name); actual != expected {
			t.Fatalf("%s=%q want %q", name, actual, expected)
		}
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("missing CSP: %q", resp.Header.Get("Content-Security-Policy"))
	}
}

func TestReadinessFailsWhenConfiguredAnalyzerIsUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{AdminKey: adminKey, ClientKeys: map[string]string{"demo-user": clientKey}, Destinations: map[string]config.Destination{"external": {Kind: "external"}}, DBPath: path, AnalyzerURL: "http://127.0.0.1:1"}
	handler, newErr := New(cfg, db, policy.New(cfg))
	if newErr != nil {
		t.Fatal(newErr)
	}
	srv := httptest.NewServer(handler.Handler())
	defer srv.Close()
	defer db.Close()

	resp, err := http.Get(srv.URL + "/ready")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("ready status=%d", resp.StatusCode)
	}
}

func TestGoGatewayPolicyAndAdmin(t *testing.T) {
	srv := newTestServer(t)
	payload := map[string]any{"keyword": "project canary", "action": "block", "scope": "external", "enabled": true}
	raw, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/admin/policies", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("policy status=%d", resp.StatusCode)
	}
	resp.Body.Close()
	result := bodyJSON(t, upload(t, srv.URL, "/v1/check/external", "canary.txt", []byte("project canary"), clientKey))
	if result["action"] != "block" {
		t.Fatalf("policy decision=%v", result)
	}
}

func TestGoGatewayPolicyExceptionWorkflow(t *testing.T) {
	srv := newTestServer(t)
	payload := map[string]any{"keyword": "project canary", "action": "block", "scope": "external"}
	raw, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/admin/policies", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("policy status=%d err=%v", resp.StatusCode, err)
	}
	resp.Body.Close()

	original := bodyJSON(t, upload(t, srv.URL, "/v1/check/external", "canary.txt", []byte("project canary synthetic"), clientKey))
	exceptionBody, _ := json.Marshal(map[string]any{"audit_id": int64(original["audit_id"].(float64)), "justification": "Synthetic approval case"})
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/v1/exceptions", bytes.NewReader(exceptionBody))
	req.Header.Set("Authorization", "Bearer "+clientKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("exception status=%d err=%v", resp.StatusCode, err)
	}
	created := bodyJSON(t, resp)

	approvalBody, _ := json.Marshal(map[string]any{"hours": 1})
	exceptionID := strconv.FormatInt(int64(created["id"].(float64)), 10)
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/v1/admin/exceptions/"+exceptionID+"/approve", bytes.NewReader(approvalBody))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("approval status=%d err=%v", resp.StatusCode, err)
	}
	resp.Body.Close()

	approved := bodyJSON(t, upload(t, srv.URL, "/v1/check/external", "canary.txt", []byte("project canary synthetic"), clientKey))
	if approved["action"] != "allow" {
		t.Fatalf("approved=%v", approved)
	}
}

func TestGoGatewayForwardsOnlyAllowedBytes(t *testing.T) {
	var received []byte
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file, _, err := r.FormFile("file")
		if err != nil {
			t.Errorf("upstream form file: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer file.Close()
		received, _ = io.ReadAll(file)
		w.WriteHeader(http.StatusCreated)
	}))
	defer receiver.Close()

	path := filepath.Join(t.TempDir(), "audit.json")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{AdminKey: adminKey, ClientKeys: map[string]string{"demo-user": clientKey}, Destinations: map[string]config.Destination{"internal": {Kind: "internal", URL: receiver.URL}}, DBPath: path}
	handler, newErr := New(cfg, db, policy.New(cfg))
	if newErr != nil {
		t.Fatal(newErr)
	}
	gateway := httptest.NewServer(handler.Handler())
	defer gateway.Close()
	defer db.Close()

	safe := []byte("synthetic safe bytes")
	result := bodyJSON(t, upload(t, gateway.URL, "/v1/forward/internal", "safe.txt", safe, clientKey))
	if result["forwarded"] != true || !bytes.Equal(received, safe) {
		t.Fatalf("forward result=%v received=%q", result, received)
	}
	if result["transfer_status"] != "forwarded" {
		t.Fatalf("transfer result=%v", result)
	}
}

func TestForwardingOutcomeIsAudited(t *testing.T) {
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer receiver.Close()
	path := filepath.Join(t.TempDir(), "audit.json")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{AdminKey: adminKey, ClientKeys: map[string]string{"demo-user": clientKey}, Destinations: map[string]config.Destination{"configured": {Kind: "internal", URL: receiver.URL}, "check-only": {Kind: "internal"}}, DBPath: path}
	handler, newErr := New(cfg, db, policy.New(cfg))
	if newErr != nil {
		t.Fatal(newErr)
	}
	srv := httptest.NewServer(handler.Handler())
	defer srv.Close()
	defer db.Close()

	failed := upload(t, srv.URL, "/v1/forward/configured", "safe.txt", []byte("synthetic safe"), clientKey)
	if failed.StatusCode != http.StatusBadGateway {
		t.Fatalf("failed forward status=%d", failed.StatusCode)
	}
	failed.Body.Close()
	unconfigured := upload(t, srv.URL, "/v1/forward/check-only", "safe.txt", []byte("synthetic safe"), clientKey)
	if unconfigured.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured status=%d", unconfigured.StatusCode)
	}
	unconfigured.Body.Close()

	audits := bodyJSONArray(t, adminRequest(t, http.MethodGet, srv.URL+"/v1/admin/audits", nil))
	if audits[0]["transfer_status"] != "not_configured" || audits[1]["transfer_status"] != "failed" || audits[1]["upstream_status"] != float64(http.StatusServiceUnavailable) {
		t.Fatalf("delivery audits=%v", audits)
	}
}

func TestAuthenticatedRejectedUploadsAreAudited(t *testing.T) {
	srv := newTestServer(t)

	unknown := upload(t, srv.URL, "/v1/check/unknown", "safe.txt", []byte("synthetic"), clientKey)
	if unknown.StatusCode != http.StatusNotFound || bodyJSON(t, unknown)["audit_id"] == nil {
		t.Fatal("unknown destination was not audited")
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/check/external", strings.NewReader("not multipart"))
	req.Header.Set("Authorization", "Bearer "+clientKey)
	req.Header.Set("Content-Type", "text/plain")
	invalid, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if invalid.StatusCode != http.StatusBadRequest || bodyJSON(t, invalid)["audit_id"] == nil {
		t.Fatal("invalid multipart was not audited")
	}

	var emptyForm bytes.Buffer
	writer := multipart.NewWriter(&emptyForm)
	_ = writer.Close()
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/v1/check/external", &emptyForm)
	req.Header.Set("Authorization", "Bearer "+clientKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	missing, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if missing.StatusCode != http.StatusBadRequest || bodyJSON(t, missing)["audit_id"] == nil {
		t.Fatal("missing file was not audited")
	}

	empty := upload(t, srv.URL, "/v1/check/external", "empty.txt", []byte{}, clientKey)
	if empty.StatusCode != http.StatusBadRequest || bodyJSON(t, empty)["audit_id"] == nil {
		t.Fatal("empty file was not audited")
	}
	tooLarge := upload(t, srv.URL, "/v1/check/external", "large.txt", bytes.Repeat([]byte("x"), int(config.MaxUploadBytes+1)), clientKey)
	if tooLarge.StatusCode != http.StatusRequestEntityTooLarge || bodyJSON(t, tooLarge)["audit_id"] == nil {
		t.Fatal("oversized file was not audited")
	}

	audits := bodyJSONArray(t, adminRequest(t, http.MethodGet, srv.URL+"/v1/admin/audits?limit=20", nil))
	want := map[string]bool{"unknown_destination": false, "invalid_multipart": false, "file_required": false, "empty_file": false, "file_too_large": false}
	for _, audit := range audits {
		if audit["action"] != "block" || audit["transfer_status"] != "not_attempted" {
			t.Fatalf("rejected audit=%v", audit)
		}
		for _, reason := range audit["reasons"].([]any) {
			if _, ok := want[reason.(string)]; ok {
				want[reason.(string)] = true
			}
		}
	}
	for reason, found := range want {
		if !found {
			t.Fatalf("missing audited reason %s in %v", reason, audits)
		}
	}
}

func TestReportAndFeedbackAreNotLimitedToRecent200(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 205; i++ {
		if _, err := db.InsertAudit(store.Audit{Actor: "demo-user", Destination: "external", Filename: "synthetic.txt", Action: "review", Reasons: []string{"policy_1"}, ModelStatus: "disabled"}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Config{AdminKey: adminKey, ClientKeys: map[string]string{"demo-user": clientKey}, Destinations: map[string]config.Destination{"external": {Kind: "external"}}, DBPath: path}
	handler, newErr := New(cfg, db, policy.New(cfg))
	if newErr != nil {
		t.Fatal(newErr)
	}
	srv := httptest.NewServer(handler.Handler())
	defer srv.Close()
	defer db.Close()

	report := bodyJSON(t, adminRequest(t, http.MethodGet, srv.URL+"/v1/admin/report?days=7", nil))
	if report["total"] != float64(205) || report["counts"].(map[string]any)["review"] != float64(205) {
		t.Fatalf("report=%v", report)
	}
	payload, _ := json.Marshal(map[string]any{"verdict": "false_positive"})
	feedback := adminRequest(t, http.MethodPut, srv.URL+"/v1/admin/audits/1/feedback", bytes.NewReader(payload))
	if feedback.StatusCode != http.StatusOK {
		t.Fatalf("old audit feedback status=%d body=%v", feedback.StatusCode, bodyJSON(t, feedback))
	}
	feedback.Body.Close()
}

func TestGoStorePersistsAtomicAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "audit.json")
	s, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.InsertAudit(store.Audit{Actor: "demo", Destination: "external", Filename: "x.txt", SHA256: "abc", Size: 1, Action: "allow", Reasons: []string{}, Signals: []string{}, ModelStatus: "disabled"})
	if err != nil || id != 1 {
		t.Fatalf("insert id=%d err=%v", id, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	audits, _ := s.Audits(10)
	if len(audits) != 1 || audits[0].SHA256 != "abc" {
		t.Fatalf("audits=%v", audits)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("store mode=%o", info.Mode().Perm())
	}
	_ = s.Close()
}

func TestGoAnalyzerUnsupportedFormatFailsClosed(t *testing.T) {
	srv := newTestServer(t)
	result := bodyJSON(t, upload(t, srv.URL, "/v1/check/external", "unknown.bin", []byte("not analyzed"), clientKey))
	if result["action"] != "review" {
		t.Fatalf("unsupported=%v", result)
	}
	if result["model_status"] != "disabled" {
		t.Fatalf("model=%v", result)
	}
	result = bodyJSON(t, upload(t, srv.URL, "/v1/check/external", "blank.txt", []byte("  \n\t"), clientKey))
	if result["action"] != "review" {
		t.Fatalf("blank=%v", result)
	}
}
