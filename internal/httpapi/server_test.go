package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/int-wc/dlp-agent-gateway/internal/config"
	"github.com/int-wc/dlp-agent-gateway/internal/policy"
	"github.com/int-wc/dlp-agent-gateway/internal/store"
)

const clientKey = "client-go-smoke-key-20260918-abcdefghijklmnopqrstuvwxyz"
const adminKey = "admin-go-smoke-key-20260918-abcdefghijklmnopqrstuvwxyz"

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.json")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{AdminKey: adminKey, ClientKeys: map[string]string{"demo-user": clientKey}, Destinations: map[string]config.Destination{"external": {Kind: "external"}, "internal": {Kind: "internal"}}, DBPath: path, ConsolePath: filepath.Join("..", "..", "dlp_gateway", "console.html"), ListenAddress: "127.0.0.1:0"}
	srv := httptest.NewServer(New(cfg, db, policy.New(cfg)).Handler())
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

func TestGoGatewayHealthAndFailClosedDecisions(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	health := bodyJSON(t, resp)
	if health["status"] != "ok" {
		t.Fatalf("health=%v", health)
	}
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
	cfg := config.Config{AdminKey: adminKey, ClientKeys: map[string]string{"demo-user": clientKey}, Destinations: map[string]config.Destination{"internal": {Kind: "internal", URL: receiver.URL}}, DBPath: path, ConsolePath: filepath.Join("..", "..", "dlp_gateway", "console.html")}
	gateway := httptest.NewServer(New(cfg, db, policy.New(cfg)).Handler())
	defer gateway.Close()
	defer db.Close()

	safe := []byte("synthetic safe bytes")
	result := bodyJSON(t, upload(t, gateway.URL, "/v1/forward/internal", "safe.txt", safe, clientKey))
	if result["forwarded"] != true || !bytes.Equal(received, safe) {
		t.Fatalf("forward result=%v received=%q", result, received)
	}
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
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
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
