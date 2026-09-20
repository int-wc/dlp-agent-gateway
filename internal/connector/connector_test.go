package connector

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/int-wc/dlp-agent-gateway/internal/config"
)

func TestForwardUsesConfiguredCredentialAndUploadField(t *testing.T) {
	const token = "synthetic-upstream-credential"
	t.Setenv("TEST_UPSTREAM_TOKEN", token)
	var received []byte
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("X-DLP-Audit-ID") != "42" {
			t.Errorf("unexpected headers: %v", r.Header)
		}
		file, _, err := r.FormFile("document")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		received, _ = io.ReadAll(file)
		w.WriteHeader(http.StatusCreated)
	}))
	defer receiver.Close()
	destination := config.Destination{Kind: "internal", URL: receiver.URL, CredentialEnv: "TEST_UPSTREAM_TOKEN", UploadField: "document"}
	client, err := New(map[string]config.Destination{"business": destination})
	if err != nil {
		t.Fatal(err)
	}
	status, reason := client.Forward(context.Background(), "business", destination, "synthetic.txt", []byte("synthetic content"), 42)
	if status != http.StatusCreated || reason != "" || string(received) != "synthetic content" {
		t.Fatalf("status=%d reason=%q received=%q", status, reason, received)
	}
}

func TestConnectorRejectsMissingConfiguredCredential(t *testing.T) {
	destination := config.Destination{Kind: "external", URL: "https://example.test/upload", CredentialEnv: "MISSING_TEST_TOKEN"}
	if _, err := New(map[string]config.Destination{"business": destination}); err == nil {
		t.Fatal("empty credential environment variable was accepted")
	}
}
