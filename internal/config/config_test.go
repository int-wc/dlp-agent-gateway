package config

import "testing"

func validTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DLP_ADMIN_KEY", "admin-config-test-20260918-abcdefghijklmnopqrstuvwxyz")
	t.Setenv("DLP_CLIENT_KEYS_JSON", `{"demo-user":"client-config-test-20260918-abcdefghijklmnopqrstuvwxyz"}`)
	t.Setenv("DLP_DESTINATIONS_JSON", `{"external":{"kind":"external"}}`)
	t.Setenv("DLP_OLLAMA_MODEL", "")
}

func TestAnalyzerURLAllowsOnlyLocalOrIsolatedService(t *testing.T) {
	validTestEnv(t)
	t.Setenv("DLP_ANALYZER_URL", "http://analyzer:19090")
	if _, err := Load(); err != nil {
		t.Fatalf("isolated analyzer rejected: %v", err)
	}

	t.Setenv("DLP_ANALYZER_URL", "https://parser.example.com")
	if _, err := Load(); err == nil {
		t.Fatal("remote analyzer URL accepted")
	}
}

func TestConfigurationRejectsDuplicateCredentials(t *testing.T) {
	validTestEnv(t)
	t.Setenv("DLP_CLIENT_KEYS_JSON", `{"demo-user":"admin-config-test-20260918-abcdefghijklmnopqrstuvwxyz"}`)
	if _, err := Load(); err == nil {
		t.Fatal("duplicate admin/client credential accepted")
	}
}
