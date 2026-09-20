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

func TestConfigurationAcceptsPostgresOIDCAndMTLS(t *testing.T) {
	validTestEnv(t)
	t.Setenv("DLP_DATABASE_URL", "postgres://dlp:synthetic@database:5432/dlp?sslmode=disable")
	t.Setenv("DLP_MTLS_ACTORS_JSON", `{"uri:spiffe://example.test/workload/uploader":"business-uploader"}`)
	t.Setenv("DLP_OIDC_ISSUER_URL", "https://identity.example.test/realms/security")
	t.Setenv("DLP_OIDC_CLIENT_ID", "dlp-console")
	t.Setenv("DLP_OIDC_CLIENT_SECRET", "synthetic-client-secret")
	t.Setenv("DLP_OIDC_REDIRECT_URL", "https://gateway.example.test/auth/callback")
	t.Setenv("DLP_SESSION_SECRET", "synthetic-session-secret-at-least-32-characters")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StorageBackend() != "postgresql" || !cfg.OIDCEnabled() || cfg.Actors()["business-uploader"] != "mtls" {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestConfigurationRejectsIncompleteSecurityModes(t *testing.T) {
	validTestEnv(t)
	t.Setenv("DLP_OIDC_ISSUER_URL", "https://identity.example.test")
	if _, err := Load(); err == nil {
		t.Fatal("incomplete OIDC configuration accepted")
	}
	validTestEnv(t)
	t.Setenv("DLP_REQUIRE_MTLS", "true")
	if _, err := Load(); err == nil {
		t.Fatal("mTLS requirement without CA/mappings accepted")
	}
}
