package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const MaxUploadBytes int64 = 8 * 1024 * 1024

type Destination struct {
	Kind           string `json:"kind"`
	URL            string `json:"url,omitempty"`
	CredentialEnv  string `json:"credential_env,omitempty"`
	UploadField    string `json:"upload_field,omitempty"`
	CAFile         string `json:"ca_file,omitempty"`
	ClientCertFile string `json:"client_cert_file,omitempty"`
	ClientKeyFile  string `json:"client_key_file,omitempty"`
}

type Config struct {
	AdminKey         string
	ClientKeys       map[string]string
	MTLSActors       map[string]string
	Destinations     map[string]Destination
	DBPath           string
	DatabaseURL      string
	AnalyzerURL      string
	OllamaModel      string
	OllamaURL        string
	ListenAddress    string
	TLSCertFile      string
	TLSKeyFile       string
	ClientCAFile     string
	RequireMTLS      bool
	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCSecret       string
	OIDCRedirect     string
	OIDCRoleClaim    string
	OIDCAdminRole    string
	OIDCOperatorRole string
	OIDCViewerRole   string
	SessionSecret    string
	CookieSecure     bool
}

func Load() (Config, error) {
	clients, err := parseObject(os.Getenv("DLP_CLIENT_KEYS_JSON"))
	if err != nil {
		return Config{}, fmt.Errorf("DLP_CLIENT_KEYS_JSON: %w", err)
	}
	mtlsActors, err := parseObject(os.Getenv("DLP_MTLS_ACTORS_JSON"))
	if err != nil {
		return Config{}, fmt.Errorf("DLP_MTLS_ACTORS_JSON: %w", err)
	}
	rawDestinations := os.Getenv("DLP_DESTINATIONS_JSON")
	if rawDestinations == "" {
		rawDestinations = `{"internal-demo":{"kind":"internal"},"external-demo":{"kind":"external"}}`
	}
	destinations, err := parseDestinations(rawDestinations)
	if err != nil {
		return Config{}, fmt.Errorf("DLP_DESTINATIONS_JSON: %w", err)
	}
	cfg := Config{
		AdminKey:         os.Getenv("DLP_ADMIN_KEY"),
		ClientKeys:       clients,
		MTLSActors:       mtlsActors,
		Destinations:     destinations,
		DBPath:           envOr("DLP_DB_PATH", "./var/audit.json"),
		DatabaseURL:      os.Getenv("DLP_DATABASE_URL"),
		AnalyzerURL:      strings.TrimRight(os.Getenv("DLP_ANALYZER_URL"), "/"),
		OllamaModel:      os.Getenv("DLP_OLLAMA_MODEL"),
		OllamaURL:        envOr("DLP_OLLAMA_URL", "http://127.0.0.1:11434/api/generate"),
		ListenAddress:    envOr("DLP_LISTEN_ADDRESS", "127.0.0.1:18080"),
		TLSCertFile:      os.Getenv("DLP_TLS_CERT_FILE"),
		TLSKeyFile:       os.Getenv("DLP_TLS_KEY_FILE"),
		ClientCAFile:     os.Getenv("DLP_CLIENT_CA_FILE"),
		RequireMTLS:      envBool("DLP_REQUIRE_MTLS", false),
		OIDCIssuerURL:    strings.TrimRight(os.Getenv("DLP_OIDC_ISSUER_URL"), "/"),
		OIDCClientID:     os.Getenv("DLP_OIDC_CLIENT_ID"),
		OIDCSecret:       os.Getenv("DLP_OIDC_CLIENT_SECRET"),
		OIDCRedirect:     os.Getenv("DLP_OIDC_REDIRECT_URL"),
		OIDCRoleClaim:    envOr("DLP_OIDC_ROLE_CLAIM", "roles"),
		OIDCAdminRole:    envOr("DLP_OIDC_ADMIN_ROLE", "dlp-admin"),
		OIDCOperatorRole: envOr("DLP_OIDC_OPERATOR_ROLE", "dlp-operator"),
		OIDCViewerRole:   envOr("DLP_OIDC_VIEWER_ROLE", "dlp-viewer"),
		SessionSecret:    os.Getenv("DLP_SESSION_SECRET"),
		CookieSecure:     envBool("DLP_COOKIE_SECURE", true),
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.AdminKey == "" && c.OIDCIssuerURL == "" {
		return errors.New("configure DLP_ADMIN_KEY or OIDC")
	}
	if c.AdminKey != "" && (len(c.AdminKey) < 24 || strings.HasPrefix(c.AdminKey, "replace-")) {
		return errors.New("DLP_ADMIN_KEY must be a random value of at least 24 characters")
	}
	if len(c.ClientKeys) == 0 && len(c.MTLSActors) == 0 {
		return errors.New("configure DLP_CLIENT_KEYS_JSON or DLP_MTLS_ACTORS_JSON")
	}
	seen := map[string]bool{}
	if c.AdminKey != "" {
		seen[c.AdminKey] = true
	}
	for actor, key := range c.ClientKeys {
		if actor == "" || len(actor) > 80 || len(key) < 24 || strings.HasPrefix(key, "replace-") {
			return fmt.Errorf("invalid client actor/key %q", actor)
		}
		if seen[key] {
			return errors.New("admin and client keys must be distinct")
		}
		seen[key] = true
	}
	for identity, actor := range c.MTLSActors {
		if !validMTLSIdentity(identity) || actor == "" || len(actor) > 80 {
			return fmt.Errorf("invalid mTLS identity mapping %q", identity)
		}
	}
	for name, dest := range c.Destinations {
		if name == "" || len(name) > 80 || (dest.Kind != "internal" && dest.Kind != "external") {
			return fmt.Errorf("invalid destination %q", name)
		}
		if dest.URL != "" {
			u, err := url.Parse(dest.URL)
			if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return fmt.Errorf("invalid destination URL for %q", name)
			}
			if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
				return fmt.Errorf("destination %q must use HTTPS or loopback HTTP", name)
			}
			if u.Scheme != "https" && (dest.CAFile != "" || dest.ClientCertFile != "") {
				return fmt.Errorf("destination %q TLS credentials require HTTPS", name)
			}
		} else if dest.CredentialEnv != "" || dest.UploadField != "" || dest.CAFile != "" || dest.ClientCertFile != "" || dest.ClientKeyFile != "" {
			return fmt.Errorf("destination %q connector options require a URL", name)
		}
		if dest.CredentialEnv != "" && !regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`).MatchString(dest.CredentialEnv) {
			return fmt.Errorf("invalid credential_env for destination %q", name)
		}
		if dest.UploadField != "" && (len(dest.UploadField) > 64 || strings.ContainsAny(dest.UploadField, "\r\n")) {
			return fmt.Errorf("invalid upload_field for destination %q", name)
		}
		if (dest.ClientCertFile == "") != (dest.ClientKeyFile == "") {
			return fmt.Errorf("destination %q client certificate and key must be configured together", name)
		}
	}
	if c.AnalyzerURL != "" {
		if err := validateAnalyzerURL(c.AnalyzerURL); err != nil {
			return fmt.Errorf("DLP_ANALYZER_URL: %w", err)
		}
	}
	if c.OllamaModel != "" {
		if err := validateLoopbackHTTP(c.OllamaURL); err != nil {
			return fmt.Errorf("DLP_OLLAMA_URL: %w", err)
		}
	}
	if c.DBPath == "" {
		return errors.New("DLP_DB_PATH cannot be empty")
	}
	if c.DatabaseURL != "" {
		u, err := url.Parse(c.DatabaseURL)
		if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" || u.Path == "" {
			return errors.New("DLP_DATABASE_URL must be a PostgreSQL URL")
		}
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("DLP_TLS_CERT_FILE and DLP_TLS_KEY_FILE must be configured together")
	}
	if c.ClientCAFile != "" && c.TLSCertFile == "" {
		return errors.New("DLP_CLIENT_CA_FILE requires gateway TLS")
	}
	if c.RequireMTLS && (c.ClientCAFile == "" || len(c.MTLSActors) == 0) {
		return errors.New("DLP_REQUIRE_MTLS requires DLP_CLIENT_CA_FILE and DLP_MTLS_ACTORS_JSON")
	}
	if err := c.validateOIDC(); err != nil {
		return err
	}
	return nil
}

func (c Config) EnsureDBDir() error {
	if c.DatabaseURL != "" {
		return nil
	}
	return os.MkdirAll(filepath.Dir(c.DBPath), 0o700)
}

func (c Config) StorageBackend() string {
	if c.DatabaseURL != "" {
		return "postgresql"
	}
	return "json-demo"
}

func (c Config) Actors() map[string]string {
	result := make(map[string]string, len(c.ClientKeys)+len(c.MTLSActors))
	for actor, key := range c.ClientKeys {
		result[actor] = key
	}
	for _, actor := range c.MTLSActors {
		if _, exists := result[actor]; !exists {
			result[actor] = "mtls"
		}
	}
	return result
}

func (c Config) OIDCEnabled() bool { return c.OIDCIssuerURL != "" }

func (c Config) validateOIDC() error {
	values := []string{c.OIDCIssuerURL, c.OIDCClientID, c.OIDCSecret, c.OIDCRedirect, c.SessionSecret}
	configured := false
	for _, value := range values {
		configured = configured || value != ""
	}
	if !configured {
		return nil
	}
	for _, value := range values {
		if value == "" {
			return errors.New("OIDC requires issuer, client ID, client secret, redirect URL, and session secret")
		}
	}
	if len(c.SessionSecret) < 32 || strings.HasPrefix(c.SessionSecret, "replace-") {
		return errors.New("DLP_SESSION_SECRET must contain at least 32 random characters")
	}
	for name, raw := range map[string]string{"issuer": c.OIDCIssuerURL, "redirect": c.OIDCRedirect} {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname()))) {
			return fmt.Errorf("OIDC %s URL must use HTTPS or loopback HTTP", name)
		}
	}
	return nil
}

func parseObject(raw string) (map[string]string, error) {
	result := map[string]string{}
	if raw == "" {
		return result, nil
	}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, err
	}
	return result, nil
}

func parseDestinations(raw string) (map[string]Destination, error) {
	result := map[string]Destination{}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, err
	}
	return result, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func validMTLSIdentity(value string) bool {
	for _, prefix := range []string{"uri:", "dns:", "email:", "cn:"} {
		if strings.HasPrefix(value, prefix) && len(value) > len(prefix) && len(value) <= 260 {
			return !strings.ContainsAny(value, "\r\n")
		}
	}
	return false
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func validateLoopbackHTTP(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || !isLoopback(u.Hostname()) || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be loopback HTTP without credentials/query/fragment")
	}
	return nil
}

func validateAnalyzerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be trusted HTTP without credentials/query/fragment")
	}
	if !isLoopback(u.Hostname()) && u.Hostname() != "analyzer" {
		return errors.New("host must be loopback or the isolated analyzer service")
	}
	return nil
}
