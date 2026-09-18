package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const MaxUploadBytes int64 = 8 * 1024 * 1024

type Destination struct {
	Kind string `json:"kind"`
	URL  string `json:"url,omitempty"`
}

type Config struct {
	AdminKey      string
	ClientKeys    map[string]string
	Destinations  map[string]Destination
	DBPath        string
	AnalyzerURL   string
	OllamaModel   string
	OllamaURL     string
	ConsolePath   string
	ListenAddress string
}

func Load() (Config, error) {
	clients, err := parseObject(os.Getenv("DLP_CLIENT_KEYS_JSON"))
	if err != nil {
		return Config{}, fmt.Errorf("DLP_CLIENT_KEYS_JSON: %w", err)
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
		AdminKey:      os.Getenv("DLP_ADMIN_KEY"),
		ClientKeys:    clients,
		Destinations:  destinations,
		DBPath:        envOr("DLP_DB_PATH", "./var/audit.json"),
		AnalyzerURL:   strings.TrimRight(os.Getenv("DLP_ANALYZER_URL"), "/"),
		OllamaModel:   os.Getenv("DLP_OLLAMA_MODEL"),
		OllamaURL:     envOr("DLP_OLLAMA_URL", "http://127.0.0.1:11434/api/generate"),
		ConsolePath:   envOr("DLP_CONSOLE_PATH", "./dlp_gateway/console.html"),
		ListenAddress: envOr("DLP_LISTEN_ADDRESS", "127.0.0.1:18080"),
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if len(c.AdminKey) < 24 || strings.HasPrefix(c.AdminKey, "replace-") {
		return errors.New("DLP_ADMIN_KEY must be a random value of at least 24 characters")
	}
	if len(c.ClientKeys) == 0 {
		return errors.New("DLP_CLIENT_KEYS_JSON must contain at least one actor")
	}
	seen := map[string]bool{c.AdminKey: true}
	for actor, key := range c.ClientKeys {
		if actor == "" || len(actor) > 80 || len(key) < 24 || strings.HasPrefix(key, "replace-") {
			return fmt.Errorf("invalid client actor/key %q", actor)
		}
		if seen[key] {
			return errors.New("admin and client keys must be distinct")
		}
		seen[key] = true
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
	return nil
}

func (c Config) EnsureDBDir() error {
	return os.MkdirAll(filepath.Dir(c.DBPath), 0o700)
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
