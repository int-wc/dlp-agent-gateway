package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

type Result struct {
	Text         string   `json:"text"`
	Signals      []string `json:"signals"`
	ParserStatus string   `json:"parser_status"`
	ModelStatus  string   `json:"model_status"`
	Risk         string   `json:"risk"`
}

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{
		Timeout:       8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (c *Client) Healthy(ctx context.Context) bool {
	if c.BaseURL == "" {
		return true
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/health", nil)
	if err != nil {
		return false
	}
	response, err := c.HTTP.Do(req)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	return response.StatusCode >= 200 && response.StatusCode < 300
}

func (c *Client) Analyze(ctx context.Context, filename string, data []byte) Result {
	if isText(filename, data) {
		text := string(data)
		if strings.TrimSpace(text) == "" {
			return Result{ParserStatus: "empty", ModelStatus: "skipped"}
		}
		if len([]rune(text)) > 100000 {
			return Result{ParserStatus: "too_large", ModelStatus: "skipped"}
		}
		return Result{Text: text, Signals: Signals(text), ParserStatus: "ok", ModelStatus: "disabled", Risk: "low"}
	}
	if c.BaseURL == "" {
		return Result{ParserStatus: "unavailable", ModelStatus: "skipped"}
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filepath.Base(filename))
	if err != nil {
		return Result{ParserStatus: "unavailable", ModelStatus: "skipped"}
	}
	_, _ = part.Write(data)
	_ = writer.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/analyze", &body)
	if err != nil {
		return Result{ParserStatus: "unavailable", ModelStatus: "skipped"}
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	response, err := c.HTTP.Do(req)
	if err != nil {
		return Result{ParserStatus: "unavailable", ModelStatus: "skipped"}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Result{ParserStatus: "unavailable", ModelStatus: "skipped"}
	}
	var result Result
	if err := json.NewDecoder(io.LimitReader(response.Body, 512*1024)).Decode(&result); err != nil || result.ParserStatus != "ok" || len([]rune(result.Text)) > 100000 {
		return Result{ParserStatus: "unavailable", ModelStatus: "skipped"}
	}
	// The gateway remains the enforcement authority even if a parser worker
	// omits or misclassifies a deterministic signal.
	result.Signals = unique(append(result.Signals, Signals(result.Text)...))
	return result
}

func unique(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func isText(filename string, data []byte) bool {
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return false
	}
	ext := strings.ToLower(filepath.Ext(filename))
	for _, candidate := range []string{".txt", ".md", ".csv", ".json", ".py", ".js", ".ts", ".go", ".java", ".yaml", ".yml", ".log"} {
		if ext == candidate {
			return true
		}
	}
	return false
}

func Signals(text string) []string {
	patterns := []struct {
		name string
		hit  func(string) bool
	}{
		{"private_key", func(v string) bool {
			return strings.Contains(v, "-----BEGIN ") && strings.Contains(v, "PRIVATE KEY-----")
		}},
		{"aws_access_key", func(v string) bool { return hasAWSKey(v) }},
		{"chinese_id_candidate", func(v string) bool { return hasDigits(v, 18) }},
		{"phone_candidate", func(v string) bool { return hasPhone(v) }},
	}
	result := []string{}
	for _, pattern := range patterns {
		if pattern.hit(text) {
			result = append(result, pattern.name)
		}
	}
	return result
}

func hasAWSKey(text string) bool {
	for i := 0; i+20 <= len(text); i++ {
		if text[i:i+4] == "AKIA" {
			valid := true
			for _, ch := range text[i+4 : i+20] {
				if !(ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
					valid = false
				}
			}
			if valid {
				return true
			}
		}
	}
	return false
}

func hasDigits(text string, length int) bool {
	count := 0
	for _, ch := range text {
		if ch >= '0' && ch <= '9' {
			count++
			if count >= length {
				return true
			}
		} else {
			count = 0
		}
	}
	return false
}

func hasPhone(text string) bool {
	for i := 0; i+11 <= len(text); i++ {
		if text[i] == '1' && text[i+1] >= '3' && text[i+1] <= '9' && allDigits(text[i+2:i+11]) {
			return true
		}
	}
	return false
}

func allDigits(text string) bool {
	for _, ch := range text {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
