package connector

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/int-wc/dlp-agent-gateway/internal/config"
)

type target struct {
	client      *http.Client
	bearerToken string
}

// Connector owns the allowlisted downstream transports. It never accepts a
// caller-provided URL and does not follow redirects.
type Connector struct {
	targets map[string]target
}

func New(destinations map[string]config.Destination) (*Connector, error) {
	result := &Connector{targets: map[string]target{}}
	for name, destination := range destinations {
		if destination.URL == "" {
			continue
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if destination.CAFile != "" {
			pem, err := os.ReadFile(destination.CAFile)
			if err != nil {
				return nil, fmt.Errorf("destination %s CA: %w", name, err)
			}
			roots, err := x509.SystemCertPool()
			if err != nil || roots == nil {
				roots = x509.NewCertPool()
			}
			if !roots.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("destination %s CA contains no certificate", name)
			}
			transport.TLSClientConfig.RootCAs = roots
		}
		if destination.ClientCertFile != "" {
			certificate, err := tls.LoadX509KeyPair(destination.ClientCertFile, destination.ClientKeyFile)
			if err != nil {
				return nil, fmt.Errorf("destination %s client certificate: %w", name, err)
			}
			transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
		}
		bearerToken := ""
		if destination.CredentialEnv != "" {
			bearerToken = os.Getenv(destination.CredentialEnv)
			if bearerToken == "" {
				return nil, fmt.Errorf("destination %s credential environment variable is empty", name)
			}
		}
		result.targets[name] = target{client: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}, bearerToken: bearerToken}
	}
	return result, nil
}

func (c *Connector) Forward(ctx context.Context, name string, destination config.Destination, filename string, data []byte, auditID int64) (int, string) {
	configured, ok := c.targets[name]
	if !ok || destination.URL == "" {
		return 0, "forwarding_not_configured"
	}
	field := destination.UploadField
	if field == "" {
		field = "file"
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile(field, filename)
	if err != nil {
		return 0, "multipart_build_failed"
	}
	if _, err = part.Write(data); err != nil {
		return 0, "multipart_build_failed"
	}
	if err = writer.Close(); err != nil {
		return 0, "multipart_build_failed"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, destination.URL, &body)
	if err != nil {
		return 0, "upstream_request_failed"
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-DLP-Audit-ID", strconv.FormatInt(auditID, 10))
	if configured.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+configured.bearerToken)
	}
	response, err := configured.client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return 0, "upstream_timeout"
		}
		return 0, "upstream_unavailable"
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, "upstream_rejected"
	}
	return response.StatusCode, ""
}
