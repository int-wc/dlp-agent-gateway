package access

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"

	"github.com/int-wc/dlp-agent-gateway/internal/config"
)

func MTLSActor(r *http.Request, mappings map[string]string) (string, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	certificate := r.TLS.PeerCertificates[0]
	for _, uri := range certificate.URIs {
		if actor, ok := mappings["uri:"+uri.String()]; ok {
			return actor, true
		}
	}
	for _, name := range certificate.DNSNames {
		if actor, ok := mappings["dns:"+name]; ok {
			return actor, true
		}
	}
	for _, email := range certificate.EmailAddresses {
		if actor, ok := mappings["email:"+email]; ok {
			return actor, true
		}
	}
	if actor, ok := mappings["cn:"+certificate.Subject.CommonName]; ok {
		return actor, true
	}
	return "", false
}

func ServerTLSConfig(cfg config.Config) (*tls.Config, error) {
	result := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.ClientCAFile == "" {
		return result, nil
	}
	pem, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("DLP_CLIENT_CA_FILE contains no certificate")
	}
	result.ClientCAs = roots
	// Client certificates are requested and verified when supplied. Upload
	// handlers enforce DLP_REQUIRE_MTLS without preventing OIDC browser login.
	result.ClientAuth = tls.VerifyClientCertIfGiven
	return result, nil
}
