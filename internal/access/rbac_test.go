package access

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestRBACRoleBoundaries(t *testing.T) {
	rbac, err := NewRBAC()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		role, path, method string
		want               bool
	}{
		{"viewer", "/v1/admin/audits", "GET", true},
		{"viewer", "/v1/admin/audits/1/feedback", "PUT", false},
		{"operator", "/v1/admin/audits/1/feedback", "PUT", true},
		{"viewer", "/v1/admin/incidents/1/notes", "POST", false},
		{"operator", "/v1/admin/incidents/1", "PUT", true},
		{"operator", "/v1/admin/incidents/1/notes", "POST", true},
		{"operator", "/v1/admin/policies", "POST", false},
		{"admin", "/v1/admin/policies", "POST", true},
		{"admin", "/v1/admin/users/demo", "PUT", true},
	}
	for _, test := range tests {
		if got := rbac.Allowed(test.role, test.path, test.method); got != test.want {
			t.Errorf("Allowed(%q,%q,%q)=%v want %v", test.role, test.path, test.method, got, test.want)
		}
	}
}

func TestOIDCRoleMappingUsesHighestKnownRole(t *testing.T) {
	manager := &Manager{roleClaim: "roles", adminRole: "dlp-admin", operatorRole: "dlp-operator", viewerRole: "dlp-viewer"}
	if role := manager.roleFromClaims(map[string]any{"roles": []any{"unrelated", "dlp-viewer", "dlp-operator"}}); role != "operator" {
		t.Fatalf("role=%q", role)
	}
	if role := manager.roleFromClaims(map[string]any{"roles": []any{"dlp-admin", "dlp-viewer"}}); role != "admin" {
		t.Fatalf("role=%q", role)
	}
	if role := manager.roleFromClaims(map[string]any{"roles": "unrelated"}); role != "" {
		t.Fatalf("unexpected role=%q", role)
	}
}

func TestMTLSActorUsesOnlyVerifiedCertificates(t *testing.T) {
	spiffe, _ := url.Parse("spiffe://example.test/workload/uploader")
	certificate := &x509.Certificate{URIs: []*url.URL{spiffe}, DNSNames: []string{"uploader.example.test"}, Subject: pkix.Name{CommonName: "fallback"}}
	request := httptest.NewRequest("POST", "https://gateway.example.test/v1/check/external", nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	if _, ok := MTLSActor(request, map[string]string{"uri:" + spiffe.String(): "business-uploader"}); ok {
		t.Fatal("unverified peer certificate was trusted")
	}
	request.TLS.VerifiedChains = [][]*x509.Certificate{{certificate}}
	actor, ok := MTLSActor(request, map[string]string{"uri:" + spiffe.String(): "business-uploader"})
	if !ok || actor != "business-uploader" {
		t.Fatalf("verified identity actor=%q ok=%v", actor, ok)
	}
}
