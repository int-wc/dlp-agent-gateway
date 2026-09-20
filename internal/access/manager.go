package access

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	sessionCookie = "dlp_session"
	stateCookie   = "dlp_oidc_state"
)

type Identity struct {
	Subject string `json:"subject"`
	Name    string `json:"name,omitempty"`
	Email   string `json:"email,omitempty"`
	Role    string `json:"role"`
}

type Options struct {
	IssuerURL     string
	ClientID      string
	Secret        string
	RedirectURL   string
	RoleClaim     string
	AdminRole     string
	OperatorRole  string
	ViewerRole    string
	SessionSecret string
	CookieSecure  bool
}

type Manager struct {
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
	roleClaim    string
	adminRole    string
	operatorRole string
	viewerRole   string
	signingKey   []byte
	cookieSecure bool
}

type sessionPayload struct {
	Identity
	Expires int64 `json:"expires"`
}

type statePayload struct {
	State    string `json:"state"`
	Verifier string `json:"verifier"`
	Expires  int64  `json:"expires"`
}

func New(ctx context.Context, options Options) (*Manager, error) {
	if options.IssuerURL == "" {
		return nil, nil
	}
	provider, err := oidc.NewProvider(ctx, options.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}
	return &Manager{
		verifier: provider.Verifier(&oidc.Config{ClientID: options.ClientID}),
		oauth2Config: oauth2.Config{
			ClientID: options.ClientID, ClientSecret: options.Secret,
			Endpoint: provider.Endpoint(), RedirectURL: options.RedirectURL,
			Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
		},
		roleClaim: options.RoleClaim, adminRole: options.AdminRole,
		operatorRole: options.OperatorRole, viewerRole: options.ViewerRole,
		signingKey: []byte(options.SessionSecret), cookieSecure: options.CookieSecure,
	}, nil
}

func (m *Manager) Login(w http.ResponseWriter, r *http.Request) {
	if m == nil {
		http.Error(w, "oidc_not_configured", http.StatusNotFound)
		return
	}
	state, err := randomToken(24)
	if err != nil {
		http.Error(w, "login_failed", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	payload := statePayload{State: state, Verifier: verifier, Expires: time.Now().Add(10 * time.Minute).Unix()}
	m.setSignedCookie(w, stateCookie, payload, 10*time.Minute)
	http.Redirect(w, r, m.oauth2Config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (m *Manager) Callback(w http.ResponseWriter, r *http.Request) {
	if m == nil {
		http.Error(w, "oidc_not_configured", http.StatusNotFound)
		return
	}
	var state statePayload
	if !m.readSignedCookie(r, stateCookie, &state) || state.Expires < time.Now().Unix() || !hmac.Equal([]byte(state.State), []byte(r.URL.Query().Get("state"))) {
		http.Error(w, "invalid_oidc_state", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing_oidc_code", http.StatusBadRequest)
		return
	}
	token, err := m.oauth2Config.Exchange(r.Context(), code, oauth2.VerifierOption(state.Verifier))
	if err != nil {
		http.Error(w, "oidc_exchange_failed", http.StatusUnauthorized)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "oidc_id_token_missing", http.StatusUnauthorized)
		return
	}
	identity, expires, err := m.identityFromToken(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "oidc_identity_rejected", http.StatusForbidden)
		return
	}
	maxExpiry := time.Now().Add(8 * time.Hour)
	if expires.Before(maxExpiry) {
		maxExpiry = expires
	}
	m.setSignedCookie(w, sessionCookie, sessionPayload{Identity: identity, Expires: maxExpiry.Unix()}, time.Until(maxExpiry))
	m.clearCookie(w, stateCookie)
	http.Redirect(w, r, "/console/#dashboard", http.StatusFound)
}

func (m *Manager) Logout(w http.ResponseWriter, r *http.Request) {
	if m != nil {
		m.clearCookie(w, sessionCookie)
	}
	http.Redirect(w, r, "/console/", http.StatusFound)
}

func (m *Manager) Identity(r *http.Request) (Identity, bool) {
	if m == nil {
		return Identity{}, false
	}
	var payload sessionPayload
	if m.readSignedCookie(r, sessionCookie, &payload) && payload.Expires > time.Now().Unix() {
		return payload.Identity, true
	}
	if token, ok := bearer(r); ok {
		identity, _, err := m.identityFromToken(r.Context(), token)
		return identity, err == nil
	}
	return Identity{}, false
}

func (m *Manager) identityFromToken(ctx context.Context, raw string) (Identity, time.Time, error) {
	token, err := m.verifier.Verify(ctx, raw)
	if err != nil {
		return Identity{}, time.Time{}, err
	}
	claims := map[string]any{}
	if err := token.Claims(&claims); err != nil {
		return Identity{}, time.Time{}, err
	}
	role := m.roleFromClaims(claims)
	if role == "" {
		return Identity{}, time.Time{}, errors.New("no permitted role")
	}
	subject, _ := claims["sub"].(string)
	if subject == "" {
		return Identity{}, time.Time{}, errors.New("subject missing")
	}
	name, _ := claims["name"].(string)
	email, _ := claims["email"].(string)
	return Identity{Subject: subject, Name: name, Email: email, Role: role}, token.Expiry, nil
}

func (m *Manager) roleFromClaims(claims map[string]any) string {
	roles := []string{}
	switch value := claims[m.roleClaim].(type) {
	case string:
		roles = append(roles, value)
	case []any:
		for _, item := range value {
			if role, ok := item.(string); ok {
				roles = append(roles, role)
			}
		}
	case []string:
		roles = append(roles, value...)
	}
	selected := ""
	for _, role := range roles {
		switch role {
		case m.adminRole:
			return "admin"
		case m.operatorRole:
			selected = "operator"
		case m.viewerRole:
			if selected == "" {
				selected = "viewer"
			}
		}
	}
	return selected
}

func (m *Manager) setSignedCookie(w http.ResponseWriter, name string, value any, lifetime time.Duration) {
	raw, _ := json.Marshal(value)
	payload := base64.RawURLEncoding.EncodeToString(raw)
	signature := m.sign(payload)
	maxAge := int(lifetime.Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: payload + "." + signature, Path: "/", HttpOnly: true, Secure: m.cookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

func (m *Manager) readSignedCookie(r *http.Request, name string, target any) bool {
	cookie, err := r.Cookie(name)
	if err != nil {
		return false
	}
	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 2 || !hmac.Equal([]byte(parts[1]), []byte(m.sign(parts[0]))) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	return err == nil && json.Unmarshal(raw, target) == nil
}

func (m *Manager) sign(payload string) string {
	mac := hmac.New(sha256.New, m.signingKey)
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *Manager) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true, Secure: m.cookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func randomToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func bearer(r *http.Request) (string, bool) {
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return "", false
	}
	value = strings.TrimSpace(strings.TrimPrefix(value, "Bearer "))
	return value, value != ""
}
