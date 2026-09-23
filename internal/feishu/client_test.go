package feishu

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchProjectsSelectedAuditEventsAndPaginates(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open-apis/auth/v3/tenant_access_token/internal":
			var body map[string]string
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil || body["app_id"] != "synthetic-app" || body["app_secret"] != "synthetic-secret" {
				t.Errorf("invalid token request")
			}
			_, _ = w.Write([]byte(`{"code":0,"tenant_access_token":"synthetic-token","expire":7200}`))
		case "/open-apis/admin/v1/audit_infos":
			requests++
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer synthetic-token" || r.URL.Query().Get("page_size") != "200" || r.URL.Query().Get("user_id_type") != "open_id" || r.URL.Query().Get("oldest") == "" || r.URL.Query().Get("latest") == "" {
				t.Errorf("invalid audit request")
			}
			if r.URL.Query().Get("page_token") == "" {
				_, _ = w.Write([]byte(`{"code":0,"data":{"has_more":true,"page_token":"next","items":[{"unique_id":"synthetic-1","event_name":"space_export_doc","event_module":1,"operator_type":1,"operator_value":"ou_synthetic","event_time":1700000000,"objects":[{"object_type":"106","object_value":"doc_synthetic","object_name":"ignored title"}],"ip":"ignored"},{"unique_id":"synthetic-2","event_name":"space_read_doc","event_time":1700000001}]}}`))
			} else {
				_, _ = w.Write([]byte(`{"code":0,"data":{"has_more":false,"items":[{"unique_id":"synthetic-3","event_name":"im_forward_file","event_module":2,"operator_type":1,"operator_value":"ou_synthetic","event_time":1700000002}]}}`))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := New("synthetic-app", "synthetic-secret")
	if err != nil {
		t.Fatal(err)
	}
	client.baseURL = server.URL
	start := time.Unix(1699999900, 0)
	items, pages, err := client.Fetch(context.Background(), start, start.Add(time.Hour))
	if err != nil || pages != 2 || requests != 2 || len(items) != 2 {
		t.Fatalf("items=%v pages=%d requests=%d err=%v", items, pages, requests, err)
	}
	if items[0].UniqueID != "synthetic-1" || items[0].ObjectValue != "doc_synthetic" || items[1].EventName != "im_forward_file" {
		t.Fatalf("projected items=%v", items)
	}
	raw, _ := json.Marshal(items)
	if strings.Contains(string(raw), "ignored title") || strings.Contains(string(raw), "ignored") {
		t.Fatalf("unwanted provider fields retained: %s", raw)
	}
}

func TestTokenErrorDoesNotExposeSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("synthetic-secret"))
	}))
	defer server.Close()
	client, err := New("synthetic-app", "synthetic-secret")
	if err != nil {
		t.Fatal(err)
	}
	client.baseURL = server.URL
	_, _, err = client.Fetch(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err == nil || strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatalf("unexpected error: %v", err)
	}
}
