package store

import (
	"path/filepath"
	"testing"
)

func TestJSONPolicyRevisionsPersistAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	created, err := first.AddPolicy(Policy{Keyword: "synthetic-orbit", Action: "review", Scope: "external", Mode: "monitor"}, "synthetic-admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.UpdatePolicy(created.ID, Policy{Keyword: "synthetic-orbit", Action: "block", Scope: "external", Mode: "enforce"}, 1, "synthetic-admin"); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	versions, err := reopened.PolicyVersions(created.ID)
	if err != nil || len(versions) != 2 || versions[0].Version != 2 || versions[1].Version != 1 {
		t.Fatalf("versions=%v err=%v", versions, err)
	}
	restored, err := reopened.RollbackPolicy(created.ID, 1, 2, "synthetic-admin")
	if err != nil || restored.Version != 3 || restored.Mode != "monitor" {
		t.Fatalf("restored=%v err=%v", restored, err)
	}
}
