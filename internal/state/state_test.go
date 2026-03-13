package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadNonexistent(t *testing.T) {
	s, err := Load("/nonexistent/state.json")
	if err != nil {
		t.Fatalf("expected empty store for missing file, got error: %v", err)
	}
	if len(s) != 0 {
		t.Fatalf("expected empty store, got %d entries", len(s))
	}
}

func TestLoadEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s) != 0 {
		t.Fatalf("expected empty store, got %d entries", len(s))
	}
}

func TestSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := make(Store)
	is := s.GetOrCreate("testorg/testapp:latest")
	is.MarkPosted("CVE-2024-1234", "homelab", "https://reddit.com/r/homelab/abc", 0)

	if err := s.Save(path); err != nil {
		t.Fatalf("save error: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load error: %v", err)
	}

	is2, ok := loaded["testorg/testapp:latest"]
	if !ok {
		t.Fatal("expected image state to exist after reload")
	}
	if !is2.IsPosted("CVE-2024-1234") {
		t.Error("expected CVE-2024-1234 to be marked as posted")
	}
	if is2.IsPosted("CVE-9999-0000") {
		t.Error("expected CVE-9999-0000 to not be marked as posted")
	}
}

func TestGetOrCreate(t *testing.T) {
	s := make(Store)

	is1 := s.GetOrCreate("img:latest")
	is1.MarkPosted("CVE-1", "test", "", 0)

	is2 := s.GetOrCreate("img:latest")
	if !is2.IsPosted("CVE-1") {
		t.Error("expected same ImageState to be returned for same key")
	}
}

func TestMarkResolved(t *testing.T) {
	is := &ImageState{
		PostedCVEs: make(map[string]SubredditStatus),
	}
	is.MarkPosted("CVE-1", "github", "https://example.com", 42)
	is.MarkResolved("CVE-1")

	s := is.PostedCVEs["CVE-1"]
	if !s.Resolved {
		t.Error("expected CVE to be marked as resolved")
	}
	if s.ResolvedAt.IsZero() {
		t.Error("expected ResolvedAt to be set")
	}
}

func TestIssueNumber(t *testing.T) {
	is := &ImageState{
		PostedCVEs: make(map[string]SubredditStatus),
	}
	is.MarkPosted("CVE-1", "github", "", 42)

	if n := is.IssueNumber("CVE-1"); n != 42 {
		t.Errorf("expected issue number 42, got %d", n)
	}
	if n := is.IssueNumber("CVE-NONE"); n != 0 {
		t.Errorf("expected issue number 0 for unknown CVE, got %d", n)
	}
}

func TestActiveCVECount(t *testing.T) {
	is := &ImageState{
		PostedCVEs: make(map[string]SubredditStatus),
	}
	is.MarkPosted("CVE-1", "github", "", 1)
	is.MarkPosted("CVE-2", "github", "", 1)
	is.MarkPosted("CVE-3", "github", "", 1)
	is.MarkResolved("CVE-2")

	if c := is.ActiveCVECount(); c != 2 {
		t.Errorf("expected 2 active CVEs, got %d", c)
	}
}
