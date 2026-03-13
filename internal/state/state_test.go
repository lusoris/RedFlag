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
	is.MarkPosted("CVE-2024-1234", "homelab", "https://reddit.com/r/homelab/abc")

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
	is1.MarkPosted("CVE-1", "test", "")

	is2 := s.GetOrCreate("img:latest")
	if !is2.IsPosted("CVE-1") {
		t.Error("expected same ImageState to be returned for same key")
	}
}
