package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "images.yaml")

	content := `images:
  - name: testapp
    image: testorg/testapp:latest
  - name: otherapp
    image: ghcr.io/org/otherapp:latest
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Images) != 2 {
		t.Fatalf("expected 2 images, got %d", len(cfg.Images))
	}

	if cfg.Images[0].Name != "testapp" {
		t.Errorf("expected name 'testapp', got %q", cfg.Images[0].Name)
	}
	if cfg.Images[0].Image != "testorg/testapp:latest" {
		t.Errorf("expected image 'testorg/testapp:latest', got %q", cfg.Images[0].Image)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadEmptyImages(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "images.yaml")
	if err := os.WriteFile(path, []byte("images: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for empty images")
	}
}

func TestLoadMissingFields(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		content string
	}{
		{"no image", "images:\n  - name: foo\n"},
		{"no name", "images:\n  - image: foo/bar:latest\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".yaml")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
