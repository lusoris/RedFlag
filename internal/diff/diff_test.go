package diff

import (
	"testing"

	"github.com/lusoris/redflag/internal/scanner"
	"github.com/lusoris/redflag/internal/state"
)

func TestNewAllNew(t *testing.T) {
	scan := &scanner.ScanResult{
		Image: "test:latest",
		Vulnerabilities: []scanner.Vulnerability{
			{VulnerabilityID: "CVE-2024-0001", Severity: "CRITICAL"},
			{VulnerabilityID: "CVE-2024-0002", Severity: "HIGH"},
		},
	}

	is := &state.ImageState{
		PostedCVEs: make(map[string]state.SubredditStatus),
	}

	result := New(scan, is)
	if len(result.NewVulns) != 2 {
		t.Fatalf("expected 2 new vulns, got %d", len(result.NewVulns))
	}
	if !result.HasNew() {
		t.Error("expected HasNew to be true")
	}
}

func TestNewSomeAlreadyPosted(t *testing.T) {
	scan := &scanner.ScanResult{
		Image: "test:latest",
		Vulnerabilities: []scanner.Vulnerability{
			{VulnerabilityID: "CVE-2024-0001", Severity: "CRITICAL"},
			{VulnerabilityID: "CVE-2024-0002", Severity: "HIGH"},
			{VulnerabilityID: "CVE-2024-0003", Severity: "HIGH"},
		},
	}

	is := &state.ImageState{
		PostedCVEs: make(map[string]state.SubredditStatus),
	}
	is.MarkPosted("CVE-2024-0001", "homelab", "")
	is.MarkPosted("CVE-2024-0003", "homelab", "")

	result := New(scan, is)
	if len(result.NewVulns) != 1 {
		t.Fatalf("expected 1 new vuln, got %d", len(result.NewVulns))
	}
	if result.NewVulns[0].VulnerabilityID != "CVE-2024-0002" {
		t.Errorf("expected CVE-2024-0002, got %s", result.NewVulns[0].VulnerabilityID)
	}
}

func TestNewNoneNew(t *testing.T) {
	scan := &scanner.ScanResult{
		Image: "test:latest",
		Vulnerabilities: []scanner.Vulnerability{
			{VulnerabilityID: "CVE-2024-0001", Severity: "CRITICAL"},
		},
	}

	is := &state.ImageState{
		PostedCVEs: make(map[string]state.SubredditStatus),
	}
	is.MarkPosted("CVE-2024-0001", "homelab", "")

	result := New(scan, is)
	if result.HasNew() {
		t.Error("expected no new vulns")
	}
}

func TestNewEmptyScan(t *testing.T) {
	scan := &scanner.ScanResult{
		Image:           "test:latest",
		Vulnerabilities: nil,
	}

	is := &state.ImageState{
		PostedCVEs: make(map[string]state.SubredditStatus),
	}

	result := New(scan, is)
	if result.HasNew() {
		t.Error("expected no new vulns for empty scan")
	}
}
