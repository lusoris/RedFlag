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
	is.MarkPosted("CVE-2024-0001", "homelab", "", 1)
	is.MarkPosted("CVE-2024-0003", "homelab", "", 1)

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
	is.MarkPosted("CVE-2024-0001", "homelab", "", 1)

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

func TestResolvedCVEs(t *testing.T) {
	// State has 3 CVEs posted, scan only returns 1 — the other 2 are resolved
	scan := &scanner.ScanResult{
		Image: "test:latest",
		Vulnerabilities: []scanner.Vulnerability{
			{VulnerabilityID: "CVE-2024-0001", Severity: "CRITICAL"},
		},
	}

	is := &state.ImageState{
		PostedCVEs: make(map[string]state.SubredditStatus),
	}
	is.MarkPosted("CVE-2024-0001", "github", "", 1)
	is.MarkPosted("CVE-2024-0002", "github", "", 1)
	is.MarkPosted("CVE-2024-0003", "github", "", 1)

	result := New(scan, is)
	if result.HasNew() {
		t.Error("expected no new vulns")
	}
	if !result.HasResolved() {
		t.Fatal("expected resolved CVEs")
	}
	if len(result.ResolvedCVEs) != 2 {
		t.Fatalf("expected 2 resolved CVEs, got %d", len(result.ResolvedCVEs))
	}
}

func TestAlreadyResolvedNotReported(t *testing.T) {
	scan := &scanner.ScanResult{
		Image:           "test:latest",
		Vulnerabilities: nil,
	}

	is := &state.ImageState{
		PostedCVEs: make(map[string]state.SubredditStatus),
	}
	is.MarkPosted("CVE-2024-0001", "github", "", 1)
	is.MarkResolved("CVE-2024-0001")

	result := New(scan, is)
	if result.HasResolved() {
		t.Error("already-resolved CVEs should not be reported again")
	}
}
