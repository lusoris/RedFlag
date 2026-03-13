package formatter

import (
	"strings"
	"testing"

	"github.com/lusoris/redflag/internal/scanner"
)

func TestFormatPostTitle(t *testing.T) {
	vulns := []scanner.Vulnerability{
		{VulnerabilityID: "CVE-2024-0001", Severity: "CRITICAL", PkgName: "openssl", InstalledVersion: "1.1.1", FixedVersion: "1.1.2"},
		{VulnerabilityID: "CVE-2024-0002", Severity: "HIGH", PkgName: "curl", InstalledVersion: "7.88", FixedVersion: "7.89"},
		{VulnerabilityID: "CVE-2024-0003", Severity: "HIGH", PkgName: "zlib", InstalledVersion: "1.2.11", FixedVersion: "1.2.13"},
	}

	post := FormatPost("Tdarr", "haveagitgat/tdarr:latest", vulns)

	expected := "[Security] Tdarr — 1 Critical, 2 High vulnerabilities found"
	if post.Title != expected {
		t.Errorf("expected title %q, got %q", expected, post.Title)
	}
}

func TestFormatPostSingleVuln(t *testing.T) {
	vulns := []scanner.Vulnerability{
		{VulnerabilityID: "CVE-2024-9999", Severity: "CRITICAL", PkgName: "libssh2", InstalledVersion: "1.10.0", FixedVersion: "1.11.0"},
	}

	post := FormatPost("FileFlows", "revenz/fileflows:latest", vulns)

	if !strings.Contains(post.Title, "1 Critical vulnerability found") {
		t.Errorf("expected singular 'vulnerability', got title: %s", post.Title)
	}
}

func TestFormatPostBodyContainsCVE(t *testing.T) {
	vulns := []scanner.Vulnerability{
		{VulnerabilityID: "CVE-2024-0001", Severity: "CRITICAL", PkgName: "openssl", InstalledVersion: "1.1.1", FixedVersion: "1.1.2", PrimaryURL: "https://example.com/cve"},
	}

	post := FormatPost("Test", "test:latest", vulns)

	if !strings.Contains(post.Body, "CVE-2024-0001") {
		t.Error("body should contain CVE ID")
	}
	if !strings.Contains(post.Body, "openssl") {
		t.Error("body should contain package name")
	}
	if !strings.Contains(post.Body, "https://example.com/cve") {
		t.Error("body should contain primary URL")
	}
	if !strings.Contains(post.Body, "RedFlag") {
		t.Error("body should contain RedFlag attribution")
	}
}

func TestFormatPostNoFixVersion(t *testing.T) {
	vulns := []scanner.Vulnerability{
		{VulnerabilityID: "CVE-2024-0001", Severity: "HIGH", PkgName: "pkg", InstalledVersion: "1.0"},
	}

	post := FormatPost("App", "app:latest", vulns)

	if !strings.Contains(post.Body, "No fix") {
		t.Error("body should show 'No fix' when FixedVersion is empty")
	}
}
