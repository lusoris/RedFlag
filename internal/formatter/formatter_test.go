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
	if len(post.Labels) < 2 {
		t.Error("expected at least 2 labels (security + app name)")
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

func TestFormatResolutionComment(t *testing.T) {
	cves := []string{"CVE-2024-0001", "CVE-2024-0002"}
	comment := FormatResolutionComment("Tdarr", cves)

	if !strings.Contains(comment, "Resolved in Tdarr") {
		t.Error("comment should mention app name")
	}
	if !strings.Contains(comment, "~CVE-2024-0001~") {
		t.Error("comment should contain strikethrough CVE")
	}
	if !strings.Contains(comment, "2 vulnerabilities") {
		t.Error("comment should mention count")
	}
}

func TestFormatResolutionCommentSingular(t *testing.T) {
	cves := []string{"CVE-2024-0001"}
	comment := FormatResolutionComment("App", cves)

	if !strings.Contains(comment, "1 vulnerability") {
		t.Error("comment should use singular form for 1 CVE")
	}
}

func TestFormatTitleExported(t *testing.T) {
	title := FormatTitle("Sonarr", 2, 3)
	expected := "[Security] Sonarr — 2 Critical, 3 High vulnerabilities found"
	if title != expected {
		t.Errorf("expected %q, got %q", expected, title)
	}
}
