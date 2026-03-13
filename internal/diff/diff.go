package diff

import (
	"github.com/lusoris/redflag/internal/scanner"
	"github.com/lusoris/redflag/internal/state"
)

// Result holds the new and resolved vulnerabilities from a scan comparison.
type Result struct {
	Image        string
	NewVulns     []scanner.Vulnerability
	ResolvedCVEs []string // CVE IDs that were previously posted but no longer appear
}

// New computes which vulnerabilities from the scan haven't been posted yet,
// and which previously posted CVEs are no longer present (i.e., resolved).
func New(scanResult *scanner.ScanResult, imageState *state.ImageState) *Result {
	r := &Result{
		Image: scanResult.Image,
	}

	// Find new vulnerabilities
	for _, v := range scanResult.Vulnerabilities {
		if !imageState.IsPosted(v.VulnerabilityID) {
			r.NewVulns = append(r.NewVulns, v)
		}
	}

	// Find resolved CVEs: posted previously but not in current scan
	currentCVEs := make(map[string]bool)
	for _, v := range scanResult.Vulnerabilities {
		currentCVEs[v.VulnerabilityID] = true
	}
	for cveID := range imageState.PostedCVEs {
		if imageState.PostedCVEs[cveID].Resolved {
			continue // already resolved
		}
		if !currentCVEs[cveID] {
			r.ResolvedCVEs = append(r.ResolvedCVEs, cveID)
		}
	}

	return r
}

// HasNew returns true if there are new vulnerabilities to report.
func (r *Result) HasNew() bool {
	return len(r.NewVulns) > 0
}

// HasResolved returns true if there are resolved vulnerabilities to report.
func (r *Result) HasResolved() bool {
	return len(r.ResolvedCVEs) > 0
}
