package diff

import (
	"github.com/lusoris/redflag/internal/scanner"
	"github.com/lusoris/redflag/internal/state"
)

// Result holds the new vulnerabilities that haven't been posted yet.
type Result struct {
	Image    string
	NewVulns []scanner.Vulnerability
}

// New computes which vulnerabilities from the scan haven't been posted yet.
func New(scanResult *scanner.ScanResult, imageState *state.ImageState) *Result {
	r := &Result{
		Image: scanResult.Image,
	}

	for _, v := range scanResult.Vulnerabilities {
		if !imageState.IsPosted(v.VulnerabilityID) {
			r.NewVulns = append(r.NewVulns, v)
		}
	}

	return r
}

// HasNew returns true if there are new vulnerabilities to report.
func (r *Result) HasNew() bool {
	return len(r.NewVulns) > 0
}
