package scanner

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
)

// Vulnerability represents a single CVE from Trivy output.
type Vulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
	PrimaryURL       string `json:"PrimaryURL"`
}

// Result represents a single target's scan results from Trivy.
type Result struct {
	Target          string          `json:"Target"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

// TrivyOutput is the top-level JSON output from trivy image --format json.
type TrivyOutput struct {
	Metadata *Metadata `json:"Metadata,omitempty"`
	Results  []Result  `json:"Results"`
}

// Metadata holds image metadata from Trivy.
type Metadata struct {
	ImageConfig *ImageConfig `json:"ImageConfig,omitempty"`
	RepoDigests []string     `json:"RepoDigests,omitempty"`
}

// ImageConfig holds minimal image config info.
type ImageConfig struct{}

// ScanResult is the processed output of a scan.
type ScanResult struct {
	Image           string
	Digest          string
	Vulnerabilities []Vulnerability
}

// Scan runs trivy against the given image and returns parsed results.
// Only CRITICAL and HIGH severity vulnerabilities are returned.
func Scan(image string) (*ScanResult, error) {
	slog.Info("scanning image", "image", image)

	args := []string{
		"image",
		"--format", "json",
		"--severity", "CRITICAL,HIGH",
		"--quiet",
		image,
	}

	cmd := exec.Command("trivy", args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("trivy exited with code %d: %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("running trivy: %w", err)
	}

	var trivyOut TrivyOutput
	if err := json.Unmarshal(output, &trivyOut); err != nil {
		return nil, fmt.Errorf("parsing trivy output: %w", err)
	}

	result := &ScanResult{
		Image: image,
	}

	if trivyOut.Metadata != nil && len(trivyOut.Metadata.RepoDigests) > 0 {
		result.Digest = trivyOut.Metadata.RepoDigests[0]
	}

	seen := make(map[string]bool)
	for _, r := range trivyOut.Results {
		for _, v := range r.Vulnerabilities {
			if seen[v.VulnerabilityID] {
				continue
			}
			seen[v.VulnerabilityID] = true
			result.Vulnerabilities = append(result.Vulnerabilities, v)
		}
	}

	slog.Info("scan complete", "image", image, "vulns", len(result.Vulnerabilities))
	return result, nil
}
