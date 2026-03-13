package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/lusoris/redflag/internal/config"
	"github.com/lusoris/redflag/internal/diff"
	"github.com/lusoris/redflag/internal/formatter"
	"github.com/lusoris/redflag/internal/notifier"
	"github.com/lusoris/redflag/internal/scanner"
	"github.com/lusoris/redflag/internal/state"
)

func main() {
	configPath := flag.String("config", "images.yaml", "path to images config file")
	statePath := flag.String("state", "state.json", "path to state file")
	ghOwner := flag.String("owner", "", "GitHub repo owner (default: from GITHUB_REPOSITORY)")
	ghRepo := flag.String("repo", "", "GitHub repo name (default: from GITHUB_REPOSITORY)")
	dryRun := flag.Bool("dry-run", false, "print posts to stdout instead of creating GitHub issues")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if err := run(*configPath, *statePath, *ghOwner, *ghRepo, *dryRun); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(configPath, statePath, ghOwner, ghRepo string, dryRun bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	slog.Info("loaded config", "images", len(cfg.Images))

	store, err := state.Load(statePath)
	if err != nil {
		return fmt.Errorf("loading state: %w", err)
	}

	var ghClient *notifier.GitHubClient
	if !dryRun {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			return fmt.Errorf("GITHUB_TOKEN is required (set automatically in GitHub Actions)")
		}
		owner, repo, err := resolveRepo(ghOwner, ghRepo)
		if err != nil {
			return err
		}
		ghClient = notifier.NewGitHubClient(token, owner, repo)
		ghClient.EnsureLabels(map[string]string{
			"security": "d73a4a",
			"critical": "b60205",
			"high":     "d93f0b",
		})
	}

	var anyError bool
	for _, img := range cfg.Images {
		if err := processImage(img, store, ghClient, dryRun); err != nil {
			slog.Error("failed to process image", "image", img.Image, "error", err)
			anyError = true
			continue
		}
	}

	if err := store.Save(statePath); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}
	slog.Info("state saved", "path", statePath)

	if anyError {
		return fmt.Errorf("one or more images failed to process")
	}
	return nil
}

func processImage(img config.ImageEntry, store state.Store, ghClient *notifier.GitHubClient, dryRun bool) error {
	slog.Info("processing", "name", img.Name, "image", img.Image)

	scanResult, err := scanner.Scan(img.Image)
	if err != nil {
		return fmt.Errorf("scanning %s: %w", img.Image, err)
	}

	imageState := store.GetOrCreate(img.Image)
	diffResult := diff.New(scanResult, imageState)

	// Handle resolved CVEs
	if diffResult.HasResolved() {
		slog.Info("resolved vulnerabilities", "image", img.Image, "count", len(diffResult.ResolvedCVEs))
		if err := handleResolved(img, imageState, diffResult, ghClient, dryRun, scanResult); err != nil {
			slog.Error("failed to handle resolved CVEs", "image", img.Image, "error", err)
		}
	}

	// Handle new CVEs
	if diffResult.HasNew() {
		slog.Info("new vulnerabilities found", "image", img.Image, "count", len(diffResult.NewVulns))
		if err := handleNew(img, imageState, diffResult, ghClient, dryRun); err != nil {
			return err
		}
	}

	if !diffResult.HasNew() && !diffResult.HasResolved() {
		slog.Info("no changes", "image", img.Image)
	}

	imageState.LastScan = time.Now().UTC()
	if scanResult.Digest != "" {
		imageState.ImageDigest = scanResult.Digest
	}

	return nil
}

func handleNew(img config.ImageEntry, imageState *state.ImageState, diffResult *diff.Result, ghClient *notifier.GitHubClient, dryRun bool) error {
	post := formatter.FormatPost(img.Name, img.Image, diffResult.NewVulns)

	if dryRun {
		fmt.Printf("\n=== DRY RUN: %s ===\n", img.Name)
		fmt.Printf("Title: %s\n", post.Title)
		fmt.Printf("Labels: %v\n", post.Labels)
		fmt.Printf("Body:\n%s\n", post.Body)
		for _, v := range diffResult.NewVulns {
			imageState.MarkPosted(v.VulnerabilityID, "dry-run", "", 0)
		}
		return nil
	}

	result, err := ghClient.CreateIssue(post.Title, post.Body, post.Labels)
	if err != nil {
		return fmt.Errorf("creating GitHub issue: %w", err)
	}
	slog.Info("created issue", "url", result.URL)

	for _, v := range diffResult.NewVulns {
		imageState.MarkPosted(v.VulnerabilityID, "github", result.URL, result.Number)
	}
	return nil
}

func handleResolved(img config.ImageEntry, imageState *state.ImageState, diffResult *diff.Result, ghClient *notifier.GitHubClient, dryRun bool, scanResult *scanner.ScanResult) error {
	// Group resolved CVEs by the issue they were reported in
	issueResolved := make(map[int][]string) // issue number → resolved CVE IDs
	for _, cveID := range diffResult.ResolvedCVEs {
		issueNum := imageState.IssueNumber(cveID)
		if issueNum > 0 {
			issueResolved[issueNum] = append(issueResolved[issueNum], cveID)
		}
		imageState.MarkResolved(cveID)
	}

	if dryRun {
		for issueNum, cves := range issueResolved {
			fmt.Printf("\n=== DRY RUN RESOLVED: %s (issue #%d) ===\n", img.Name, issueNum)
			fmt.Printf("Resolved CVEs: %v\n", cves)
			allResolved := issueFullyResolved(imageState, issueNum)
			fmt.Printf("All CVEs resolved (close issue): %v\n", allResolved)
		}
		return nil
	}

	for issueNum, cves := range issueResolved {
		comment := formatter.FormatResolutionComment(img.Name, cves)
		if err := ghClient.CommentOnIssue(issueNum, comment); err != nil {
			slog.Error("failed to comment on issue", "number", issueNum, "error", err)
			continue
		}

		if issueFullyResolved(imageState, issueNum) {
			// All CVEs on this issue are resolved — close it
			if err := ghClient.CloseIssue(issueNum); err != nil {
				slog.Error("failed to close issue", "number", issueNum, "error", err)
			}
		} else {
			// Some CVEs remain — update the title with current counts
			critCount, highCount := remainingCounts(imageState, issueNum, scanResult)
			newTitle := formatter.FormatTitle(img.Name, critCount, highCount)
			if err := ghClient.UpdateIssueTitle(issueNum, newTitle); err != nil {
				slog.Error("failed to update issue title", "number", issueNum, "error", err)
			}
		}
	}
	return nil
}

// issueFullyResolved checks if all CVEs associated with an issue are resolved.
func issueFullyResolved(imageState *state.ImageState, issueNum int) bool {
	for _, s := range imageState.PostedCVEs {
		if s.IssueNumber == issueNum && !s.Resolved {
			return false
		}
	}
	return true
}

// remainingCounts computes the critical/high counts for unresolved CVEs on an issue,
// using the current scan results for severity info.
func remainingCounts(imageState *state.ImageState, issueNum int, scanResult *scanner.ScanResult) (critical, high int) {
	// Build a lookup from CVE ID → severity from current scan
	sevMap := make(map[string]string)
	for _, v := range scanResult.Vulnerabilities {
		sevMap[v.VulnerabilityID] = v.Severity
	}

	for cveID, s := range imageState.PostedCVEs {
		if s.IssueNumber == issueNum && !s.Resolved {
			switch sevMap[cveID] {
			case "CRITICAL":
				critical++
			case "HIGH":
				high++
			}
		}
	}
	return
}

func resolveRepo(owner, repo string) (string, string, error) {
	if owner != "" && repo != "" {
		return owner, repo, nil
	}

	// GITHUB_REPOSITORY is set automatically in GitHub Actions as "owner/repo"
	ghRepo := os.Getenv("GITHUB_REPOSITORY")
	if ghRepo == "" {
		return "", "", fmt.Errorf("--owner and --repo flags or GITHUB_REPOSITORY env var required")
	}

	parts := strings.SplitN(ghRepo, "/", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid GITHUB_REPOSITORY format: %q", ghRepo)
	}
	return parts[0], parts[1], nil
}
