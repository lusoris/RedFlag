package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/lusoris/redflag/internal/config"
	"github.com/lusoris/redflag/internal/diff"
	"github.com/lusoris/redflag/internal/formatter"
	"github.com/lusoris/redflag/internal/reddit"
	"github.com/lusoris/redflag/internal/scanner"
	"github.com/lusoris/redflag/internal/state"
)

func main() {
	configPath := flag.String("config", "images.yaml", "path to images config file")
	statePath := flag.String("state", "state.json", "path to state file")
	dryRun := flag.Bool("dry-run", false, "print posts to stdout instead of posting to Reddit")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if err := run(*configPath, *statePath, *dryRun); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(configPath, statePath string, dryRun bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	slog.Info("loaded config", "images", len(cfg.Images))

	store, err := state.Load(statePath)
	if err != nil {
		return fmt.Errorf("loading state: %w", err)
	}

	var redditClient *reddit.Client
	if !dryRun {
		creds, err := loadRedditCreds()
		if err != nil {
			return err
		}
		redditClient = reddit.NewClient(creds)
	}

	var anyError bool
	for _, img := range cfg.Images {
		if err := processImage(img, store, redditClient, dryRun); err != nil {
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

func processImage(img config.ImageEntry, store state.Store, redditClient *reddit.Client, dryRun bool) error {
	slog.Info("processing", "name", img.Name, "image", img.Image)

	scanResult, err := scanner.Scan(img.Image)
	if err != nil {
		return fmt.Errorf("scanning %s: %w", img.Image, err)
	}

	imageState := store.GetOrCreate(img.Image)

	diffResult := diff.New(scanResult, imageState)
	if !diffResult.HasNew() {
		slog.Info("no new vulnerabilities", "image", img.Image)
		imageState.LastScan = time.Now().UTC()
		if scanResult.Digest != "" {
			imageState.ImageDigest = scanResult.Digest
		}
		return nil
	}

	slog.Info("new vulnerabilities found", "image", img.Image, "count", len(diffResult.NewVulns))

	post := formatter.FormatPost(img.Name, img.Image, diffResult.NewVulns)

	if dryRun {
		fmt.Printf("\n=== DRY RUN: %s ===\n", img.Name)
		fmt.Printf("Subreddits: %v\n", img.Subreddits)
		fmt.Printf("Title: %s\n", post.Title)
		fmt.Printf("Body:\n%s\n", post.Body)
	} else {
		for _, sub := range img.Subreddits {
			result, err := redditClient.Submit(sub, post.Title, post.Body)
			if err != nil {
				slog.Error("failed to post to reddit", "subreddit", sub, "error", err)
				continue
			}
			slog.Info("posted", "subreddit", sub, "url", result.URL)

			for _, v := range diffResult.NewVulns {
				imageState.MarkPosted(v.VulnerabilityID, sub, result.URL)
			}
		}
	}

	// In dry-run mode, still mark CVEs as "posted" so subsequent dry runs show fresh results
	if dryRun {
		for _, v := range diffResult.NewVulns {
			imageState.MarkPosted(v.VulnerabilityID, "dry-run", "")
		}
	}

	imageState.LastScan = time.Now().UTC()
	if scanResult.Digest != "" {
		imageState.ImageDigest = scanResult.Digest
	}

	return nil
}

func loadRedditCreds() (reddit.Credentials, error) {
	creds := reddit.Credentials{
		ClientID:     os.Getenv("REDDIT_CLIENT_ID"),
		ClientSecret: os.Getenv("REDDIT_CLIENT_SECRET"),
		Username:     os.Getenv("REDDIT_USERNAME"),
		Password:     os.Getenv("REDDIT_PASSWORD"),
	}

	if creds.ClientID == "" || creds.ClientSecret == "" || creds.Username == "" || creds.Password == "" {
		return creds, fmt.Errorf("missing Reddit credentials: set REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET, REDDIT_USERNAME, REDDIT_PASSWORD")
	}

	return creds, nil
}
