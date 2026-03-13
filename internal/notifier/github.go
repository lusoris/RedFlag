package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// GitHubClient posts issues to a GitHub repository.
type GitHubClient struct {
	token      string
	owner      string
	repo       string
	httpClient *http.Client
}

// NewGitHubClient creates a client that posts issues to owner/repo.
func NewGitHubClient(token, owner, repo string) *GitHubClient {
	return &GitHubClient{
		token: token,
		owner: owner,
		repo:  repo,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// IssueResult holds the response from creating an issue.
type IssueResult struct {
	URL    string
	Number int
}

type createIssueRequest struct {
	Title  string   `json:"title"`
	Body   string   `json:"body"`
	Labels []string `json:"labels"`
}

type createIssueResponse struct {
	HTMLURL string `json:"html_url"`
	Number  int    `json:"number"`
	Message string `json:"message,omitempty"`
}

// CreateIssue creates a new issue in the configured repository.
func (c *GitHubClient) CreateIssue(title, body string, labels []string) (*IssueResult, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", c.owner, c.repo)

	payload := createIssueRequest{
		Title:  title,
		Body:   body,
		Labels: labels,
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling issue: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result createIssueResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	slog.Info("created GitHub issue", "url", result.HTMLURL, "number", result.Number)

	return &IssueResult{
		URL:    result.HTMLURL,
		Number: result.Number,
	}, nil
}

// EnsureLabels creates labels if they don't already exist (ignores 422 = already exists).
func (c *GitHubClient) EnsureLabels(labels map[string]string) {
	for name, color := range labels {
		c.createLabel(name, color)
	}
}

func (c *GitHubClient) createLabel(name, color string) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/labels", c.owner, c.repo)

	payload, _ := json.Marshal(map[string]string{
		"name":  name,
		"color": color,
	})

	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// CommentOnIssue adds a comment to an existing issue.
func (c *GitHubClient) CommentOnIssue(issueNumber int, body string) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues/%d/comments", c.owner, c.repo, issueNumber)

	payload, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return fmt.Errorf("marshaling comment: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	slog.Info("commented on issue", "number", issueNumber)
	return nil
}

// CloseIssue closes an existing issue.
func (c *GitHubClient) CloseIssue(issueNumber int) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues/%d", c.owner, c.repo, issueNumber)

	payload, err := json.Marshal(map[string]string{"state": "closed", "state_reason": "completed"})
	if err != nil {
		return fmt.Errorf("marshaling close: %w", err)
	}

	req, err := http.NewRequest("PATCH", url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	slog.Info("closed issue", "number", issueNumber)
	return nil
}

// UpdateIssueTitle updates the title of an existing issue.
func (c *GitHubClient) UpdateIssueTitle(issueNumber int, title string) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues/%d", c.owner, c.repo, issueNumber)

	payload, err := json.Marshal(map[string]string{"title": title})
	if err != nil {
		return fmt.Errorf("marshaling title update: %w", err)
	}

	req, err := http.NewRequest("PATCH", url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	slog.Info("updated issue title", "number", issueNumber, "title", title)
	return nil
}
