package reddit

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	tokenURL  = "https://www.reddit.com/api/v1/access_token"
	submitURL = "https://oauth.reddit.com/api/submit"
	userAgent = "RedFlag/1.0 (by /u/RedFlagBot)"
)

// Credentials holds Reddit OAuth2 script app credentials.
type Credentials struct {
	ClientID     string
	ClientSecret string
	Username     string
	Password     string
}

// Client is a Reddit API client.
type Client struct {
	creds       Credentials
	accessToken string
	tokenExpiry time.Time
	httpClient  *http.Client
}

// NewClient creates a new Reddit client.
func NewClient(creds Credentials) *Client {
	return &Client{
		creds: creds,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SubmitResult holds the response from a Reddit submit call.
type SubmitResult struct {
	URL string
	ID  string
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error,omitempty"`
}

type submitResponse struct {
	JSON struct {
		Errors [][]string `json:"errors"`
		Data   struct {
			URL string `json:"url"`
			ID  string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	} `json:"json"`
}

// authenticate obtains an OAuth2 access token using the script app flow.
func (c *Client) authenticate() error {
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		return nil
	}

	data := url.Values{
		"grant_type": {"password"},
		"username":   {c.creds.Username},
		"password":   {c.creds.Password},
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("creating auth request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.creds.ClientID, c.creds.ClientSecret)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading auth response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return fmt.Errorf("parsing auth response: %w", err)
	}

	if tok.Error != "" {
		return fmt.Errorf("auth error: %s", tok.Error)
	}

	c.accessToken = tok.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)

	slog.Info("reddit auth successful", "expires_in", tok.ExpiresIn)
	return nil
}

// Submit creates a self-post in the given subreddit.
func (c *Client) Submit(subreddit, title, body string) (*SubmitResult, error) {
	if err := c.authenticate(); err != nil {
		return nil, err
	}

	data := url.Values{
		"sr":       {subreddit},
		"kind":     {"self"},
		"title":    {title},
		"text":     {body},
		"api_type": {"json"},
	}

	req, err := http.NewRequest("POST", submitURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating submit request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	for attempt := range 3 {
		resp, err = c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("submit request: %w", err)
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			wait := time.Duration(2<<uint(attempt)) * time.Second
			slog.Warn("rate limited, backing off", "wait", wait, "attempt", attempt+1)
			time.Sleep(wait)
			continue
		}
		break
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading submit response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("submit failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var sr submitResponse
	if err := json.Unmarshal(respBody, &sr); err != nil {
		return nil, fmt.Errorf("parsing submit response: %w", err)
	}

	if len(sr.JSON.Errors) > 0 {
		return nil, fmt.Errorf("reddit API errors: %v", sr.JSON.Errors)
	}

	slog.Info("posted to reddit", "subreddit", subreddit, "url", sr.JSON.Data.URL)

	return &SubmitResult{
		URL: sr.JSON.Data.URL,
		ID:  sr.JSON.Data.ID,
	}, nil
}
