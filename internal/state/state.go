package state

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// SubredditStatus tracks whether a CVE set was posted to a specific subreddit.
type SubredditStatus struct {
	PostedAt time.Time `json:"posted_at"`
	PostURL  string    `json:"post_url,omitempty"`
}

// ImageState holds the scan state for a single container image.
type ImageState struct {
	LastScan    time.Time                  `json:"last_scan"`
	ImageDigest string                     `json:"image_digest,omitempty"`
	PostedCVEs  map[string]SubredditStatus `json:"posted_cves"` // CVE ID → subreddit → status
}

// Store is the top-level state file mapping image references to their state.
type Store map[string]*ImageState

// Load reads state from a JSON file. Returns an empty Store if the file doesn't exist.
func Load(path string) (Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(Store), nil
		}
		return nil, fmt.Errorf("reading state: %w", err)
	}

	if len(data) == 0 {
		return make(Store), nil
	}

	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing state: %w", err)
	}

	if s == nil {
		s = make(Store)
	}

	return s, nil
}

// Save writes the state to a JSON file.
func (s Store) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing state: %w", err)
	}
	return nil
}

// GetOrCreate returns the ImageState for the given image, creating one if it doesn't exist.
func (s Store) GetOrCreate(image string) *ImageState {
	if st, ok := s[image]; ok {
		return st
	}
	st := &ImageState{
		PostedCVEs: make(map[string]SubredditStatus),
	}
	s[image] = st
	return st
}

// IsPosted returns true if the given CVE has already been posted (to any subreddit).
func (is *ImageState) IsPosted(cveID string) bool {
	_, ok := is.PostedCVEs[cveID]
	return ok
}

// MarkPosted records that a CVE was posted to a subreddit.
func (is *ImageState) MarkPosted(cveID, subreddit, postURL string) {
	is.PostedCVEs[cveID] = SubredditStatus{
		PostedAt: time.Now().UTC(),
		PostURL:  postURL,
	}
}
