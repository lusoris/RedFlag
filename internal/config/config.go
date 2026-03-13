package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type ImageEntry struct {
	Name       string   `yaml:"name"`
	Image      string   `yaml:"image"`
	Subreddits []string `yaml:"subreddits"`
}

type Config struct {
	Images []ImageEntry `yaml:"images"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if len(cfg.Images) == 0 {
		return nil, fmt.Errorf("config has no images defined")
	}

	for i, img := range cfg.Images {
		if img.Image == "" {
			return nil, fmt.Errorf("image at index %d has no image field", i)
		}
		if img.Name == "" {
			return nil, fmt.Errorf("image at index %d has no name field", i)
		}
		if len(img.Subreddits) == 0 {
			return nil, fmt.Errorf("image %q has no subreddits", img.Name)
		}
	}

	return &cfg, nil
}
