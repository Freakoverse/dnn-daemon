// Package config handles configuration loading for the DNN daemon.
package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the daemon configuration
type Config struct {
	Nodes []string    `yaml:"nodes"`
	Cache CacheConfig `yaml:"cache"`
	TUN   TUNConfig   `yaml:"tun"`
	DNS   DNSConfig   `yaml:"dns"`
	Log   LogConfig   `yaml:"log"`
}

// CacheConfig holds cache settings
type CacheConfig struct {
	TTL        time.Duration `yaml:"ttl"`
	MaxEntries int           `yaml:"max_entries"`
}

// TUNConfig holds TUN device settings
type TUNConfig struct {
	Name string `yaml:"name"`
	MTU  int    `yaml:"mtu"`
}

// DNSConfig holds DNS server settings
type DNSConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	Domain     string `yaml:"domain"` // e.g., "dnn" for .dnn domains
}

// LogConfig holds logging settings
type LogConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Nodes: []string{
			"https://node.icannot.xyz",
			"http://64.111.92.122:8080",
		},
		Cache: CacheConfig{
			TTL:        60 * time.Second,
			MaxEntries: 10000,
		},
		TUN: TUNConfig{
			Name: "dnn0",
			MTU:  1420,
		},
		DNS: DNSConfig{
			ListenAddr: "127.0.0.1:53",
			Domain:     "dnn",
		},
		Log: LogConfig{
			Level: "info",
			File:  "/var/log/dnn-daemon.log",
		},
	}
}

// Load reads configuration from a YAML file
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// Save writes configuration to a YAML file
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
