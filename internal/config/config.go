// Package config handles application configuration and paths.
package config

import (
	"os"
	"path/filepath"
	"runtime"
)

const (
	AppName    = "gpg-go"
	AppVersion = "0.1.0"
	DirName    = ".gpg-go"
)

type Config struct {
	HomeDir    string
	PubRingDir string
	SecRingDir string
	TrustDB    string
	ConfigFile string
	Keyserver  string
	Armor      bool
	Verbose    bool
}

func DefaultHomeDir() string {
	if env := os.Getenv("GPG_GO_HOME"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		if runtime.GOOS == "windows" {
			home = os.Getenv("USERPROFILE")
		} else {
			home = os.Getenv("HOME")
		}
	}
	return filepath.Join(home, DirName)
}

func New(homeDir string) (*Config, error) {
	if homeDir == "" {
		homeDir = DefaultHomeDir()
	}

	cfg := &Config{
		HomeDir:    homeDir,
		PubRingDir: filepath.Join(homeDir, "pubring"),
		SecRingDir: filepath.Join(homeDir, "secring"),
		TrustDB:    filepath.Join(homeDir, "trustdb.json"),
		ConfigFile: filepath.Join(homeDir, "config.json"),
		Keyserver:  "hkps://keys.openpgp.org",
	}

	dirs := []string{cfg.HomeDir, cfg.PubRingDir, cfg.SecRingDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}
