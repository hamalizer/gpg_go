// Package config handles application configuration and paths.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const (
	AppName    = "gpg-go"
	AppVersion = "0.2.0-canary"
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

func DefaultHomeDir() (string, error) {
	if env := os.Getenv("GPG_GO_HOME"); env != "" {
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		if runtime.GOOS == "windows" {
			home = os.Getenv("USERPROFILE")
		} else {
			home = os.Getenv("HOME")
		}
	}
	if home == "" {
		return "", fmt.Errorf("unable to determine home directory: set GPG_GO_HOME or HOME")
	}
	return filepath.Join(home, DirName), nil
}

func New(homeDir string) (*Config, error) {
	if homeDir == "" {
		var err error
		homeDir, err = DefaultHomeDir()
		if err != nil {
			return nil, err
		}
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
