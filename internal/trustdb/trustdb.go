// Package trustdb implements a simple per-key trust database backed by JSON.
//
// Trust levels follow the OpenPGP convention:
//
//	Unknown   (0) – no trust information
//	Never     (1) – explicitly untrusted
//	Marginal  (2) – somewhat trusted
//	Full      (3) – fully trusted
//	Ultimate  (4) – owner trust (your own keys)
package trustdb

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// TrustLevel represents the owner-trust assigned to a key.
type TrustLevel int

const (
	TrustUnknown  TrustLevel = 0
	TrustNever    TrustLevel = 1
	TrustMarginal TrustLevel = 2
	TrustFull     TrustLevel = 3
	TrustUltimate TrustLevel = 4
)

func (t TrustLevel) String() string {
	switch t {
	case TrustUnknown:
		return "unknown"
	case TrustNever:
		return "never"
	case TrustMarginal:
		return "marginal"
	case TrustFull:
		return "full"
	case TrustUltimate:
		return "ultimate"
	default:
		return fmt.Sprintf("TrustLevel(%d)", int(t))
	}
}

// ParseTrustLevel converts a string to a TrustLevel.
func ParseTrustLevel(s string) (TrustLevel, error) {
	switch s {
	case "unknown":
		return TrustUnknown, nil
	case "never":
		return TrustNever, nil
	case "marginal":
		return TrustMarginal, nil
	case "full":
		return TrustFull, nil
	case "ultimate":
		return TrustUltimate, nil
	default:
		return TrustUnknown, fmt.Errorf("unknown trust level: %q", s)
	}
}

// record is the JSON-serialisable form of a trust entry.
type record struct {
	Fingerprint string     `json:"fingerprint"`
	Trust       TrustLevel `json:"trust"`
}

// trustFile is the on-disk format with HMAC integrity protection (L-03).
type trustFile struct {
	Entries []record `json:"entries"`
	MAC     string   `json:"mac"`
}

// DB is a concurrency-safe trust database.
type DB struct {
	mu      sync.RWMutex
	path    string
	keyPath string
	hmacKey []byte
	entries map[string]TrustLevel // fingerprint → trust
}

// Open loads the trust database from path, creating it if it doesn't exist.
func Open(path string) (*DB, error) {
	keyPath := strings.TrimSuffix(path, filepath.Ext(path)) + ".key"

	db := &DB{
		path:    path,
		keyPath: keyPath,
		entries: make(map[string]TrustLevel),
	}

	// Load or create HMAC key
	hmacKey, err := db.loadOrCreateKey()
	if err != nil {
		return nil, fmt.Errorf("trustdb key: %w", err)
	}
	db.hmacKey = hmacKey

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return db, nil
		}
		return nil, sanitizeError(fmt.Errorf("read trustdb: %w", err))
	}

	if len(data) == 0 {
		return db, nil
	}

	// Try new format (with MAC) first
	var tf trustFile
	if err := json.Unmarshal(data, &tf); err == nil && tf.MAC != "" {
		// Verify HMAC
		entriesJSON, err := json.Marshal(tf.Entries)
		if err != nil {
			return nil, fmt.Errorf("re-marshal trustdb entries: %w", err)
		}
		mac, err := hex.DecodeString(tf.MAC)
		if err != nil {
			return nil, fmt.Errorf("decode trustdb MAC: %w", err)
		}
		if !verifyMAC(db.hmacKey, entriesJSON, mac) {
			return nil, fmt.Errorf("trustdb integrity check failed: file may have been tampered with")
		}
		for _, r := range tf.Entries {
			db.entries[r.Fingerprint] = r.Trust
		}
		return db, nil
	}

	// Fall back to legacy format (plain array, no MAC) — migrate on next save
	var records []record
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parse trustdb: %w", err)
	}
	for _, r := range records {
		db.entries[r.Fingerprint] = r.Trust
	}
	// Migrate: re-save with MAC
	db.mu.Lock()
	_ = db.saveLocked()
	db.mu.Unlock()
	return db, nil
}

// GetTrust returns the trust level for a key fingerprint.
func (db *DB) GetTrust(fingerprint string) TrustLevel {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.entries[fingerprint]
}

// SetTrust sets the trust level for a key fingerprint and persists to disk.
func (db *DB) SetTrust(fingerprint string, level TrustLevel) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if level == TrustUnknown {
		delete(db.entries, fingerprint)
	} else {
		db.entries[fingerprint] = level
	}
	return db.saveLocked()
}

// All returns all trust entries as a map of fingerprint → TrustLevel.
func (db *DB) All() map[string]TrustLevel {
	db.mu.RLock()
	defer db.mu.RUnlock()
	out := make(map[string]TrustLevel, len(db.entries))
	for k, v := range db.entries {
		out[k] = v
	}
	return out
}

// IsTrusted returns true if the key has Marginal, Full, or Ultimate trust.
func (db *DB) IsTrusted(fingerprint string) bool {
	return db.GetTrust(fingerprint) >= TrustMarginal
}

func (db *DB) saveLocked() error {
	records := make([]record, 0, len(db.entries))
	for fp, t := range db.entries {
		records = append(records, record{Fingerprint: fp, Trust: t})
	}

	entriesJSON, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("marshal trustdb entries: %w", err)
	}

	mac := computeMAC(db.hmacKey, entriesJSON)
	tf := trustFile{
		Entries: records,
		MAC:     hex.EncodeToString(mac),
	}

	data, err := json.MarshalIndent(tf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal trustdb: %w", err)
	}
	return os.WriteFile(db.path, data, 0600)
}

func (db *DB) loadOrCreateKey() ([]byte, error) {
	data, err := os.ReadFile(db.keyPath)
	if err == nil && len(data) == 64 {
		key, err := hex.DecodeString(strings.TrimSpace(string(data)))
		if err == nil && len(key) == 32 {
			return key, nil
		}
	}

	// Generate new key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate HMAC key: %w", err)
	}
	encoded := hex.EncodeToString(key)
	if err := os.WriteFile(db.keyPath, []byte(encoded), 0600); err != nil {
		return nil, sanitizeError(fmt.Errorf("write HMAC key: %w", err))
	}
	return key, nil
}

func computeMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func verifyMAC(key, data, mac []byte) bool {
	expected := computeMAC(key, data)
	return hmac.Equal(expected, mac)
}

// sanitizeError replaces the user's home directory in error messages with "~".
func sanitizeError(err error) error {
	if err == nil {
		return nil
	}
	home, herr := os.UserHomeDir()
	if herr != nil || home == "" {
		return err
	}
	msg := strings.ReplaceAll(err.Error(), home, "~")
	return fmt.Errorf("%s", msg)
}
