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
	"encoding/json"
	"fmt"
	"os"
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

// DB is a concurrency-safe trust database.
type DB struct {
	mu      sync.RWMutex
	path    string
	entries map[string]TrustLevel // fingerprint → trust
}

// Open loads the trust database from path, creating it if it doesn't exist.
func Open(path string) (*DB, error) {
	db := &DB{
		path:    path,
		entries: make(map[string]TrustLevel),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return db, nil
		}
		return nil, fmt.Errorf("read trustdb: %w", err)
	}

	if len(data) == 0 {
		return db, nil
	}

	var records []record
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parse trustdb: %w", err)
	}
	for _, r := range records {
		db.entries[r.Fingerprint] = r.Trust
	}
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

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal trustdb: %w", err)
	}
	return os.WriteFile(db.path, data, 0600)
}
