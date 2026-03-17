// Package keyring manages OpenPGP key storage and retrieval.
package keyring

import (
	"bytes"
	gocrypto "crypto"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// sanitizeError replaces the user's home directory in error messages with "~"
// to avoid leaking internal filesystem paths in error output (L-02).
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

// Store handles persisting keys to disk.
type Store struct {
	pubDir string
	secDir string
}

func NewStore(pubDir, secDir string) *Store {
	return &Store{pubDir: pubDir, secDir: secDir}
}

func (s *Store) SavePublicKey(entity *openpgp.Entity) error {
	fp := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
	path := filepath.Join(s.pubDir, fp+".asc")

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		return fmt.Errorf("armor encode: %w", err)
	}
	if err := entity.Serialize(w); err != nil {
		w.Close()
		return fmt.Errorf("serialize public key: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("finalize armor: %w", err)
	}

	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		return sanitizeError(err)
	}
	return nil
}

func (s *Store) SavePrivateKey(entity *openpgp.Entity) error {
	fp := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
	path := filepath.Join(s.secDir, fp+".asc")

	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		return fmt.Errorf("armor encode: %w", err)
	}
	if err := entity.SerializePrivate(w, s2kSerializeConfig()); err != nil {
		w.Close()
		return fmt.Errorf("serialize private key: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("finalize armor: %w", err)
	}

	if err := os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		return sanitizeError(err)
	}
	return nil
}

func (s *Store) LoadPublicKeys() (openpgp.EntityList, error) {
	return s.loadKeysFromDir(s.pubDir)
}

func (s *Store) LoadPrivateKeys() (openpgp.EntityList, error) {
	return s.loadKeysFromDir(s.secDir)
}

func (s *Store) DeleteKey(keyID string, private bool) error {
	dir := s.pubDir
	if private {
		dir = s.secDir
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return sanitizeError(err)
	}

	// Normalize key ID for matching
	keyID = strings.ToUpper(strings.TrimPrefix(strings.ToUpper(keyID), "0X"))

	deleted := false
	for _, entry := range entries {
		name := strings.TrimSuffix(entry.Name(), ".asc")
		if strings.EqualFold(name, keyID) {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
				return sanitizeError(err)
			}
			deleted = true
		}
	}
	if !deleted {
		return fmt.Errorf("key %s not found", keyID)
	}
	return nil
}

// s2kSerializeConfig returns a packet.Config with strong S2K parameters for
// serializing encrypted private keys. When the key is encrypted, the library
// uses these settings for the string-to-key derivation.
func s2kSerializeConfig() *packet.Config {
	return &packet.Config{
		DefaultHash:   gocrypto.SHA256,
		DefaultCipher: packet.CipherAES256,
	}
}

func (s *Store) loadKeysFromDir(dir string) (openpgp.EntityList, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, sanitizeError(err)
	}

	// L-01: Check directory permissions. Secret key directories should be 0700.
	if info, err := os.Stat(dir); err == nil {
		perm := info.Mode().Perm()
		if perm&0077 != 0 {
			fmt.Fprintf(os.Stderr, "WARNING: directory %s has permissive permissions (%04o), should be 0700\n",
				filepath.Base(dir), perm)
		}
	}

	var entities openpgp.EntityList
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".asc") {
			continue
		}

		filePath := filepath.Join(dir, entry.Name())

		// L-01: Check individual key file permissions
		if info, err := entry.Info(); err == nil {
			perm := info.Mode().Perm()
			if perm&0077 != 0 {
				fmt.Fprintf(os.Stderr, "WARNING: key file %s has permissive permissions (%04o), should be 0600\n",
					entry.Name(), perm)
			}
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
		if err != nil {
			continue
		}
		entities = append(entities, el...)
	}
	return entities, nil
}
