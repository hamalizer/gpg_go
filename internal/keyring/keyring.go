package keyring

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/hamalizer/gpg_go/internal/config"
)

// Keyring manages the in-memory and on-disk key collections.
// All methods are safe for concurrent use.
type Keyring struct {
	mu      sync.RWMutex
	store   *Store
	pubKeys openpgp.EntityList
	secKeys openpgp.EntityList
	cfg     *config.Config
}

func New(cfg *config.Config) (*Keyring, error) {
	store := NewStore(cfg.PubRingDir, cfg.SecRingDir)

	pubKeys, err := store.LoadPublicKeys()
	if err != nil {
		return nil, fmt.Errorf("load public keys: %w", err)
	}

	secKeys, err := store.LoadPrivateKeys()
	if err != nil {
		return nil, fmt.Errorf("load private keys: %w", err)
	}

	return &Keyring{
		store:   store,
		pubKeys: pubKeys,
		secKeys: secKeys,
		cfg:     cfg,
	}, nil
}

func (kr *Keyring) PublicKeys() openpgp.EntityList {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	result := make(openpgp.EntityList, len(kr.pubKeys))
	copy(result, kr.pubKeys)
	return result
}

func (kr *Keyring) SecretKeys() openpgp.EntityList {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	result := make(openpgp.EntityList, len(kr.secKeys))
	copy(result, kr.secKeys)
	return result
}

// AllKeys returns all keys (public + secret) as an EntityList for decryption.
func (kr *Keyring) AllKeys() openpgp.EntityList {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	all := make(openpgp.EntityList, 0, len(kr.pubKeys)+len(kr.secKeys))
	all = append(all, kr.pubKeys...)
	all = append(all, kr.secKeys...)
	return all
}

func (kr *Keyring) ImportKey(keyData io.Reader) ([]*openpgp.Entity, error) {
	// Buffer the input so we can retry with binary format if armored fails
	data, err := io.ReadAll(keyData)
	if err != nil {
		return nil, fmt.Errorf("read key data: %w", err)
	}

	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
	if err != nil {
		// Try binary format as fallback
		entities, err = openpgp.ReadKeyRing(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("read key (tried armored and binary): %w", err)
		}
	}

	kr.mu.Lock()
	defer kr.mu.Unlock()

	var imported []*openpgp.Entity
	for _, entity := range entities {
		fp := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
		if entity.PrivateKey != nil {
			if !kr.hasKeyLocked(kr.secKeys, fp) {
				if err := kr.store.SavePrivateKey(entity); err != nil {
					return imported, fmt.Errorf("save private key: %w", err)
				}
				kr.secKeys = append(kr.secKeys, entity)
			}
			if !kr.hasKeyLocked(kr.pubKeys, fp) {
				if err := kr.store.SavePublicKey(entity); err != nil {
					return imported, fmt.Errorf("save public key: %w", err)
				}
				kr.pubKeys = append(kr.pubKeys, entity)
			}
		} else {
			if !kr.hasKeyLocked(kr.pubKeys, fp) {
				if err := kr.store.SavePublicKey(entity); err != nil {
					return imported, fmt.Errorf("save public key: %w", err)
				}
				kr.pubKeys = append(kr.pubKeys, entity)
			}
		}
		imported = append(imported, entity)
	}
	return imported, nil
}

func (kr *Keyring) AddEntity(entity *openpgp.Entity) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	fp := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)

	if entity.PrivateKey != nil {
		if !kr.hasKeyLocked(kr.secKeys, fp) {
			if err := kr.store.SavePrivateKey(entity); err != nil {
				return err
			}
			kr.secKeys = append(kr.secKeys, entity)
		}
		if !kr.hasKeyLocked(kr.pubKeys, fp) {
			if err := kr.store.SavePublicKey(entity); err != nil {
				return err
			}
			kr.pubKeys = append(kr.pubKeys, entity)
		}
	} else {
		if !kr.hasKeyLocked(kr.pubKeys, fp) {
			if err := kr.store.SavePublicKey(entity); err != nil {
				return err
			}
			kr.pubKeys = append(kr.pubKeys, entity)
		}
	}
	return nil
}

// UpdateEntity re-saves an existing entity to disk. Use this after modifying
// a key (e.g. adding subkeys or UIDs) so the changes are persisted.
func (kr *Keyring) UpdateEntity(entity *openpgp.Entity) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	if entity.PrivateKey != nil {
		if err := kr.store.SavePrivateKey(entity); err != nil {
			return err
		}
	}
	if err := kr.store.SavePublicKey(entity); err != nil {
		return err
	}
	return nil
}

// hasKeyLocked checks if a key with the given fingerprint exists in the list.
// Caller must hold kr.mu.
func (kr *Keyring) hasKeyLocked(keys openpgp.EntityList, fingerprint string) bool {
	for _, e := range keys {
		if fmt.Sprintf("%X", e.PrimaryKey.Fingerprint) == fingerprint {
			return true
		}
	}
	return false
}

func (kr *Keyring) FindPublicKey(identifier string) *openpgp.Entity {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return findKey(kr.pubKeys, identifier)
}

func (kr *Keyring) FindSecretKey(identifier string) *openpgp.Entity {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return findKey(kr.secKeys, identifier)
}

func (kr *Keyring) DeletePublicKey(identifier string) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	// Resolve identifier (email, name, etc.) to actual key ID
	entity := findKey(kr.pubKeys, identifier)
	if entity == nil {
		return fmt.Errorf("public key not found: %s", identifier)
	}
	keyID := entity.PrimaryKey.KeyIdString()

	if err := kr.store.DeleteKey(keyID, false); err != nil {
		return err
	}
	kr.pubKeys = removeKey(kr.pubKeys, keyID)
	return nil
}

func (kr *Keyring) DeleteSecretKey(identifier string) error {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	// Resolve identifier (email, name, etc.) to actual key ID
	entity := findKey(kr.secKeys, identifier)
	if entity == nil {
		return fmt.Errorf("secret key not found: %s", identifier)
	}
	keyID := entity.PrimaryKey.KeyIdString()

	if err := kr.store.DeleteKey(keyID, true); err != nil {
		return err
	}
	kr.secKeys = removeKey(kr.secKeys, keyID)
	return nil
}

func (kr *Keyring) ExportPublicKey(identifier string, armored bool) ([]byte, error) {
	kr.mu.RLock()
	entity := findKey(kr.pubKeys, identifier)
	kr.mu.RUnlock()

	if entity == nil {
		return nil, fmt.Errorf("public key not found: %s", identifier)
	}

	var buf bytes.Buffer
	if armored {
		w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
		if err != nil {
			return nil, err
		}
		if err := entity.Serialize(w); err != nil {
			w.Close()
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, fmt.Errorf("finalize armor: %w", err)
		}
	} else {
		if err := entity.Serialize(&buf); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func (kr *Keyring) ExportSecretKey(identifier string, armored bool) ([]byte, error) {
	kr.mu.RLock()
	entity := findKey(kr.secKeys, identifier)
	kr.mu.RUnlock()

	if entity == nil {
		return nil, fmt.Errorf("secret key not found: %s", identifier)
	}

	var buf bytes.Buffer
	if armored {
		w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
		if err != nil {
			return nil, err
		}
		if err := entity.SerializePrivate(w, s2kSerializeConfig()); err != nil {
			w.Close()
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, fmt.Errorf("finalize armor: %w", err)
		}
	} else {
		if err := entity.SerializePrivate(&buf, s2kSerializeConfig()); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// KeyInfo returns a human-readable summary of a key.
func KeyInfo(entity *openpgp.Entity) string {
	pk := entity.PrimaryKey
	algo := "unknown"
	bitStr := ""

	if bl, err := pk.BitLength(); err == nil && bl > 0 {
		bitStr = fmt.Sprintf("%d", bl)
	}

	switch pk.PubKeyAlgo {
	case 1, 2, 3: // RSA
		algo = "RSA"
	case 17: // DSA
		algo = "DSA"
	case 18: // ECDH
		algo = "ECDH"
	case 19: // ECDSA
		algo = "ECDSA"
	case 22: // EdDSA
		algo = "EdDSA"
		if bitStr == "" {
			bitStr = "256"
		}
	}

	keyID := pk.KeyIdString()
	fingerprint := fmt.Sprintf("%X", pk.Fingerprint)
	created := pk.CreationTime.Format("2006-01-02")

	// Sort identity names for deterministic output
	uids := SortedUIDs(entity)

	hasSecret := ""
	if entity.PrivateKey != nil {
		hasSecret = " [secret]"
	}

	expiry := KeyExpiry(entity)
	expiryStr := ""
	if !expiry.IsZero() {
		if IsKeyExpired(entity) {
			expiryStr = fmt.Sprintf(" [EXPIRED %s]", expiry.Format("2006-01-02"))
		} else {
			expiryStr = fmt.Sprintf(" [expires %s]", expiry.Format("2006-01-02"))
		}
	}

	info := fmt.Sprintf("%s%s/%s %s%s%s\n", algo, bitStr, keyID, created, hasSecret, expiryStr)
	for _, uid := range uids {
		info += fmt.Sprintf("  uid: %s\n", uid)
	}
	info += fmt.Sprintf("  fingerprint: %s\n", fingerprint)
	for _, sub := range entity.Subkeys {
		subAlgo := "unknown"
		subBits := ""
		if bl, err := sub.PublicKey.BitLength(); err == nil && bl > 0 {
			subBits = fmt.Sprintf("%d", bl)
		}
		switch sub.PublicKey.PubKeyAlgo {
		case 1, 2, 3:
			subAlgo = "RSA"
		case 18:
			subAlgo = "ECDH"
		case 22:
			subAlgo = "EdDSA"
			if subBits == "" {
				subBits = "256"
			}
		case 25:
			subAlgo = "X25519"
			if subBits == "" {
				subBits = "256"
			}
		}
		usage := ""
		if sub.Sig != nil {
			if sub.Sig.FlagEncryptStorage || sub.Sig.FlagEncryptCommunications {
				usage = " [encrypt]"
			}
			if sub.Sig.FlagSign {
				usage = " [sign]"
			}
		}
		subCreated := sub.PublicKey.CreationTime.Format("2006-01-02")
		subExpiry := ""
		if sub.Sig != nil && sub.Sig.KeyLifetimeSecs != nil && *sub.Sig.KeyLifetimeSecs > 0 {
			exp := sub.PublicKey.CreationTime.Add(time.Duration(*sub.Sig.KeyLifetimeSecs) * time.Second)
			subExpiry = fmt.Sprintf(" [expires %s]", exp.Format("2006-01-02"))
		}
		revoked := ""
		if len(sub.Revocations) > 0 {
			revoked = " [REVOKED]"
		}
		info += fmt.Sprintf("  sub: %s%s/%s %s%s%s%s\n", subAlgo, subBits, sub.PublicKey.KeyIdString(), subCreated, usage, subExpiry, revoked)
	}
	return strings.TrimRight(info, "\n")
}

// SortedUIDs returns identity names in deterministic order.
func SortedUIDs(entity *openpgp.Entity) []string {
	uids := make([]string, 0, len(entity.Identities))
	for _, id := range entity.Identities {
		uids = append(uids, id.Name)
	}
	sort.Strings(uids)
	return uids
}

// PrimaryUID returns the first UID in sorted order.
func PrimaryUID(entity *openpgp.Entity) string {
	uids := SortedUIDs(entity)
	if len(uids) > 0 {
		return uids[0]
	}
	return ""
}

func findKey(keys openpgp.EntityList, identifier string) *openpgp.Entity {
	// Normalize: strip 0x/0X prefix, uppercase for hex comparisons
	upper := strings.ToUpper(identifier)
	upper = strings.TrimPrefix(upper, "0X")

	// First pass: exact match on key ID or fingerprint (unambiguous)
	for _, entity := range keys {
		keyID := entity.PrimaryKey.KeyIdString()
		fingerprint := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)

		if strings.EqualFold(keyID, upper) || strings.EqualFold(fingerprint, upper) {
			return entity
		}
	}

	// Second pass: exact email match (preferred over substring)
	lowerID := strings.ToLower(identifier)
	for _, entity := range keys {
		for _, id := range entity.Identities {
			// Extract email from UID format "Name (Comment) <email>"
			name := id.Name
			if emailStart := strings.LastIndex(name, "<"); emailStart >= 0 {
				if emailEnd := strings.LastIndex(name, ">"); emailEnd > emailStart {
					email := strings.ToLower(name[emailStart+1 : emailEnd])
					if email == lowerID {
						return entity
					}
				}
			}
		}
	}

	// Third pass: exact name match
	for _, entity := range keys {
		for _, id := range entity.Identities {
			name := id.Name
			// Strip email portion for name comparison
			if idx := strings.LastIndex(name, "<"); idx > 0 {
				name = strings.TrimSpace(name[:idx])
			}
			if strings.EqualFold(name, identifier) {
				return entity
			}
		}
	}

	// Fourth pass: substring match, but only if exactly one key matches.
	seen := make(map[string]*openpgp.Entity)
	for _, entity := range keys {
		for _, id := range entity.Identities {
			if strings.Contains(strings.ToLower(id.Name), lowerID) {
				fp := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
				seen[fp] = entity
				break
			}
		}
	}
	if len(seen) == 1 {
		for _, entity := range seen {
			return entity
		}
	}
	return nil
}

// EncryptEntityKeys encrypts all private key material in an entity with the
// given passphrase using S2K key derivation. Both the primary key and all
// subkeys are encrypted. This should be called before persisting keys to disk.
func EncryptEntityKeys(entity *openpgp.Entity, passphrase []byte) error {
	if entity.PrivateKey != nil && !entity.PrivateKey.Encrypted {
		if err := entity.PrivateKey.Encrypt(passphrase); err != nil {
			return fmt.Errorf("encrypt primary key: %w", err)
		}
	}
	for i, sub := range entity.Subkeys {
		if sub.PrivateKey != nil && !sub.PrivateKey.Encrypted {
			if err := entity.Subkeys[i].PrivateKey.Encrypt(passphrase); err != nil {
				return fmt.Errorf("encrypt subkey: %w", err)
			}
		}
	}
	return nil
}

// DecryptEntityKeys decrypts all private key material in an entity.
func DecryptEntityKeys(entity *openpgp.Entity, passphrase []byte) error {
	if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
		if err := entity.PrivateKey.Decrypt(passphrase); err != nil {
			return fmt.Errorf("decrypt primary key: %w", err)
		}
	}
	for i, sub := range entity.Subkeys {
		if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
			if err := entity.Subkeys[i].PrivateKey.Decrypt(passphrase); err != nil {
				return fmt.Errorf("decrypt subkey: %w", err)
			}
		}
	}
	return nil
}

// IsEntityKeyEncrypted returns true if any private key material in the entity
// is passphrase-encrypted.
func IsEntityKeyEncrypted(entity *openpgp.Entity) bool {
	if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
		return true
	}
	for _, sub := range entity.Subkeys {
		if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
			return true
		}
	}
	return false
}

// IsKeyExpired checks if the primary identity's self-signature contains a key
// expiration time that has passed. Returns true if expired, false otherwise
// (including when no expiration is set).
func IsKeyExpired(entity *openpgp.Entity) bool {
	for _, id := range entity.Identities {
		if id.SelfSignature != nil && id.SelfSignature.KeyLifetimeSecs != nil && *id.SelfSignature.KeyLifetimeSecs > 0 {
			expiry := entity.PrimaryKey.CreationTime.Add(
				time.Duration(*id.SelfSignature.KeyLifetimeSecs) * time.Second,
			)
			if time.Now().After(expiry) {
				return true
			}
			return false // found a valid self-sig with expiry, not expired
		}
	}
	return false // no expiration set (or lifetime is 0, meaning no expiry)
}

// KeyExpiry returns the expiration time of a key, or zero time if none is set.
func KeyExpiry(entity *openpgp.Entity) time.Time {
	for _, id := range entity.Identities {
		if id.SelfSignature != nil && id.SelfSignature.KeyLifetimeSecs != nil && *id.SelfSignature.KeyLifetimeSecs > 0 {
			return entity.PrimaryKey.CreationTime.Add(
				time.Duration(*id.SelfSignature.KeyLifetimeSecs) * time.Second,
			)
		}
	}
	return time.Time{}
}

func removeKey(keys openpgp.EntityList, keyID string) openpgp.EntityList {
	keyID = strings.ToUpper(strings.TrimPrefix(strings.ToUpper(keyID), "0X"))
	var result openpgp.EntityList
	for _, entity := range keys {
		id := entity.PrimaryKey.KeyIdString()
		fp := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
		if !strings.EqualFold(id, keyID) && !strings.EqualFold(fp, keyID) {
			result = append(result, entity)
		}
	}
	return result
}
