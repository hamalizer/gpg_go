package keyring

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/hamalizer/gpg_go/internal/config"
)

// Keyring manages the in-memory and on-disk key collections.
type Keyring struct {
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
	return kr.pubKeys
}

func (kr *Keyring) SecretKeys() openpgp.EntityList {
	return kr.secKeys
}

// AllKeys returns all keys (public + secret) as an EntityList for decryption.
func (kr *Keyring) AllKeys() openpgp.EntityList {
	all := make(openpgp.EntityList, 0, len(kr.pubKeys)+len(kr.secKeys))
	all = append(all, kr.pubKeys...)
	all = append(all, kr.secKeys...)
	return all
}

func (kr *Keyring) ImportKey(armoredKey io.Reader) ([]*openpgp.Entity, error) {
	entities, err := openpgp.ReadArmoredKeyRing(armoredKey)
	if err != nil {
		return nil, fmt.Errorf("read armored key: %w", err)
	}

	var imported []*openpgp.Entity
	for _, entity := range entities {
		if entity.PrivateKey != nil {
			if err := kr.store.SavePrivateKey(entity); err != nil {
				return imported, fmt.Errorf("save private key: %w", err)
			}
			kr.secKeys = append(kr.secKeys, entity)
		} else {
			if err := kr.store.SavePublicKey(entity); err != nil {
				return imported, fmt.Errorf("save public key: %w", err)
			}
			kr.pubKeys = append(kr.pubKeys, entity)
		}
		imported = append(imported, entity)
	}
	return imported, nil
}

func (kr *Keyring) AddEntity(entity *openpgp.Entity) error {
	if entity.PrivateKey != nil {
		if err := kr.store.SavePrivateKey(entity); err != nil {
			return err
		}
		kr.secKeys = append(kr.secKeys, entity)
		// Also save public part
		if err := kr.store.SavePublicKey(entity); err != nil {
			return err
		}
		kr.pubKeys = append(kr.pubKeys, entity)
	} else {
		if err := kr.store.SavePublicKey(entity); err != nil {
			return err
		}
		kr.pubKeys = append(kr.pubKeys, entity)
	}
	return nil
}

func (kr *Keyring) FindPublicKey(identifier string) *openpgp.Entity {
	return findKey(kr.pubKeys, identifier)
}

func (kr *Keyring) FindSecretKey(identifier string) *openpgp.Entity {
	return findKey(kr.secKeys, identifier)
}

func (kr *Keyring) DeletePublicKey(keyID string) error {
	if err := kr.store.DeleteKey(keyID, false); err != nil {
		return err
	}
	kr.pubKeys = removeKey(kr.pubKeys, keyID)
	return nil
}

func (kr *Keyring) DeleteSecretKey(keyID string) error {
	if err := kr.store.DeleteKey(keyID, true); err != nil {
		return err
	}
	kr.secKeys = removeKey(kr.secKeys, keyID)
	return nil
}

func (kr *Keyring) ExportPublicKey(identifier string, armored bool) ([]byte, error) {
	entity := kr.FindPublicKey(identifier)
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
		w.Close()
	} else {
		if err := entity.Serialize(&buf); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func (kr *Keyring) ExportSecretKey(identifier string, armored bool) ([]byte, error) {
	entity := kr.FindSecretKey(identifier)
	if entity == nil {
		return nil, fmt.Errorf("secret key not found: %s", identifier)
	}

	var buf bytes.Buffer
	if armored {
		w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
		if err != nil {
			return nil, err
		}
		if err := entity.SerializePrivate(w, nil); err != nil {
			w.Close()
			return nil, err
		}
		w.Close()
	} else {
		if err := entity.SerializePrivate(&buf, nil); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// KeyInfo returns a human-readable summary of a key.
func KeyInfo(entity *openpgp.Entity) string {
	pk := entity.PrimaryKey
	algo := "unknown"
	bits := 0

	switch pk.PubKeyAlgo {
	case 1, 2, 3: // RSA
		algo = "RSA"
		if bl, err := pk.BitLength(); err == nil {
			bits = int(bl)
		}
	case 17: // DSA
		algo = "DSA"
	case 18: // ECDH
		algo = "ECDH"
	case 19: // ECDSA
		algo = "ECDSA"
	case 22: // EdDSA
		algo = "EdDSA"
		bits = 256
	}

	keyID := pk.KeyIdString()
	fingerprint := fmt.Sprintf("%X", pk.Fingerprint)
	created := pk.CreationTime.Format("2006-01-02")

	var uids []string
	for _, id := range entity.Identities {
		uids = append(uids, id.Name)
	}

	hasSecret := ""
	if entity.PrivateKey != nil {
		hasSecret = " [secret]"
	}

	info := fmt.Sprintf("%s%d/%s %s%s\n", algo, bits, keyID, created, hasSecret)
	for _, uid := range uids {
		info += fmt.Sprintf("  uid: %s\n", uid)
	}
	info += fmt.Sprintf("  fingerprint: %s", fingerprint)
	return info
}

func findKey(keys openpgp.EntityList, identifier string) *openpgp.Entity {
	identifier = strings.ToUpper(strings.TrimPrefix(identifier, "0x"))

	for _, entity := range keys {
		keyID := entity.PrimaryKey.KeyIdString()
		fingerprint := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)

		if strings.EqualFold(keyID, identifier) || strings.EqualFold(fingerprint, identifier) {
			return entity
		}

		for _, id := range entity.Identities {
			if strings.Contains(strings.ToLower(id.Name), strings.ToLower(identifier)) {
				return entity
			}
		}
	}
	return nil
}

func removeKey(keys openpgp.EntityList, keyID string) openpgp.EntityList {
	keyID = strings.ToUpper(strings.TrimPrefix(keyID, "0x"))
	var result openpgp.EntityList
	for _, entity := range keys {
		id := entity.PrimaryKey.KeyIdString()
		if !strings.EqualFold(id, keyID) {
			result = append(result, entity)
		}
	}
	return result
}
