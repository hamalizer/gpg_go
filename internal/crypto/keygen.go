// Package crypto provides OpenPGP cryptographic operations.
package crypto

import (
	gocrypto "crypto"
	"fmt"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type KeyAlgorithm int

const (
	AlgoRSA2048 KeyAlgorithm = iota
	AlgoRSA3072
	AlgoRSA4096
	AlgoEd25519
)

func (a KeyAlgorithm) String() string {
	switch a {
	case AlgoRSA2048:
		return "RSA-2048"
	case AlgoRSA3072:
		return "RSA-3072"
	case AlgoRSA4096:
		return "RSA-4096"
	case AlgoEd25519:
		return "Ed25519"
	default:
		return "unknown"
	}
}

type KeyGenParams struct {
	Name       string
	Comment    string
	Email      string
	Algorithm  KeyAlgorithm
	Passphrase []byte        // If non-nil, encrypts the private key with S2K
	Lifetime   time.Duration // If >0, sets key expiration (e.g. 365*24h for 1 year)
}

func GenerateKey(params KeyGenParams) (*openpgp.Entity, error) {
	if params.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if params.Email == "" {
		return nil, fmt.Errorf("email is required")
	}

	cfg := &packet.Config{
		DefaultHash:   gocrypto.SHA256,
		DefaultCipher: packet.CipherAES256,
	}

	if params.Lifetime > 0 {
		secs := uint32(params.Lifetime.Seconds())
		cfg.KeyLifetimeSecs = secs
	}

	switch params.Algorithm {
	case AlgoRSA2048:
		cfg.Algorithm = packet.PubKeyAlgoRSA
		cfg.RSABits = 2048
	case AlgoRSA3072:
		cfg.Algorithm = packet.PubKeyAlgoRSA
		cfg.RSABits = 3072
	case AlgoRSA4096:
		cfg.Algorithm = packet.PubKeyAlgoRSA
		cfg.RSABits = 4096
	case AlgoEd25519:
		cfg.Algorithm = packet.PubKeyAlgoEdDSA
	default:
		return nil, fmt.Errorf("unsupported algorithm: %d", params.Algorithm)
	}

	entity, err := openpgp.NewEntity(params.Name, params.Comment, params.Email, cfg)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	// Encrypt the private key material with S2K if a passphrase was provided
	if len(params.Passphrase) > 0 {
		if entity.PrivateKey != nil {
			if err := entity.PrivateKey.Encrypt(params.Passphrase); err != nil {
				return nil, fmt.Errorf("encrypt primary key: %w", err)
			}
		}
		for i, sub := range entity.Subkeys {
			if sub.PrivateKey != nil {
				if err := entity.Subkeys[i].PrivateKey.Encrypt(params.Passphrase); err != nil {
					return nil, fmt.Errorf("encrypt subkey: %w", err)
				}
			}
		}
	}

	return entity, nil
}

// AddSubkey generates and adds a new subkey to an existing entity.
// The entity's primary private key must be decrypted before calling this.
// If passphrase is non-nil, the new subkey will be encrypted with it.
func AddSubkey(entity *openpgp.Entity, subkeyType SubkeyType, lifetime time.Duration, passphrase []byte) error {
	if entity.PrivateKey == nil {
		return fmt.Errorf("entity has no private key")
	}
	if entity.PrivateKey.Encrypted {
		return fmt.Errorf("primary key must be decrypted first")
	}

	cfg := &packet.Config{
		DefaultHash:   gocrypto.SHA256,
		DefaultCipher: packet.CipherAES256,
	}
	if lifetime > 0 {
		secs := uint32(lifetime.Seconds())
		cfg.KeyLifetimeSecs = secs
	}

	// Match the algorithm family of the primary key
	switch entity.PrimaryKey.PubKeyAlgo {
	case 1, 2, 3: // RSA
		cfg.Algorithm = packet.PubKeyAlgoRSA
		if bl, err := entity.PrimaryKey.BitLength(); err == nil {
			cfg.RSABits = int(bl)
		} else {
			cfg.RSABits = 4096
		}
	default:
		cfg.Algorithm = packet.PubKeyAlgoEdDSA
	}

	switch subkeyType {
	case SubkeyEncryption:
		if err := entity.AddEncryptionSubkey(cfg); err != nil {
			return fmt.Errorf("add encryption subkey: %w", err)
		}
	case SubkeySigning:
		if err := entity.AddSigningSubkey(cfg); err != nil {
			return fmt.Errorf("add signing subkey: %w", err)
		}
	default:
		return fmt.Errorf("unknown subkey type: %d", subkeyType)
	}

	// Encrypt the new subkey if passphrase provided
	if len(passphrase) > 0 {
		newSub := &entity.Subkeys[len(entity.Subkeys)-1]
		if newSub.PrivateKey != nil {
			if err := newSub.PrivateKey.Encrypt(passphrase); err != nil {
				return fmt.Errorf("encrypt new subkey: %w", err)
			}
		}
	}

	return nil
}

// SubkeyType indicates the purpose of a subkey.
type SubkeyType int

const (
	SubkeyEncryption SubkeyType = iota
	SubkeySigning
)

func (t SubkeyType) String() string {
	switch t {
	case SubkeyEncryption:
		return "encryption"
	case SubkeySigning:
		return "signing"
	default:
		return "unknown"
	}
}

// AddUID adds a new user ID to an existing entity.
// The entity's primary private key must be decrypted before calling this.
func AddUID(entity *openpgp.Entity, name, comment, email string) error {
	if entity.PrivateKey == nil {
		return fmt.Errorf("entity has no private key")
	}
	if entity.PrivateKey.Encrypted {
		return fmt.Errorf("primary key must be decrypted first")
	}

	cfg := &packet.Config{
		DefaultHash:   gocrypto.SHA256,
		DefaultCipher: packet.CipherAES256,
	}

	if err := entity.AddUserId(name, comment, email, cfg); err != nil {
		return fmt.Errorf("add UID: %w", err)
	}
	return nil
}

// SubkeyInfo returns a human-readable summary of a subkey.
func SubkeyInfo(sub openpgp.Subkey) string {
	pk := sub.PublicKey
	algo := "unknown"
	bits := ""

	if bl, err := pk.BitLength(); err == nil && bl > 0 {
		bits = fmt.Sprintf("%d", bl)
	}

	switch pk.PubKeyAlgo {
	case 1, 2, 3:
		algo = "RSA"
	case 18:
		algo = "ECDH"
	case 22:
		algo = "EdDSA"
		if bits == "" {
			bits = "256"
		}
	case 25:
		algo = "X25519"
		if bits == "" {
			bits = "256"
		}
	}

	usage := ""
	if sub.Sig != nil {
		if sub.Sig.FlagEncryptStorage || sub.Sig.FlagEncryptCommunications {
			usage = "[encrypt]"
		}
		if sub.Sig.FlagSign {
			usage = "[sign]"
		}
	}

	created := pk.CreationTime.Format("2006-01-02")
	expiry := ""
	if sub.Sig != nil && sub.Sig.KeyLifetimeSecs != nil && *sub.Sig.KeyLifetimeSecs > 0 {
		exp := pk.CreationTime.Add(time.Duration(*sub.Sig.KeyLifetimeSecs) * time.Second)
		expiry = fmt.Sprintf(" [expires %s]", exp.Format("2006-01-02"))
	}

	return fmt.Sprintf("  sub: %s%s/%s %s %s%s", algo, bits, pk.KeyIdString(), created, usage, expiry)
}
