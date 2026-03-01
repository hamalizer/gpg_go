// Package crypto provides OpenPGP cryptographic operations.
package crypto

import (
	gocrypto "crypto"
	"fmt"

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
	Name      string
	Comment   string
	Email     string
	Algorithm KeyAlgorithm
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

	return entity, nil
}
