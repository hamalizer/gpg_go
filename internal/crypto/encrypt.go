package crypto

import (
	"bytes"
	gocrypto "crypto"
	"fmt"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type EncryptParams struct {
	Recipients []*openpgp.Entity
	Signer     *openpgp.Entity // optional: sign while encrypting
	Armor      bool
}

func Encrypt(plaintext io.Reader, params EncryptParams) ([]byte, error) {
	if len(params.Recipients) == 0 {
		return nil, fmt.Errorf("at least one recipient required")
	}

	// Reject expired recipient keys
	for _, r := range params.Recipients {
		if isEntityExpired(r) {
			uid := ""
			for _, id := range r.Identities {
				uid = id.Name
				break
			}
			return nil, fmt.Errorf("recipient key expired: %s (%s)", r.PrimaryKey.KeyIdString(), uid)
		}
	}

	// Reject expired signer key
	if params.Signer != nil && isEntityExpired(params.Signer) {
		return nil, fmt.Errorf("signing key expired: %s", params.Signer.PrimaryKey.KeyIdString())
	}

	cfg := &packet.Config{
		DefaultHash:   gocrypto.SHA256,
		DefaultCipher: packet.CipherAES256,
	}

	var output bytes.Buffer
	var armorWriter io.WriteCloser
	var encTarget io.Writer = &output

	if params.Armor {
		var err error
		armorWriter, err = armor.Encode(&output, "PGP MESSAGE", nil)
		if err != nil {
			return nil, fmt.Errorf("armor encode: %w", err)
		}
		encTarget = armorWriter
	}

	encWriter, err := openpgp.Encrypt(encTarget, params.Recipients, params.Signer, nil, cfg)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	if _, err := io.Copy(encWriter, plaintext); err != nil {
		encWriter.Close()
		return nil, fmt.Errorf("write plaintext: %w", err)
	}

	if err := encWriter.Close(); err != nil {
		return nil, fmt.Errorf("close encrypt writer: %w", err)
	}

	if armorWriter != nil {
		if err := armorWriter.Close(); err != nil {
			return nil, fmt.Errorf("close armor writer: %w", err)
		}
	}

	return output.Bytes(), nil
}

// isEntityExpired checks if the entity's primary identity self-signature
// contains an expiration time that has passed.
func isEntityExpired(entity *openpgp.Entity) bool {
	for _, id := range entity.Identities {
		if id.SelfSignature != nil && id.SelfSignature.KeyLifetimeSecs != nil && *id.SelfSignature.KeyLifetimeSecs > 0 {
			expiry := entity.PrimaryKey.CreationTime.Add(
				time.Duration(*id.SelfSignature.KeyLifetimeSecs) * time.Second,
			)
			return time.Now().After(expiry)
		}
	}
	return false
}

// EncryptSymmetric encrypts data with a passphrase (symmetric encryption).
func EncryptSymmetric(plaintext io.Reader, passphrase []byte, useArmor bool) ([]byte, error) {
	cfg := &packet.Config{
		DefaultHash:   gocrypto.SHA256,
		DefaultCipher: packet.CipherAES256,
	}

	var output bytes.Buffer
	var armorWriter io.WriteCloser
	var encTarget io.Writer = &output

	if useArmor {
		var err error
		armorWriter, err = armor.Encode(&output, "PGP MESSAGE", nil)
		if err != nil {
			return nil, fmt.Errorf("armor encode: %w", err)
		}
		encTarget = armorWriter
	}

	encWriter, err := openpgp.SymmetricallyEncrypt(encTarget, passphrase, nil, cfg)
	if err != nil {
		return nil, fmt.Errorf("symmetric encrypt: %w", err)
	}

	if _, err := io.Copy(encWriter, plaintext); err != nil {
		encWriter.Close()
		return nil, fmt.Errorf("write plaintext: %w", err)
	}

	if err := encWriter.Close(); err != nil {
		return nil, fmt.Errorf("close encrypt writer: %w", err)
	}

	if armorWriter != nil {
		if err := armorWriter.Close(); err != nil {
			return nil, fmt.Errorf("close armor writer: %w", err)
		}
	}

	return output.Bytes(), nil
}
