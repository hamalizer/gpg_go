package crypto

import (
	"bytes"
	"fmt"
	"io"

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

	cfg := &packet.Config{
		DefaultCipher: packet.CipherAES256,
	}

	var output bytes.Buffer
	var writeTarget io.WriteCloser

	if params.Armor {
		armorWriter, err := armor.Encode(&output, "PGP MESSAGE", nil)
		if err != nil {
			return nil, fmt.Errorf("armor encode: %w", err)
		}
		writeTarget = armorWriter
	}

	var encBuf *bytes.Buffer
	if !params.Armor {
		encBuf = &output
	} else {
		encBuf = nil
	}

	var encWriter io.WriteCloser
	var err error
	if params.Armor {
		encWriter, err = openpgp.Encrypt(writeTarget, params.Recipients, params.Signer, nil, cfg)
	} else {
		_ = encBuf
		encWriter, err = openpgp.Encrypt(&output, params.Recipients, params.Signer, nil, cfg)
	}
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

	if params.Armor {
		if err := writeTarget.Close(); err != nil {
			return nil, fmt.Errorf("close armor writer: %w", err)
		}
	}

	return output.Bytes(), nil
}

// EncryptSymmetric encrypts data with a passphrase (symmetric encryption).
func EncryptSymmetric(plaintext io.Reader, passphrase []byte, useArmor bool) ([]byte, error) {
	cfg := &packet.Config{
		DefaultCipher: packet.CipherAES256,
	}

	var output bytes.Buffer
	var writeTarget io.Writer = &output

	var armorWriter io.WriteCloser
	if useArmor {
		var err error
		armorWriter, err = armor.Encode(&output, "PGP MESSAGE", nil)
		if err != nil {
			return nil, fmt.Errorf("armor encode: %w", err)
		}
		writeTarget = armorWriter
	}

	encWriter, err := openpgp.SymmetricallyEncrypt(writeTarget, passphrase, nil, cfg)
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
