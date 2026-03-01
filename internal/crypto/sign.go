package crypto

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type SignParams struct {
	Signer    *openpgp.Entity
	Armor     bool
	Detached  bool
	Cleartext bool
}

// Sign creates a signature over the given data.
func Sign(data io.Reader, params SignParams) ([]byte, error) {
	if params.Signer == nil {
		return nil, fmt.Errorf("signer required")
	}

	if params.Signer.PrivateKey == nil {
		return nil, fmt.Errorf("private key required for signing")
	}

	cfg := &packet.Config{}

	if params.Cleartext {
		return cleartextSign(data, params.Signer, cfg)
	}

	if params.Detached {
		return detachedSign(data, params.Signer, params.Armor, cfg)
	}

	return inlineSign(data, params, cfg)
}

func detachedSign(data io.Reader, signer *openpgp.Entity, useArmor bool, cfg *packet.Config) ([]byte, error) {
	var buf bytes.Buffer

	if useArmor {
		if err := openpgp.ArmoredDetachSign(&buf, signer, data, cfg); err != nil {
			return nil, fmt.Errorf("armored detach sign: %w", err)
		}
	} else {
		if err := openpgp.DetachSign(&buf, signer, data, cfg); err != nil {
			return nil, fmt.Errorf("detach sign: %w", err)
		}
	}

	return buf.Bytes(), nil
}

func cleartextSign(data io.Reader, signer *openpgp.Entity, cfg *packet.Config) ([]byte, error) {
	// Read all data first
	plaintext, err := io.ReadAll(data)
	if err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}

	var buf bytes.Buffer

	// Create a cleartext signed message
	// Header + body + signature
	buf.WriteString("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n")
	buf.Write(plaintext)
	buf.WriteString("\n")

	// Generate detached signature
	var sigBuf bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&sigBuf, signer, bytes.NewReader(plaintext), cfg); err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	buf.Write(sigBuf.Bytes())

	return buf.Bytes(), nil
}

func inlineSign(data io.Reader, params SignParams, cfg *packet.Config) ([]byte, error) {
	// For inline signing, we encrypt to no one but sign
	plaintext, err := io.ReadAll(data)
	if err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}

	var output bytes.Buffer
	var writeTarget io.Writer = &output
	var armorWriter io.WriteCloser

	if params.Armor {
		var err error
		armorWriter, err = armor.Encode(&output, "PGP MESSAGE", nil)
		if err != nil {
			return nil, fmt.Errorf("armor encode: %w", err)
		}
		writeTarget = armorWriter
	}

	// Sign-only message: encrypt to empty recipient list with signer
	w, err := openpgp.Sign(writeTarget, params.Signer, nil, cfg)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		w.Close()
		return nil, fmt.Errorf("write: %w", err)
	}

	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("close signer: %w", err)
	}

	if armorWriter != nil {
		if err := armorWriter.Close(); err != nil {
			return nil, fmt.Errorf("close armor: %w", err)
		}
	}

	return output.Bytes(), nil
}
