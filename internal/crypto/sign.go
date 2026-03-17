package crypto

import (
	"bytes"
	gocrypto "crypto"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/hamalizer/gpg_go/internal/keyring"
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

	if keyring.IsKeyExpired(params.Signer) {
		return nil, fmt.Errorf("signing key expired: %s", params.Signer.PrimaryKey.KeyIdString())
	}

	cfg := &packet.Config{
		DefaultHash: gocrypto.SHA256,
	}

	if params.Cleartext {
		return cleartextSignMsg(data, params.Signer, cfg)
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

func cleartextSignMsg(data io.Reader, signer *openpgp.Entity, cfg *packet.Config) ([]byte, error) {
	plaintext, err := io.ReadAll(data)
	if err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}

	var buf bytes.Buffer

	// Use the proper clearsign package which handles dash-escaping,
	// hash headers, and line ending normalization per RFC 4880 Section 7.
	w, err := clearsign.Encode(&buf, signer.PrivateKey, cfg)
	if err != nil {
		return nil, fmt.Errorf("clearsign encode: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		w.Close()
		return nil, fmt.Errorf("write cleartext body: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("close clearsign: %w", err)
	}

	return buf.Bytes(), nil
}

func inlineSign(data io.Reader, params SignParams, cfg *packet.Config) ([]byte, error) {
	plaintext, err := io.ReadAll(data)
	if err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}

	var output bytes.Buffer
	var writeTarget io.Writer = &output
	var armorWriter io.WriteCloser

	if params.Armor {
		armorWriter, err = armor.Encode(&output, "PGP MESSAGE", nil)
		if err != nil {
			return nil, fmt.Errorf("armor encode: %w", err)
		}
		writeTarget = armorWriter
	}

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
