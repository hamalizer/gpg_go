package crypto

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type DecryptResult struct {
	Plaintext  []byte
	SignedBy   *openpgp.Key
	Encrypted  bool
	IsSigned   bool
	SignatureOK bool
}

// PromptFunc returns a function that provides the passphrase for decryption.
func PromptFunc(passphrase []byte) func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
	return func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if symmetric {
			return passphrase, nil
		}
		for _, key := range keys {
			if key.PrivateKey != nil && key.PrivateKey.Encrypted {
				if err := key.PrivateKey.Decrypt(passphrase); err != nil {
					return nil, err
				}
			}
		}
		return nil, nil
	}
}

func Decrypt(ciphertext io.Reader, keyring openpgp.KeyRing, passphrase []byte) (*DecryptResult, error) {
	data, err := io.ReadAll(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("read ciphertext: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("empty ciphertext")
	}

	var reader io.Reader
	if isArmored(data) {
		block, err := armor.Decode(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("decode armor: %w", err)
		}
		reader = block.Body
	} else {
		reader = bytes.NewReader(data)
	}

	cfg := &packet.Config{}
	var prompt func([]openpgp.Key, bool) ([]byte, error)
	if passphrase != nil {
		prompt = PromptFunc(passphrase)
	}

	md, err := openpgp.ReadMessage(reader, keyring, prompt, cfg)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("read plaintext: %w", err)
	}

	result := &DecryptResult{
		Plaintext: plaintext,
		Encrypted: md.IsEncrypted,
		IsSigned:  md.IsSigned,
	}

	if md.SignedBy != nil {
		result.SignedBy = md.SignedBy
	}
	if md.SignatureError == nil && md.IsSigned {
		result.SignatureOK = true
	}

	return result, nil
}

func isArmored(data []byte) bool {
	// Trim leading whitespace/newlines, then check for armor header prefix.
	trimmed := bytes.TrimLeft(data[:min(len(data), 100)], " \t\r\n")
	return bytes.HasPrefix(trimmed, []byte("-----BEGIN PGP"))
}
