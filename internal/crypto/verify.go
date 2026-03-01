package crypto

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type VerifyResult struct {
	Valid    bool
	SignedBy *openpgp.Key
	Message  string
}

// VerifyDetached verifies a detached signature.
func VerifyDetached(signed io.Reader, signature io.Reader, keyring openpgp.KeyRing) (*VerifyResult, error) {
	sigData, err := io.ReadAll(signature)
	if err != nil {
		return nil, fmt.Errorf("read signature: %w", err)
	}

	var sigReader io.Reader
	if isArmored(sigData) {
		block, err := armor.Decode(bytes.NewReader(sigData))
		if err != nil {
			return nil, fmt.Errorf("decode armor: %w", err)
		}
		sigReader = block.Body
	} else {
		sigReader = bytes.NewReader(sigData)
	}

	signer, err := openpgp.CheckDetachedSignature(keyring, signed, sigReader, &packet.Config{})
	if err != nil {
		return &VerifyResult{
			Valid:   false,
			Message: fmt.Sprintf("BAD signature: %v", err),
		}, nil
	}

	result := &VerifyResult{
		Valid:   true,
		Message: "Good signature",
	}
	if signer != nil {
		for _, id := range signer.Identities {
			result.Message = fmt.Sprintf("Good signature from \"%s\"", id.Name)
			break
		}
	}

	return result, nil
}

// VerifyInline verifies an inline-signed message and returns the plaintext.
func VerifyInline(signedMsg io.Reader, keyring openpgp.KeyRing) (*VerifyResult, []byte, error) {
	data, err := io.ReadAll(signedMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("read signed message: %w", err)
	}

	var reader io.Reader
	if isArmored(data) {
		block, err := armor.Decode(bytes.NewReader(data))
		if err != nil {
			return nil, nil, fmt.Errorf("decode armor: %w", err)
		}
		reader = block.Body
	} else {
		reader = bytes.NewReader(data)
	}

	md, err := openpgp.ReadMessage(reader, keyring, nil, &packet.Config{})
	if err != nil {
		return nil, nil, fmt.Errorf("read signed message: %w", err)
	}

	plaintext, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, nil, fmt.Errorf("read body: %w", err)
	}

	result := &VerifyResult{
		Valid: md.SignatureError == nil,
	}

	if md.SignedBy != nil {
		result.SignedBy = md.SignedBy
	}

	if md.SignatureError != nil {
		result.Message = fmt.Sprintf("BAD signature: %v", md.SignatureError)
		// Do not return plaintext when signature verification fails.
		return result, nil, nil
	}

	result.Message = "Good signature"
	if md.SignedBy != nil && md.SignedBy.Entity != nil {
		for _, id := range md.SignedBy.Entity.Identities {
			result.Message = fmt.Sprintf("Good signature from \"%s\"", id.Name)
			break
		}
	}

	return result, plaintext, nil
}
