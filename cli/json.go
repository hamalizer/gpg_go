package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/hamalizer/gpg_go/internal/keyring"
)

// KeyJSON is the structured representation of a key for JSON output.
type KeyJSON struct {
	KeyID       string   `json:"key_id"`
	Fingerprint string   `json:"fingerprint"`
	Algorithm   string   `json:"algorithm"`
	BitLength   int      `json:"bit_length,omitempty"`
	Created     string   `json:"created"`
	Expires     string   `json:"expires,omitempty"`
	Expired     bool     `json:"expired"`
	HasSecret   bool     `json:"has_secret"`
	UIDs        []string `json:"uids"`
}

// VerifyJSON is the structured representation of a verification result.
type VerifyJSON struct {
	Valid    bool   `json:"valid"`
	SignedBy string `json:"signed_by,omitempty"`
	KeyID    string `json:"key_id,omitempty"`
	Message  string `json:"message"`
}

func entityToJSON(entity *openpgp.Entity) KeyJSON {
	pk := entity.PrimaryKey
	algo := "unknown"
	var bitLen int

	if bl, err := pk.BitLength(); err == nil && bl > 0 {
		bitLen = int(bl)
	}

	switch pk.PubKeyAlgo {
	case 1, 2, 3:
		algo = "RSA"
	case 17:
		algo = "DSA"
	case 18:
		algo = "ECDH"
	case 19:
		algo = "ECDSA"
	case 22:
		algo = "EdDSA"
		if bitLen == 0 {
			bitLen = 256
		}
	}

	kj := KeyJSON{
		KeyID:       pk.KeyIdString(),
		Fingerprint: fmt.Sprintf("%X", pk.Fingerprint),
		Algorithm:   algo,
		BitLength:   bitLen,
		Created:     pk.CreationTime.Format(time.RFC3339),
		HasSecret:   entity.PrivateKey != nil,
		Expired:     keyring.IsKeyExpired(entity),
		UIDs:        keyring.SortedUIDs(entity),
	}

	expiry := keyring.KeyExpiry(entity)
	if !expiry.IsZero() {
		kj.Expires = expiry.Format(time.RFC3339)
	}

	return kj
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
