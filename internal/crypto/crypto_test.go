package crypto

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// testEntity generates a fresh Ed25519 key pair for testing.
func testEntity(t *testing.T) *openpgp.Entity {
	t.Helper()
	entity, err := GenerateKey(KeyGenParams{
		Name:      "Test User",
		Email:     "test@example.com",
		Algorithm: AlgoEd25519,
	})
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return entity
}

// --- Key Generation Tests ---

func TestGenerateKeyEd25519(t *testing.T) {
	entity, err := GenerateKey(KeyGenParams{
		Name:      "Ed User",
		Email:     "ed@example.com",
		Algorithm: AlgoEd25519,
	})
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	if entity.PrivateKey == nil {
		t.Fatal("expected private key")
	}
	if entity.PrimaryKey.PubKeyAlgo != 22 { // EdDSA
		t.Errorf("expected EdDSA algo (22), got %d", entity.PrimaryKey.PubKeyAlgo)
	}
}

func TestGenerateKeyRSA4096(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping RSA key generation in short mode")
	}
	entity, err := GenerateKey(KeyGenParams{
		Name:      "RSA User",
		Email:     "rsa@example.com",
		Algorithm: AlgoRSA4096,
	})
	if err != nil {
		t.Fatalf("generate RSA-4096 key: %v", err)
	}
	if entity.PrivateKey == nil {
		t.Fatal("expected private key")
	}
}

func TestGenerateKeyWithPassphrase(t *testing.T) {
	entity, err := GenerateKey(KeyGenParams{
		Name:       "Pass User",
		Email:      "pass@example.com",
		Algorithm:  AlgoEd25519,
		Passphrase: []byte("testpassphrase"),
	})
	if err != nil {
		t.Fatalf("generate key with passphrase: %v", err)
	}
	if !entity.PrivateKey.Encrypted {
		t.Error("expected primary key to be encrypted")
	}
}

func TestGenerateKeyWithExpiry(t *testing.T) {
	entity, err := GenerateKey(KeyGenParams{
		Name:      "Expiring User",
		Email:     "expiry@example.com",
		Algorithm: AlgoEd25519,
		Lifetime:  365 * 24 * time.Hour, // 1 year
	})
	if err != nil {
		t.Fatalf("generate key with expiry: %v", err)
	}
	for _, id := range entity.Identities {
		if id.SelfSignature == nil || id.SelfSignature.KeyLifetimeSecs == nil {
			t.Fatal("expected key lifetime to be set")
		}
		if *id.SelfSignature.KeyLifetimeSecs == 0 {
			t.Error("expected non-zero key lifetime")
		}
		break
	}
}

func TestGenerateKeyMissingName(t *testing.T) {
	_, err := GenerateKey(KeyGenParams{
		Email:     "noname@example.com",
		Algorithm: AlgoEd25519,
	})
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestGenerateKeyMissingEmail(t *testing.T) {
	_, err := GenerateKey(KeyGenParams{
		Name:      "No Email",
		Algorithm: AlgoEd25519,
	})
	if err == nil {
		t.Fatal("expected error for missing email")
	}
}

// --- Encrypt/Decrypt Round-Trip Tests ---

func TestEncryptDecryptArmored(t *testing.T) {
	entity := testEntity(t)
	plaintext := "Hello, world! This is a test message."

	ciphertext, err := Encrypt(strings.NewReader(plaintext), EncryptParams{
		Recipients: []*openpgp.Entity{entity},
		Armor:      true,
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if !bytes.Contains(ciphertext, []byte("-----BEGIN PGP MESSAGE-----")) {
		t.Error("expected armored output")
	}

	result, err := Decrypt(bytes.NewReader(ciphertext), openpgp.EntityList{entity}, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if string(result.Plaintext) != plaintext {
		t.Errorf("plaintext mismatch: got %q, want %q", result.Plaintext, plaintext)
	}
}

func TestEncryptDecryptBinary(t *testing.T) {
	entity := testEntity(t)
	plaintext := "Binary mode test."

	ciphertext, err := Encrypt(strings.NewReader(plaintext), EncryptParams{
		Recipients: []*openpgp.Entity{entity},
		Armor:      false,
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if bytes.Contains(ciphertext, []byte("-----BEGIN")) {
		t.Error("expected non-armored output")
	}

	result, err := Decrypt(bytes.NewReader(ciphertext), openpgp.EntityList{entity}, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if string(result.Plaintext) != plaintext {
		t.Errorf("plaintext mismatch: got %q, want %q", result.Plaintext, plaintext)
	}
}

func TestEncryptDecryptSymmetric(t *testing.T) {
	passphrase := []byte("symmetric-test-pass")
	plaintext := "Symmetric encryption test."

	ciphertext, err := EncryptSymmetric(strings.NewReader(plaintext), passphrase, true)
	if err != nil {
		t.Fatalf("symmetric encrypt: %v", err)
	}

	result, err := Decrypt(bytes.NewReader(ciphertext), openpgp.EntityList{}, passphrase)
	if err != nil {
		t.Fatalf("symmetric decrypt: %v", err)
	}

	if string(result.Plaintext) != plaintext {
		t.Errorf("plaintext mismatch: got %q, want %q", result.Plaintext, plaintext)
	}
}

func TestEncryptDecryptSignedMessage(t *testing.T) {
	entity := testEntity(t)
	plaintext := "Signed and encrypted message."

	ciphertext, err := Encrypt(strings.NewReader(plaintext), EncryptParams{
		Recipients: []*openpgp.Entity{entity},
		Signer:     entity,
		Armor:      true,
	})
	if err != nil {
		t.Fatalf("encrypt+sign: %v", err)
	}

	result, err := Decrypt(bytes.NewReader(ciphertext), openpgp.EntityList{entity}, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if string(result.Plaintext) != plaintext {
		t.Errorf("plaintext mismatch: got %q, want %q", result.Plaintext, plaintext)
	}
	if !result.IsSigned {
		t.Error("expected message to be signed")
	}
	if !result.SignatureOK {
		t.Error("expected signature to be valid")
	}
}

func TestDecryptEmpty(t *testing.T) {
	_, err := Decrypt(bytes.NewReader(nil), openpgp.EntityList{}, nil)
	if err == nil {
		t.Fatal("expected error for empty ciphertext")
	}
}

// --- Sign/Verify Round-Trip Tests ---

func TestSignVerifyDetachedArmored(t *testing.T) {
	entity := testEntity(t)
	message := "Detached signature test."

	sig, err := Sign(strings.NewReader(message), SignParams{
		Signer:   entity,
		Armor:    true,
		Detached: true,
	})
	if err != nil {
		t.Fatalf("sign detached: %v", err)
	}

	if !bytes.Contains(sig, []byte("-----BEGIN PGP SIGNATURE-----")) {
		t.Error("expected armored signature")
	}

	result, err := VerifyDetached(
		strings.NewReader(message),
		bytes.NewReader(sig),
		openpgp.EntityList{entity},
	)
	if err != nil {
		t.Fatalf("verify detached: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid signature, got: %s", result.Message)
	}
}

func TestSignVerifyDetachedBinary(t *testing.T) {
	entity := testEntity(t)
	message := "Detached binary signature test."

	sig, err := Sign(strings.NewReader(message), SignParams{
		Signer:   entity,
		Armor:    false,
		Detached: true,
	})
	if err != nil {
		t.Fatalf("sign detached binary: %v", err)
	}

	result, err := VerifyDetached(
		strings.NewReader(message),
		bytes.NewReader(sig),
		openpgp.EntityList{entity},
	)
	if err != nil {
		t.Fatalf("verify detached binary: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid signature, got: %s", result.Message)
	}
}

func TestSignVerifyInlineArmored(t *testing.T) {
	entity := testEntity(t)
	message := "Inline signature test."

	sig, err := Sign(strings.NewReader(message), SignParams{
		Signer: entity,
		Armor:  true,
	})
	if err != nil {
		t.Fatalf("sign inline: %v", err)
	}

	if !bytes.Contains(sig, []byte("-----BEGIN PGP MESSAGE-----")) {
		t.Error("expected armored message")
	}

	result, plaintext, err := VerifyInline(
		bytes.NewReader(sig),
		openpgp.EntityList{entity},
	)
	if err != nil {
		t.Fatalf("verify inline: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid signature, got: %s", result.Message)
	}
	if string(plaintext) != message {
		t.Errorf("plaintext mismatch: got %q, want %q", plaintext, message)
	}
}

func TestSignVerifyClearsign(t *testing.T) {
	entity := testEntity(t)
	message := "Clearsign test message."

	sig, err := Sign(strings.NewReader(message), SignParams{
		Signer:    entity,
		Cleartext: true,
	})
	if err != nil {
		t.Fatalf("clearsign: %v", err)
	}

	if !bytes.Contains(sig, []byte("-----BEGIN PGP SIGNED MESSAGE-----")) {
		t.Error("expected clearsign header")
	}

	// Verify through the VerifyInline auto-detect path
	result, plaintext, err := VerifyInline(
		bytes.NewReader(sig),
		openpgp.EntityList{entity},
	)
	if err != nil {
		t.Fatalf("verify clearsign: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected valid signature, got: %s", result.Message)
	}
	if !bytes.Contains(plaintext, []byte("Clearsign test message.")) {
		t.Errorf("expected plaintext to contain original message, got %q", plaintext)
	}

	// Also verify directly through VerifyClearsign
	result2, _, err := VerifyClearsign(sig, openpgp.EntityList{entity})
	if err != nil {
		t.Fatalf("verify clearsign direct: %v", err)
	}
	if !result2.Valid {
		t.Errorf("expected valid clearsign signature, got: %s", result2.Message)
	}
}

func TestSignVerifyDetachedTamperedMessage(t *testing.T) {
	entity := testEntity(t)
	message := "Original message."

	sig, err := Sign(strings.NewReader(message), SignParams{
		Signer:   entity,
		Armor:    true,
		Detached: true,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Verify with tampered message
	result, err := VerifyDetached(
		strings.NewReader("Tampered message!"),
		bytes.NewReader(sig),
		openpgp.EntityList{entity},
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if result.Valid {
		t.Error("expected invalid signature for tampered message")
	}
}

func TestSignRequiresSigner(t *testing.T) {
	_, err := Sign(strings.NewReader("test"), SignParams{})
	if err == nil {
		t.Fatal("expected error for nil signer")
	}
}

// --- isArmored Tests ---

func TestIsArmored(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{"standard armor", "-----BEGIN PGP MESSAGE-----\ndata", true},
		{"with leading whitespace", "   \n  -----BEGIN PGP MESSAGE-----\ndata", true},
		{"public key block", "-----BEGIN PGP PUBLIC KEY BLOCK-----\ndata", true},
		{"binary data", "\x99\x01\x0d\x04\x5f\x5f\x5f", false},
		{"empty", "", false},
		{"random text", "Hello world this is not armored", false},
		{"almost armor", "-----BEGIN PGP", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isArmored([]byte(tt.input))
			if got != tt.expect {
				t.Errorf("isArmored(%q) = %v, want %v", tt.input[:min(len(tt.input), 40)], got, tt.expect)
			}
		})
	}
}

func TestIsArmoredLargeLeadingWhitespace(t *testing.T) {
	// L-05: Ensure we check up to 1024 bytes
	ws := strings.Repeat(" ", 500)
	data := ws + "-----BEGIN PGP MESSAGE-----\n"
	if !isArmored([]byte(data)) {
		t.Error("expected armor detection with 500 bytes of leading whitespace")
	}
}

// --- MaxMessageSize Tests ---

func TestMaxMessageSizeConstant(t *testing.T) {
	if MaxMessageSize != 256<<20 {
		t.Errorf("MaxMessageSize = %d, want %d", MaxMessageSize, 256<<20)
	}
}

// --- isClearsigned Tests ---

func TestIsClearsigned(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{"clearsign header", "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256", true},
		{"with whitespace", "  \n-----BEGIN PGP SIGNED MESSAGE-----\n", true},
		{"regular message", "-----BEGIN PGP MESSAGE-----\n", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isClearsigned([]byte(tt.input))
			if got != tt.expect {
				t.Errorf("isClearsigned(%q) = %v, want %v", tt.input[:min(len(tt.input), 40)], got, tt.expect)
			}
		})
	}
}
