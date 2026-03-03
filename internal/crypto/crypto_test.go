package crypto

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// genEd25519 generates a fresh Ed25519 key pair for testing.
func genEd25519(t *testing.T, name, email string) *openpgp.Entity {
	t.Helper()
	e, err := GenerateKey(KeyGenParams{
		Name:      name,
		Email:     email,
		Algorithm: AlgoEd25519,
	})
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	return e
}

// genRSA4096 generates a fresh RSA-4096 key pair for testing.
func genRSA4096(t *testing.T, name, email string) *openpgp.Entity {
	t.Helper()
	e, err := GenerateKey(KeyGenParams{
		Name:      name,
		Email:     email,
		Algorithm: AlgoRSA4096,
	})
	if err != nil {
		t.Fatalf("generate RSA-4096 key: %v", err)
	}
	return e
}

// entityList wraps entities into an openpgp.EntityList (implements
// openpgp.KeyRing).
func entityList(entities ...*openpgp.Entity) openpgp.EntityList {
	return openpgp.EntityList(entities)
}

// ---------------------------------------------------------------------------
// 1. Key generation
// ---------------------------------------------------------------------------

func TestGenerateKey_Ed25519(t *testing.T) {
	e := genEd25519(t, "Alice", "alice@example.com")
	if e.PrivateKey == nil {
		t.Fatal("expected private key to be present")
	}
	if len(e.Identities) == 0 {
		t.Fatal("expected at least one identity")
	}
	for _, id := range e.Identities {
		if !strings.Contains(id.Name, "Alice") {
			t.Errorf("identity name %q does not contain Alice", id.Name)
		}
		break
	}
	// Verify the algorithm is EdDSA (22).
	if e.PrimaryKey.PubKeyAlgo != 22 {
		t.Errorf("expected EdDSA algo (22), got %d", e.PrimaryKey.PubKeyAlgo)
	}
}

func TestGenerateKey_RSA4096(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping RSA-4096 key generation in short mode")
	}
	e := genRSA4096(t, "Bob", "bob@example.com")
	if e.PrivateKey == nil {
		t.Fatal("expected private key to be present")
	}
	if len(e.Identities) == 0 {
		t.Fatal("expected at least one identity")
	}
}

func TestGenerateKey_WithExpiry(t *testing.T) {
	lifetime := 365 * 24 * time.Hour
	e, err := GenerateKey(KeyGenParams{
		Name:      "Expiry Test",
		Email:     "expiry@example.com",
		Algorithm: AlgoEd25519,
		Lifetime:  lifetime,
	})
	if err != nil {
		t.Fatalf("generate key with expiry: %v", err)
	}
	for _, id := range e.Identities {
		if id.SelfSignature == nil {
			t.Fatal("expected self-signature")
		}
		if id.SelfSignature.KeyLifetimeSecs == nil || *id.SelfSignature.KeyLifetimeSecs == 0 {
			t.Fatal("expected non-zero KeyLifetimeSecs on self-signature")
		}
		got := time.Duration(*id.SelfSignature.KeyLifetimeSecs) * time.Second
		if got != lifetime {
			t.Errorf("expected lifetime %v, got %v", lifetime, got)
		}
		break
	}
}

func TestGenerateKey_NoExpiry(t *testing.T) {
	e := genEd25519(t, "NoExpiry", "noexpiry@example.com")
	for _, id := range e.Identities {
		if id.SelfSignature != nil && id.SelfSignature.KeyLifetimeSecs != nil && *id.SelfSignature.KeyLifetimeSecs > 0 {
			t.Fatal("expected no expiry on key")
		}
		break
	}
}

func TestGenerateKey_WithPassphrase(t *testing.T) {
	passphrase := []byte("super-secret")
	e, err := GenerateKey(KeyGenParams{
		Name:       "Passphrase User",
		Email:      "pass@example.com",
		Algorithm:  AlgoEd25519,
		Passphrase: passphrase,
	})
	if err != nil {
		t.Fatalf("generate key with passphrase: %v", err)
	}
	if e.PrivateKey == nil {
		t.Fatal("expected private key to be present")
	}
	if !e.PrivateKey.Encrypted {
		t.Fatal("expected primary private key to be encrypted")
	}
	for _, sub := range e.Subkeys {
		if sub.PrivateKey != nil && !sub.PrivateKey.Encrypted {
			t.Fatal("expected subkey private key to be encrypted")
		}
	}
}

func TestGenerateKey_WithoutPassphrase(t *testing.T) {
	e := genEd25519(t, "NoPass", "nopass@example.com")
	if e.PrivateKey.Encrypted {
		t.Fatal("expected primary private key to NOT be encrypted")
	}
}

func TestGenerateKey_MissingName(t *testing.T) {
	_, err := GenerateKey(KeyGenParams{
		Email:     "noname@example.com",
		Algorithm: AlgoEd25519,
	})
	if err == nil {
		t.Fatal("expected error when name is empty")
	}
}

func TestGenerateKey_MissingEmail(t *testing.T) {
	_, err := GenerateKey(KeyGenParams{
		Name:      "NoEmail",
		Algorithm: AlgoEd25519,
	})
	if err == nil {
		t.Fatal("expected error when email is empty")
	}
}

// ---------------------------------------------------------------------------
// 2. Encrypt / Decrypt round-trip
// ---------------------------------------------------------------------------

func TestEncryptDecrypt_Armored(t *testing.T) {
	key := genEd25519(t, "EncTest", "enc@example.com")
	original := "Hello, armored encryption!"

	ciphertext, err := Encrypt(strings.NewReader(original), EncryptParams{
		Recipients: []*openpgp.Entity{key},
		Armor:      true,
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if !bytes.Contains(ciphertext, []byte("-----BEGIN PGP MESSAGE-----")) {
		t.Fatal("expected armored output")
	}

	result, err := Decrypt(bytes.NewReader(ciphertext), entityList(key), nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(result.Plaintext) != original {
		t.Errorf("plaintext mismatch: got %q, want %q", result.Plaintext, original)
	}
	if !result.Encrypted {
		t.Error("expected Encrypted flag to be true")
	}
}

func TestEncryptDecrypt_Binary(t *testing.T) {
	key := genEd25519(t, "BinEnc", "binenc@example.com")
	original := "Hello, binary encryption!"

	ciphertext, err := Encrypt(strings.NewReader(original), EncryptParams{
		Recipients: []*openpgp.Entity{key},
		Armor:      false,
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if bytes.Contains(ciphertext, []byte("-----BEGIN PGP")) {
		t.Fatal("expected binary (non-armored) output")
	}

	result, err := Decrypt(bytes.NewReader(ciphertext), entityList(key), nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(result.Plaintext) != original {
		t.Errorf("plaintext mismatch: got %q, want %q", result.Plaintext, original)
	}
}

func TestEncryptDecrypt_SignedAndEncrypted(t *testing.T) {
	sender := genEd25519(t, "Sender", "sender@example.com")
	recipient := genEd25519(t, "Recipient", "recipient@example.com")
	original := "signed and encrypted payload"

	ciphertext, err := Encrypt(strings.NewReader(original), EncryptParams{
		Recipients: []*openpgp.Entity{recipient},
		Signer:     sender,
		Armor:      true,
	})
	if err != nil {
		t.Fatalf("encrypt+sign: %v", err)
	}

	// Decrypt with recipient key; pass sender in keyring for signature verification.
	kr := entityList(recipient, sender)
	result, err := Decrypt(bytes.NewReader(ciphertext), kr, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(result.Plaintext) != original {
		t.Errorf("plaintext mismatch: got %q, want %q", result.Plaintext, original)
	}
	if !result.Encrypted {
		t.Error("expected Encrypted flag")
	}
	if !result.IsSigned {
		t.Error("expected IsSigned flag")
	}
	if !result.SignatureOK {
		t.Error("expected SignatureOK flag")
	}
}

func TestEncryptDecrypt_Symmetric_Armored(t *testing.T) {
	passphrase := []byte("symmetric-secret")
	original := "symmetric armored payload"

	ciphertext, err := EncryptSymmetric(strings.NewReader(original), passphrase, true)
	if err != nil {
		t.Fatalf("symmetric encrypt: %v", err)
	}

	if !bytes.Contains(ciphertext, []byte("-----BEGIN PGP MESSAGE-----")) {
		t.Fatal("expected armored output")
	}

	result, err := Decrypt(bytes.NewReader(ciphertext), nil, passphrase)
	if err != nil {
		t.Fatalf("symmetric decrypt: %v", err)
	}
	if string(result.Plaintext) != original {
		t.Errorf("plaintext mismatch: got %q, want %q", result.Plaintext, original)
	}
}

func TestEncryptDecrypt_Symmetric_Binary(t *testing.T) {
	passphrase := []byte("symmetric-binary-secret")
	original := "symmetric binary payload"

	ciphertext, err := EncryptSymmetric(strings.NewReader(original), passphrase, false)
	if err != nil {
		t.Fatalf("symmetric encrypt: %v", err)
	}

	if bytes.Contains(ciphertext, []byte("-----BEGIN PGP")) {
		t.Fatal("expected binary (non-armored) output")
	}

	result, err := Decrypt(bytes.NewReader(ciphertext), nil, passphrase)
	if err != nil {
		t.Fatalf("symmetric decrypt: %v", err)
	}
	if string(result.Plaintext) != original {
		t.Errorf("plaintext mismatch: got %q, want %q", result.Plaintext, original)
	}
}

func TestEncryptDecrypt_WithPassphraseProtectedKey(t *testing.T) {
	passphrase := []byte("key-passphrase")
	key, err := GenerateKey(KeyGenParams{
		Name:       "PassKey",
		Email:      "passkey@example.com",
		Algorithm:  AlgoEd25519,
		Passphrase: passphrase,
	})
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	original := "encrypted with passphrase-protected key"

	// Encryption uses the public key of the recipient, so it works regardless.
	ciphertext, err := Encrypt(strings.NewReader(original), EncryptParams{
		Recipients: []*openpgp.Entity{key},
		Armor:      true,
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Decrypt requires the passphrase to unlock the private key.
	result, err := Decrypt(bytes.NewReader(ciphertext), entityList(key), passphrase)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(result.Plaintext) != original {
		t.Errorf("plaintext mismatch: got %q, want %q", result.Plaintext, original)
	}
}

func TestEncrypt_NoRecipients(t *testing.T) {
	_, err := Encrypt(strings.NewReader("data"), EncryptParams{
		Armor: true,
	})
	if err == nil {
		t.Fatal("expected error with no recipients")
	}
}

func TestDecrypt_EmptyCiphertext(t *testing.T) {
	_, err := Decrypt(bytes.NewReader(nil), entityList(), nil)
	if err == nil {
		t.Fatal("expected error on empty ciphertext")
	}
}

// ---------------------------------------------------------------------------
// 3. Sign / Verify round-trip
// ---------------------------------------------------------------------------

func TestSignVerify_DetachedArmored(t *testing.T) {
	key := genEd25519(t, "Signer", "signer@example.com")
	message := "This message will be detach-signed (armored)."

	sig, err := Sign(strings.NewReader(message), SignParams{
		Signer:   key,
		Armor:    true,
		Detached: true,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !bytes.Contains(sig, []byte("-----BEGIN PGP SIGNATURE-----")) {
		t.Fatal("expected armored signature")
	}

	vr, err := VerifyDetached(
		strings.NewReader(message),
		bytes.NewReader(sig),
		entityList(key),
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !vr.Valid {
		t.Errorf("expected valid signature, got: %s", vr.Message)
	}
}

func TestSignVerify_DetachedBinary(t *testing.T) {
	key := genEd25519(t, "BinSigner", "binsigner@example.com")
	message := "This message will be detach-signed (binary)."

	sig, err := Sign(strings.NewReader(message), SignParams{
		Signer:   key,
		Armor:    false,
		Detached: true,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if bytes.Contains(sig, []byte("-----BEGIN PGP")) {
		t.Fatal("expected binary (non-armored) signature")
	}

	vr, err := VerifyDetached(
		strings.NewReader(message),
		bytes.NewReader(sig),
		entityList(key),
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !vr.Valid {
		t.Errorf("expected valid signature, got: %s", vr.Message)
	}
}

func TestSignVerify_DetachedWrongKey(t *testing.T) {
	signer := genEd25519(t, "RealSigner", "real@example.com")
	wrongKey := genEd25519(t, "WrongKey", "wrong@example.com")
	message := "signed by someone else"

	sig, err := Sign(strings.NewReader(message), SignParams{
		Signer:   signer,
		Armor:    true,
		Detached: true,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	vr, err := VerifyDetached(
		strings.NewReader(message),
		bytes.NewReader(sig),
		entityList(wrongKey),
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if vr.Valid {
		t.Error("expected invalid signature when verifying with wrong key")
	}
}

func TestSignVerify_DetachedTamperedMessage(t *testing.T) {
	key := genEd25519(t, "TamperSigner", "tamper@example.com")
	message := "original message"

	sig, err := Sign(strings.NewReader(message), SignParams{
		Signer:   key,
		Armor:    true,
		Detached: true,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	tampered := "tampered message"
	vr, err := VerifyDetached(
		strings.NewReader(tampered),
		bytes.NewReader(sig),
		entityList(key),
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if vr.Valid {
		t.Error("expected invalid signature for tampered message")
	}
}

func TestSignVerify_InlineArmored(t *testing.T) {
	key := genEd25519(t, "InlineSigner", "inline@example.com")
	message := "This message will be inline-signed."

	signedMsg, err := Sign(strings.NewReader(message), SignParams{
		Signer: key,
		Armor:  true,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !bytes.Contains(signedMsg, []byte("-----BEGIN PGP MESSAGE-----")) {
		t.Fatal("expected armored PGP message")
	}

	vr, plaintext, err := VerifyInline(bytes.NewReader(signedMsg), entityList(key))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !vr.Valid {
		t.Errorf("expected valid signature, got: %s", vr.Message)
	}
	if string(plaintext) != message {
		t.Errorf("plaintext mismatch: got %q, want %q", plaintext, message)
	}
}

func TestSignVerify_Clearsign(t *testing.T) {
	key := genEd25519(t, "ClearSigner", "clear@example.com")
	message := "This message will be clearsigned."

	signedMsg, err := Sign(strings.NewReader(message), SignParams{
		Signer:    key,
		Cleartext: true,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !bytes.Contains(signedMsg, []byte("-----BEGIN PGP SIGNED MESSAGE-----")) {
		t.Fatal("expected clearsign header")
	}

	// Verify via VerifyClearsign directly.
	vr, plaintext, err := VerifyClearsign(signedMsg, entityList(key))
	if err != nil {
		t.Fatalf("verify clearsign: %v", err)
	}
	if !vr.Valid {
		t.Errorf("expected valid signature, got: %s", vr.Message)
	}
	if !bytes.Contains(plaintext, []byte(message)) {
		t.Errorf("plaintext does not contain original message: got %q", plaintext)
	}
}

func TestSignVerify_ClearsignViaVerifyInline(t *testing.T) {
	key := genEd25519(t, "ClearInline", "clearinline@example.com")
	message := "Clearsign routed through VerifyInline."

	signedMsg, err := Sign(strings.NewReader(message), SignParams{
		Signer:    key,
		Cleartext: true,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// VerifyInline should auto-detect clearsigned messages and delegate.
	vr, plaintext, err := VerifyInline(bytes.NewReader(signedMsg), entityList(key))
	if err != nil {
		t.Fatalf("verify inline (clearsign): %v", err)
	}
	if !vr.Valid {
		t.Errorf("expected valid signature, got: %s", vr.Message)
	}
	if !bytes.Contains(plaintext, []byte(message)) {
		t.Errorf("plaintext does not contain original message: got %q", plaintext)
	}
}

func TestSign_NilSigner(t *testing.T) {
	_, err := Sign(strings.NewReader("data"), SignParams{})
	if err == nil {
		t.Fatal("expected error with nil signer")
	}
}

// ---------------------------------------------------------------------------
// 4. Expired key rejection
// ---------------------------------------------------------------------------

func TestExpiredKeyRejection_Encrypt(t *testing.T) {
	// Generate a key with a 1-second lifetime.
	key, err := GenerateKey(KeyGenParams{
		Name:      "ShortLived",
		Email:     "short@example.com",
		Algorithm: AlgoEd25519,
		Lifetime:  1 * time.Second,
	})
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Wait for the key to expire.
	time.Sleep(2 * time.Second)

	_, err = Encrypt(strings.NewReader("test"), EncryptParams{
		Recipients: []*openpgp.Entity{key},
		Armor:      true,
	})
	if err == nil {
		t.Fatal("expected error encrypting to expired key")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected 'expired' in error, got: %v", err)
	}
}

func TestExpiredKeyRejection_Sign(t *testing.T) {
	key, err := GenerateKey(KeyGenParams{
		Name:      "ShortSignKey",
		Email:     "shortsign@example.com",
		Algorithm: AlgoEd25519,
		Lifetime:  1 * time.Second,
	})
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	time.Sleep(2 * time.Second)

	_, err = Sign(strings.NewReader("test"), SignParams{
		Signer:   key,
		Detached: true,
		Armor:    true,
	})
	if err == nil {
		t.Fatal("expected error signing with expired key")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected 'expired' in error, got: %v", err)
	}
}

func TestExpiredKeyRejection_EncryptWithExpiredSigner(t *testing.T) {
	recipient := genEd25519(t, "ValidRecip", "validrecip@example.com")
	signer, err := GenerateKey(KeyGenParams{
		Name:      "ExpiredSigner",
		Email:     "expiredsigner@example.com",
		Algorithm: AlgoEd25519,
		Lifetime:  1 * time.Second,
	})
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	time.Sleep(2 * time.Second)

	_, err = Encrypt(strings.NewReader("test"), EncryptParams{
		Recipients: []*openpgp.Entity{recipient},
		Signer:     signer,
		Armor:      true,
	})
	if err == nil {
		t.Fatal("expected error encrypting with expired signer key")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected 'expired' in error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 5. isArmored detection
// ---------------------------------------------------------------------------

func TestIsArmored(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "armored PGP message",
			data: []byte("-----BEGIN PGP MESSAGE-----\nsomething\n-----END PGP MESSAGE-----"),
			want: true,
		},
		{
			name: "armored PGP signature",
			data: []byte("-----BEGIN PGP SIGNATURE-----\nsomething"),
			want: true,
		},
		{
			name: "armored PGP public key",
			data: []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\nsomething"),
			want: true,
		},
		{
			name: "leading spaces",
			data: []byte("   -----BEGIN PGP MESSAGE-----\nsomething"),
			want: true,
		},
		{
			name: "leading tabs",
			data: []byte("\t\t-----BEGIN PGP MESSAGE-----\nsomething"),
			want: true,
		},
		{
			name: "leading newlines",
			data: []byte("\n\n\n-----BEGIN PGP MESSAGE-----\nsomething"),
			want: true,
		},
		{
			name: "leading mixed whitespace",
			data: []byte("  \t\r\n  -----BEGIN PGP MESSAGE-----\nsomething"),
			want: true,
		},
		{
			name: "large leading whitespace within 1024 byte window",
			data: append([]byte(strings.Repeat(" ", 500)), []byte("-----BEGIN PGP MESSAGE-----\n")...),
			want: true,
		},
		{
			name: "binary data",
			data: []byte{0x99, 0x01, 0x0d, 0x04, 0x5f},
			want: false,
		},
		{
			name: "plain text",
			data: []byte("Hello, World!"),
			want: false,
		},
		{
			name: "almost armored - wrong prefix",
			data: []byte("-----BEGIN SOMETHING-----"),
			want: false,
		},
		{
			name: "empty input",
			data: []byte{},
			want: false,
		},
		{
			name: "only whitespace",
			data: []byte("   \t\r\n   "),
			want: false,
		},
		{
			name: "prefix only (no full header)",
			data: []byte("-----BEGIN PGP"),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isArmored(tt.data)
			if got != tt.want {
				truncated := string(tt.data)
				if len(truncated) > 40 {
					truncated = truncated[:40] + "..."
				}
				t.Errorf("isArmored(%q) = %v, want %v", truncated, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 6. Decompression bomb protection: MaxMessageSize constant
// ---------------------------------------------------------------------------

func TestMaxMessageSize(t *testing.T) {
	expected := 256 << 20 // 256 MiB
	if MaxMessageSize != expected {
		t.Errorf("MaxMessageSize = %d, want %d", MaxMessageSize, expected)
	}
}

// ---------------------------------------------------------------------------
// isClearsigned detection
// ---------------------------------------------------------------------------

func TestIsClearsigned(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		{"clearsign header", "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256", true},
		{"with leading whitespace", "  \n-----BEGIN PGP SIGNED MESSAGE-----\n", true},
		{"regular message", "-----BEGIN PGP MESSAGE-----\n", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isClearsigned([]byte(tt.input))
			if got != tt.expect {
				t.Errorf("isClearsigned(%q) = %v, want %v", tt.input, got, tt.expect)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Additional round-trip tests with RSA-4096
// ---------------------------------------------------------------------------

func TestEncryptDecrypt_RSA4096(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping RSA-4096 round-trip in short mode")
	}
	key := genRSA4096(t, "RSAUser", "rsa@example.com")
	original := "RSA-4096 round-trip test"

	ciphertext, err := Encrypt(strings.NewReader(original), EncryptParams{
		Recipients: []*openpgp.Entity{key},
		Armor:      true,
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	result, err := Decrypt(bytes.NewReader(ciphertext), entityList(key), nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(result.Plaintext) != original {
		t.Errorf("plaintext mismatch: got %q, want %q", result.Plaintext, original)
	}
}

func TestSignVerify_RSA4096_Detached(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping RSA-4096 sign/verify in short mode")
	}
	key := genRSA4096(t, "RSASigner", "rsasign@example.com")
	message := "RSA-4096 detached signature test"

	sig, err := Sign(strings.NewReader(message), SignParams{
		Signer:   key,
		Armor:    true,
		Detached: true,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	vr, err := VerifyDetached(
		strings.NewReader(message),
		bytes.NewReader(sig),
		entityList(key),
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !vr.Valid {
		t.Errorf("expected valid signature, got: %s", vr.Message)
	}
}
