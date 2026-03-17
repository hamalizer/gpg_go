package cli

import (
	"bytes"
	gocrypto "crypto"
	"fmt"
	"os"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/hamalizer/gpg_go/internal/keyring"
	"github.com/spf13/cobra"
)

func newRevokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gen-revoke <key-id>",
		Short: "Generate a revocation certificate",
		Long:  "Generate a revocation certificate for a key. Store this safely — it can be used to revoke your key if it is ever compromised.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			identifier := args[0]

			entity := kr.FindSecretKey(identifier)
			if entity == nil {
				return fmt.Errorf("secret key not found: %s", identifier)
			}

			// If the key is encrypted, prompt for passphrase and decrypt
			if keyring.IsEntityKeyEncrypted(entity) {
				fmt.Fprint(os.Stderr, "Passphrase: ")
				passphrase, pErr := readPassphrase()
				if pErr != nil {
					return fmt.Errorf("read passphrase: %w", pErr)
				}
				fmt.Fprintln(os.Stderr)
				defer zeroBytes(passphrase)

				if err := keyring.DecryptEntityKeys(entity, passphrase); err != nil {
					return fmt.Errorf("unlock key: %w", err)
				}
			}

			// Create a revocation signature
			sig := &packet.Signature{
				Version:      entity.PrimaryKey.Version,
				SigType:      packet.SigTypeKeyRevocation,
				PubKeyAlgo:   entity.PrimaryKey.PubKeyAlgo,
				Hash:         gocrypto.SHA256,
				CreationTime: time.Now(),
				IssuerKeyId:  &entity.PrimaryKey.KeyId,
			}

			if err := sig.SignKey(entity.PrimaryKey, entity.PrivateKey, nil); err != nil {
				return fmt.Errorf("sign revocation: %w", err)
			}

			// Serialize the public key and revocation signature into an armored block
			var buf bytes.Buffer
			armorWriter, err := armor.Encode(&buf, "PGP PUBLIC KEY BLOCK", nil)
			if err != nil {
				return fmt.Errorf("create armor writer: %w", err)
			}

			if err := entity.PrimaryKey.Serialize(armorWriter); err != nil {
				armorWriter.Close()
				return fmt.Errorf("serialize public key: %w", err)
			}

			if err := sig.Serialize(armorWriter); err != nil {
				armorWriter.Close()
				return fmt.Errorf("serialize revocation signature: %w", err)
			}

			if err := armorWriter.Close(); err != nil {
				return fmt.Errorf("close armor writer: %w", err)
			}

			fmt.Fprintln(os.Stderr, "Revocation certificate generated.")
			fmt.Fprintln(os.Stderr, "Store this certificate securely. If your key is compromised,")
			fmt.Fprintln(os.Stderr, "you can publish this to revoke it.")

			return writeOutput(buf.Bytes())
		},
	}

	return cmd
}
