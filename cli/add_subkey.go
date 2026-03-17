package cli

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hamalizer/gpg_go/internal/crypto"
	"github.com/hamalizer/gpg_go/internal/keyring"
	"github.com/spf13/cobra"
)

func newAddSubkeyCmd() *cobra.Command {
	var (
		subkeyType string
		expire     string
	)

	cmd := &cobra.Command{
		Use:   "add-subkey <key-id>",
		Short: "Add a new subkey to an existing key",
		Long: `Add a new encryption or signing subkey to an existing key pair.
This is useful for key rotation — you can add a new encryption subkey
and let the old one expire without changing your primary identity.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			identifier := args[0]

			entity := kr.FindSecretKey(identifier)
			if entity == nil {
				return fmt.Errorf("secret key not found: %s", identifier)
			}

			// Determine subkey type
			var skType crypto.SubkeyType
			switch strings.ToLower(subkeyType) {
			case "encrypt", "encryption":
				skType = crypto.SubkeyEncryption
			case "sign", "signing":
				skType = crypto.SubkeySigning
			default:
				return fmt.Errorf("unknown subkey type %q (use 'encrypt' or 'sign')", subkeyType)
			}

			// If the key is encrypted, prompt for passphrase and decrypt
			var passphrase []byte
			if keyring.IsEntityKeyEncrypted(entity) {
				fmt.Fprint(os.Stderr, "Passphrase: ")
				var pErr error
				passphrase, pErr = readPassphrase()
				if pErr != nil {
					return fmt.Errorf("read passphrase: %w", pErr)
				}
				fmt.Fprintln(os.Stderr)
				defer zeroBytes(passphrase)

				if err := keyring.DecryptEntityKeys(entity, passphrase); err != nil {
					return fmt.Errorf("unlock key: %w", err)
				}
			} else {
				// Prompt for optional passphrase to protect new subkey
				fmt.Fprint(os.Stderr, "Passphrase for new subkey (empty for none): ")
				var pErr error
				passphrase, pErr = readPassphrase()
				if pErr != nil {
					return fmt.Errorf("read passphrase: %w", pErr)
				}
				fmt.Fprintln(os.Stderr)
				if len(passphrase) > 0 {
					fmt.Fprint(os.Stderr, "Repeat passphrase: ")
					p2, pErr2 := readPassphrase()
					if pErr2 != nil {
						zeroBytes(passphrase)
						return fmt.Errorf("read passphrase: %w", pErr2)
					}
					fmt.Fprintln(os.Stderr)
					if !bytes.Equal(passphrase, p2) {
						zeroBytes(passphrase)
						zeroBytes(p2)
						return fmt.Errorf("passphrases do not match")
					}
					zeroBytes(p2)
				}
				defer zeroBytes(passphrase)
			}

			var lifetime time.Duration
			if expire != "" {
				d, pErr := time.ParseDuration(expire)
				if pErr != nil {
					return fmt.Errorf("invalid --expire duration: %w", pErr)
				}
				lifetime = d
			}

			fmt.Fprintf(os.Stderr, "Adding %s subkey to key %s...\n", skType, entity.PrimaryKey.KeyIdString())

			if err := crypto.AddSubkey(entity, skType, lifetime, passphrase); err != nil {
				return fmt.Errorf("add subkey: %w", err)
			}

			// Re-encrypt primary key if it was originally encrypted
			if len(passphrase) > 0 {
				if err := keyring.EncryptEntityKeys(entity, passphrase); err != nil {
					return fmt.Errorf("re-encrypt keys: %w", err)
				}
			}

			// Save updated entity
			if err := kr.UpdateEntity(entity); err != nil {
				return fmt.Errorf("save key: %w", err)
			}

			newSub := entity.Subkeys[len(entity.Subkeys)-1]
			fmt.Fprintf(os.Stderr, "Subkey added: %s\n", newSub.PublicKey.KeyIdString())
			fmt.Println(keyring.KeyInfo(entity))
			return nil
		},
	}

	cmd.Flags().StringVar(&subkeyType, "type", "encrypt", "subkey type: 'encrypt' or 'sign'")
	cmd.Flags().StringVar(&expire, "expire", "", "subkey lifetime (e.g. 8760h for 1 year)")

	return cmd
}
