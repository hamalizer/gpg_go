package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/hamalizer/gpg_go/internal/crypto"
	"github.com/hamalizer/gpg_go/internal/keyring"
	"github.com/spf13/cobra"
)

func newAddUIDCmd() *cobra.Command {
	var (
		name    string
		email   string
		comment string
	)

	cmd := &cobra.Command{
		Use:   "add-uid <key-id>",
		Short: "Add a new user ID to an existing key",
		Long: `Add an additional user identity (name + email) to an existing key pair.
This lets you associate multiple email addresses with a single key
instead of maintaining separate keys.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			identifier := args[0]

			entity := kr.FindSecretKey(identifier)
			if entity == nil {
				return fmt.Errorf("secret key not found: %s", identifier)
			}

			// Interactive prompts for missing fields
			reader := bufio.NewReader(os.Stdin)
			if name == "" {
				fmt.Fprint(os.Stderr, "Real name: ")
				var err error
				name, err = reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("read name: %w", err)
				}
				name = strings.TrimSpace(name)
			}
			if email == "" {
				fmt.Fprint(os.Stderr, "Email address: ")
				var err error
				email, err = reader.ReadString('\n')
				if err != nil {
					return fmt.Errorf("read email: %w", err)
				}
				email = strings.TrimSpace(email)
			}
			if comment == "" {
				fmt.Fprint(os.Stderr, "Comment (optional): ")
				comment, _ = reader.ReadString('\n')
				comment = strings.TrimSpace(comment)
			}

			if name == "" || email == "" {
				return fmt.Errorf("name and email are required")
			}

			// If the key is encrypted, prompt for passphrase
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

				// Add UID then re-encrypt
				if err := crypto.AddUID(entity, name, comment, email); err != nil {
					return err
				}
				if err := keyring.EncryptEntityKeys(entity, passphrase); err != nil {
					return fmt.Errorf("re-encrypt keys: %w", err)
				}
			} else {
				if err := crypto.AddUID(entity, name, comment, email); err != nil {
					return err
				}
			}

			// Save updated entity
			if err := kr.UpdateEntity(entity); err != nil {
				return fmt.Errorf("save key: %w", err)
			}

			fmt.Fprintf(os.Stderr, "UID added: %s <%s>\n", name, email)
			fmt.Println(keyring.KeyInfo(entity))
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "real name for the new UID")
	cmd.Flags().StringVar(&email, "email", "", "email address for the new UID")
	cmd.Flags().StringVar(&comment, "comment", "", "optional comment")

	return cmd
}
