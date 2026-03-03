package cli

import (
	"bytes"
	"fmt"
	"os"

	"github.com/hamalizer/gpg_go/internal/keyring"
	"github.com/spf13/cobra"
)

func newImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "import [file]",
		Aliases: []string{"recv"},
		Short:   "Import keys from a file",
		Long:    "Import public or private keys from an armored key file. Reads from file or stdin.",
		RunE: func(cmd *cobra.Command, args []string) error {
			input, err := readInput(args)
			if err != nil {
				return err
			}

			imported, err := kr.ImportKey(bytes.NewReader(input))
			if err != nil {
				return fmt.Errorf("import failed: %w", err)
			}

			fmt.Printf("Imported %d key(s):\n", len(imported))
			for _, entity := range imported {
				fmt.Println(keyring.KeyInfo(entity))
				fmt.Println()
			}
			return nil
		},
	}

	return cmd
}

func newExportCmd() *cobra.Command {
	var exportSecret bool

	cmd := &cobra.Command{
		Use:   "export <key-id>",
		Short: "Export keys to stdout",
		Long:  "Export public or secret keys in armored format.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			identifier := args[0]

			if exportSecret {
				// Require passphrase confirmation before exporting secret key material
				entity := kr.FindSecretKey(identifier)
				if entity == nil {
					return fmt.Errorf("secret key not found: %s", identifier)
				}
				if keyring.IsEntityKeyEncrypted(entity) {
					fmt.Fprint(os.Stderr, "Passphrase (confirm identity): ")
					passphrase, pErr := readPassphrase()
					if pErr != nil {
						return fmt.Errorf("read passphrase: %w", pErr)
					}
					fmt.Fprintln(os.Stderr)
					defer zeroBytes(passphrase)

					// Verify the passphrase is correct by trying to decrypt,
					// but we don't actually need the decrypted key — just proof of knowledge.
					if err := keyring.DecryptEntityKeys(entity, passphrase); err != nil {
						return fmt.Errorf("wrong passphrase")
					}
					// Re-encrypt so the exported key is still protected
					if err := keyring.EncryptEntityKeys(entity, passphrase); err != nil {
						return fmt.Errorf("re-encrypt key: %w", err)
					}
				}

				data, err := kr.ExportSecretKey(identifier, true)
				if err != nil {
					return err
				}
				return writeOutput(data)
			}

			data, err := kr.ExportPublicKey(identifier, true)
			if err != nil {
				return err
			}
			return writeOutput(data)
		},
	}

	cmd.Flags().BoolVar(&exportSecret, "secret", false, "export secret key")
	return cmd
}
