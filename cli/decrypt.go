package cli

import (
	"bytes"
	"fmt"
	"os"

	"github.com/hamalizer/gpg_go/internal/crypto"
	"github.com/hamalizer/gpg_go/internal/keyring"
	"github.com/spf13/cobra"
)

func newDecryptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "decrypt [file]",
		Aliases: []string{"dec", "-d"},
		Short:   "Decrypt a file or stdin",
		Long:    "Decrypt an OpenPGP encrypted message. Reads from file or stdin.",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			input, err := readInput(args)
			if err != nil {
				return err
			}

			allKeys := kr.AllKeys()

			// Always prompt for passphrase if any secret key is encrypted,
			// to avoid a timing oracle that distinguishes protected vs unprotected keys.
			var passphrase []byte
			hasEncrypted := false
			for _, entity := range kr.SecretKeys() {
				if keyring.IsEntityKeyEncrypted(entity) {
					hasEncrypted = true
					break
				}
			}
			if hasEncrypted {
				fmt.Fprint(os.Stderr, "Passphrase: ")
				var pErr error
				passphrase, pErr = readPassphrase()
				if pErr != nil {
					return fmt.Errorf("read passphrase: %w", pErr)
				}
				fmt.Fprintln(os.Stderr)
				defer zeroBytes(passphrase)
			}

			result, err := crypto.Decrypt(bytes.NewReader(input), allKeys, passphrase)
			if err != nil {
				return fmt.Errorf("decryption failed: %w", err)
			}

			if verbose && result.IsSigned {
				if result.SignatureOK {
					fmt.Fprintln(os.Stderr, "gpg-go: Good signature")
				} else {
					fmt.Fprintln(os.Stderr, "gpg-go: WARNING: Bad signature!")
				}
			}

			return writeOutput(result.Plaintext)
		},
	}

	return cmd
}
