package cli

import (
	"bytes"
	"fmt"
	"os"

	"github.com/hamalizer/gpg_go/internal/crypto"
	"github.com/spf13/cobra"
)

func newDecryptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "decrypt [file]",
		Aliases: []string{"dec", "-d"},
		Short:   "Decrypt a file or stdin",
		Long:    "Decrypt an OpenPGP encrypted message. Reads from file or stdin.",
		RunE: func(cmd *cobra.Command, args []string) error {
			input, err := readInput(args)
			if err != nil {
				return err
			}

			allKeys := kr.AllKeys()

			result, err := crypto.Decrypt(bytes.NewReader(input), allKeys, nil)
			if err != nil {
				// May need passphrase
				fmt.Fprint(os.Stderr, "Passphrase: ")
				passphrase := readPassphrase()

				result, err = crypto.Decrypt(bytes.NewReader(input), allKeys, passphrase)
				if err != nil {
					return fmt.Errorf("decryption failed: %w", err)
				}
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
