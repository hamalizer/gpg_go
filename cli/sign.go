package cli

import (
	"bytes"
	"fmt"
	"os"

	"github.com/hamalizer/gpg_go/internal/crypto"
	"github.com/hamalizer/gpg_go/internal/keyring"
	"github.com/spf13/cobra"
)

func newSignCmd() *cobra.Command {
	var (
		localUser string
		detach    bool
		clearSign bool
	)

	cmd := &cobra.Command{
		Use:     "sign [file]",
		Aliases: []string{"-s"},
		Short:   "Sign a file or stdin",
		Long:    "Create a digital signature. Supports detached, clear-text, and inline signatures.",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			input, err := readInput(args)
			if err != nil {
				return err
			}

			signer := kr.FindSecretKey(localUser)
			if signer == nil {
				if localUser != "" {
					return fmt.Errorf("secret key not found: %s", localUser)
				}
				// No -u specified: use the most recently created secret key
				// for deterministic behavior regardless of filesystem ordering.
				secKeys := kr.SecretKeys()
				if len(secKeys) == 0 {
					return fmt.Errorf("no secret key available for signing")
				}
				signer = secKeys[0]
				for _, k := range secKeys[1:] {
					if k.PrimaryKey.CreationTime.After(signer.PrimaryKey.CreationTime) {
						signer = k
					}
				}
			}

			// If the signing key is encrypted, prompt for passphrase
			if keyring.IsEntityKeyEncrypted(signer) {
				fmt.Fprint(os.Stderr, "Passphrase: ")
				passphrase, pErr := readPassphrase()
				if pErr != nil {
					return fmt.Errorf("read passphrase: %w", pErr)
				}
				fmt.Fprintln(os.Stderr)
				defer zeroBytes(passphrase)

				if err := keyring.DecryptEntityKeys(signer, passphrase); err != nil {
					return fmt.Errorf("unlock signing key: %w", err)
				}
			}

			result, err := crypto.Sign(bytes.NewReader(input), crypto.SignParams{
				Signer:    signer,
				Armor:     armorFlag,
				Detached:  detach,
				Cleartext: clearSign,
			})
			if err != nil {
				return fmt.Errorf("signing failed: %w", err)
			}

			return writeOutput(result)
		},
	}

	cmd.Flags().StringVarP(&localUser, "local-user", "u", "", "use this key for signing")
	cmd.Flags().BoolVarP(&detach, "detach-sign", "b", false, "create a detached signature")
	cmd.Flags().BoolVar(&clearSign, "clear-sign", false, "create a clear text signature")

	return cmd
}
