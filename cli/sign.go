package cli

import (
	"bytes"
	"fmt"

	"github.com/hamalizer/gpg_go/internal/crypto"
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
		RunE: func(cmd *cobra.Command, args []string) error {
			input, err := readInput(args)
			if err != nil {
				return err
			}

			signer := kr.FindSecretKey(localUser)
			if signer == nil {
				// Try first secret key if none specified
				secKeys := kr.SecretKeys()
				if len(secKeys) == 0 {
					return fmt.Errorf("no secret key available for signing")
				}
				if localUser == "" {
					signer = secKeys[0]
				} else {
					return fmt.Errorf("secret key not found: %s", localUser)
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
