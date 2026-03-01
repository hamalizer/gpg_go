package cli

import (
	"bytes"
	"fmt"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/hamalizer/gpg_go/internal/crypto"
	"github.com/spf13/cobra"
)

func newEncryptCmd() *cobra.Command {
	var (
		recipients []string
		signWith   string
		symmetric  bool
	)

	cmd := &cobra.Command{
		Use:     "encrypt [file]",
		Aliases: []string{"enc", "-e"},
		Short:   "Encrypt a file or stdin",
		Long:    "Encrypt data for one or more recipients. Reads from file or stdin.",
		RunE: func(cmd *cobra.Command, args []string) error {
			input, err := readInput(args)
			if err != nil {
				return err
			}

			if symmetric {
				fmt.Print("Passphrase: ")
				passphrase := readPassphrase()
				fmt.Print("Repeat passphrase: ")
				passphrase2 := readPassphrase()
				if string(passphrase) != string(passphrase2) {
					return fmt.Errorf("passphrases do not match")
				}

				result, err := crypto.EncryptSymmetric(bytes.NewReader(input), passphrase, armorFlag)
				if err != nil {
					return err
				}
				return writeOutput(result)
			}

			if len(recipients) == 0 {
				return fmt.Errorf("at least one recipient (-r) is required, or use --symmetric")
			}

			var recipientEntities []*openpgp.Entity
			for _, r := range recipients {
				entity := kr.FindPublicKey(r)
				if entity == nil {
					return fmt.Errorf("public key not found for recipient: %s", r)
				}
				recipientEntities = append(recipientEntities, entity)
			}

			var signer *openpgp.Entity
			if signWith != "" {
				signer = kr.FindSecretKey(signWith)
				if signer == nil {
					return fmt.Errorf("secret key not found for signing: %s", signWith)
				}
			}

			result, err := crypto.Encrypt(bytes.NewReader(input), crypto.EncryptParams{
				Recipients: recipientEntities,
				Signer:     signer,
				Armor:      armorFlag,
			})
			if err != nil {
				return err
			}

			return writeOutput(result)
		},
	}

	cmd.Flags().StringArrayVarP(&recipients, "recipient", "r", nil, "encrypt for recipient (key ID or email)")
	cmd.Flags().StringVarP(&signWith, "sign", "u", "", "sign with this key")
	cmd.Flags().BoolVarP(&symmetric, "symmetric", "c", false, "encrypt with passphrase (symmetric)")

	return cmd
}

func readInput(args []string) ([]byte, error) {
	if len(args) > 0 {
		data, err := os.ReadFile(args[0])
		if err != nil {
			return nil, fmt.Errorf("read file: %w", err)
		}
		return data, nil
	}

	// Read from stdin
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		fmt.Fprintln(os.Stderr, "Reading from stdin (Ctrl+D to finish)...")
	}

	data, err := os.ReadFile("/dev/stdin")
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	return data, nil
}

func readPassphrase() []byte {
	// Simple passphrase reading - in production you'd use term.ReadPassword
	var passphrase string
	fmt.Scanln(&passphrase)
	return []byte(passphrase)
}
