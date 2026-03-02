package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/hamalizer/gpg_go/internal/crypto"
	"github.com/hamalizer/gpg_go/internal/keyring"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			input, err := readInput(args)
			if err != nil {
				return err
			}

			if symmetric {
				fmt.Fprint(os.Stderr, "Passphrase: ")
				passphrase, err := readPassphrase()
				if err != nil {
					return fmt.Errorf("read passphrase: %w", err)
				}
				fmt.Fprintln(os.Stderr)
				defer zeroBytes(passphrase)

				fmt.Fprint(os.Stderr, "Repeat passphrase: ")
				passphrase2, err := readPassphrase()
				if err != nil {
					return fmt.Errorf("read passphrase: %w", err)
				}
				fmt.Fprintln(os.Stderr)
				defer zeroBytes(passphrase2)

				if !bytes.Equal(passphrase, passphrase2) {
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
				// If the signing key is encrypted, prompt for passphrase
				if keyring.IsEntityKeyEncrypted(signer) {
					fmt.Fprint(os.Stderr, "Passphrase for signing key: ")
					sigPass, pErr := readPassphrase()
					if pErr != nil {
						return fmt.Errorf("read passphrase: %w", pErr)
					}
					fmt.Fprintln(os.Stderr)
					defer zeroBytes(sigPass)
					if err := keyring.DecryptEntityKeys(signer, sigPass); err != nil {
						return fmt.Errorf("unlock signing key: %w", err)
					}
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

	// Read from stdin (portable: works on Windows, Linux, macOS)
	stat, err := os.Stdin.Stat()
	if err == nil && (stat.Mode()&os.ModeCharDevice) != 0 {
		fmt.Fprintln(os.Stderr, "Reading from stdin (Ctrl+D to finish)...")
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	return data, nil
}

// readPassphrase reads a passphrase from the terminal with echo disabled.
func readPassphrase() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		return term.ReadPassword(fd)
	}
	// Not a terminal (piped input) - read a line
	var buf []byte
	b := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(b)
		if n > 0 && b[0] != '\n' && b[0] != '\r' {
			buf = append(buf, b[0])
		}
		if err != nil || b[0] == '\n' {
			break
		}
	}
	return buf, nil
}

// zeroBytes overwrites a byte slice with zeros to remove sensitive data from memory.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
