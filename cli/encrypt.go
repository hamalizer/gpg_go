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

				if len(passphrase) == 0 {
					fmt.Fprintln(os.Stderr, "WARNING: empty passphrase provides no security")
				} else if len(passphrase) < 8 {
					fmt.Fprintln(os.Stderr, "WARNING: passphrase is very short (< 8 characters)")
				}

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

			// R2-L-03: Check trust levels and warn for untrusted recipients.
			if err := initTrustDB(); err == nil && trustDB != nil {
				for _, entity := range recipientEntities {
					fp := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
					level := trustDB.GetTrust(fp)
					uid := keyring.PrimaryUID(entity)
					switch {
					case level == 1: // TrustNever
						fmt.Fprintf(os.Stderr, "WARNING: recipient %s is explicitly UNTRUSTED\n", uid)
					case level == 0: // TrustUnknown
						fmt.Fprintf(os.Stderr, "WARNING: recipient %s has unknown trust level\n", uid)
					}
				}
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
//
// NOTE: Go's garbage collector may copy the returned byte slice during
// compaction. zeroBytes() only clears the current copy, not any prior GC
// copies. This is a fundamental limitation of Go — true memory pinning
// requires mlock(2) via cgo/unsafe, which is out of scope for this tool.
// The window of exposure is small (GC'd memory is quickly reused), and
// this matches the tradeoff made by most Go crypto tools including age.
func readPassphrase() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		return term.ReadPassword(fd)
	}
	// Not a terminal (piped input). Warn that the passphrase may be visible
	// in process listings if piped via echo or heredoc.
	fmt.Fprintln(os.Stderr, "WARNING: reading passphrase from non-terminal input")
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
