package cli

import (
	"bytes"
	"fmt"
	"os"

	"github.com/hamalizer/gpg_go/internal/crypto"
	"github.com/spf13/cobra"
)

// errBadSignature is returned when signature verification fails.
// The caller (Execute) can check for this to set exit code 1.
var errBadSignature = fmt.Errorf("signature verification failed")

func newVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <signature> [signed-file]",
		Short: "Verify a signature",
		Long: `Verify a digital signature.

For detached signatures: gpg-go verify signature.sig file.txt
For inline signatures:   gpg-go verify signed-message.gpg`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// M-05: Use PublicKeys() for verification — secret key material
			// is not needed and should not be loaded into memory.
			pubKeys := kr.PublicKeys()

			if len(args) == 2 {
				// Detached signature verification
				sigData, err := os.ReadFile(args[0])
				if err != nil {
					return fmt.Errorf("read signature: %w", err)
				}

				signedData, err := os.ReadFile(args[1])
				if err != nil {
					return fmt.Errorf("read signed file: %w", err)
				}

				result, err := crypto.VerifyDetached(
					bytes.NewReader(signedData),
					bytes.NewReader(sigData),
					pubKeys,
				)
				if err != nil {
					return err
				}

				if jsonOutput {
					vj := VerifyJSON{Valid: result.Valid, Message: result.Message}
					if result.SignedBy != nil {
						vj.KeyID = result.SignedBy.PublicKey.KeyIdString()
					}
					return printJSON(vj)
				}

				fmt.Fprintln(os.Stderr, result.Message)
				if !result.Valid {
					return errBadSignature
				}
				return nil
			}

			// Inline signature verification
			sigData, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read file: %w", err)
			}

			result, plaintext, err := crypto.VerifyInline(
				bytes.NewReader(sigData),
				pubKeys,
			)
			if err != nil {
				return err
			}

			if jsonOutput {
				vj := VerifyJSON{Valid: result.Valid, Message: result.Message}
				if result.SignedBy != nil {
					vj.KeyID = result.SignedBy.PublicKey.KeyIdString()
				}
				return printJSON(vj)
			}

			fmt.Fprintln(os.Stderr, result.Message)
			if !result.Valid {
				return errBadSignature
			}

			if len(plaintext) > 0 {
				os.Stdout.Write(plaintext)
			}
			return nil
		},
	}

	return cmd
}
