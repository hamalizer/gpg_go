package cli

import (
	"bytes"
	"fmt"
	"os"

	"github.com/hamalizer/gpg_go/internal/crypto"
	"github.com/spf13/cobra"
)

func newVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <signature> [signed-file]",
		Short: "Verify a signature",
		Long: `Verify a digital signature.

For detached signatures: gpg-go verify signature.sig file.txt
For inline signatures:   gpg-go verify signed-message.gpg`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("signature file required")
			}

			allKeys := kr.AllKeys()

			if len(args) >= 2 {
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
					allKeys,
				)
				if err != nil {
					return err
				}

				fmt.Println(result.Message)
				if !result.Valid {
					os.Exit(1)
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
				allKeys,
			)
			if err != nil {
				return err
			}

			fmt.Fprintln(os.Stderr, result.Message)
			if !result.Valid {
				os.Exit(1)
			}

			if len(plaintext) > 0 {
				os.Stdout.Write(plaintext)
			}
			return nil
		},
	}

	return cmd
}
