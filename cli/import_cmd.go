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
		Use:     "import <file>",
		Aliases: []string{"recv"},
		Short:   "Import keys from a file",
		Long:    "Import public or private keys from an armored or binary key file.",
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
				data, err := kr.ExportSecretKey(identifier, true)
				if err != nil {
					return err
				}
				_, err = os.Stdout.Write(data)
				return err
			}

			data, err := kr.ExportPublicKey(identifier, true)
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(data)
			return err
		},
	}

	cmd.Flags().BoolVar(&exportSecret, "secret", false, "export secret key")
	return cmd
}
