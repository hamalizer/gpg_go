// Package cli implements the command-line interface for gpg-go.
package cli

import (
	"fmt"
	"os"

	"github.com/hamalizer/gpg_go/internal/config"
	"github.com/hamalizer/gpg_go/internal/keyring"
	"github.com/spf13/cobra"
)

var (
	cfgHomeDir string
	armorFlag  bool
	outputFile string
	verbose    bool

	appConfig *config.Config
	kr        *keyring.Keyring
)

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "gpg-go",
		Short: "A modern OpenPGP implementation in Go",
		Long: `gpg-go is a complete rewrite of GnuPG in Go.

It provides full OpenPGP encryption, decryption, signing, verification,
and key management with a clean CLI, full GUI, and cross-platform support.

Supports RSA (2048/3072/4096) and Ed25519 keys, AES-256 encryption,
SHA-256 hashing, HKP keyserver protocol, and ASCII armor.`,
		Version: config.AppVersion,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			appConfig, err = config.New(cfgHomeDir)
			if err != nil {
				return fmt.Errorf("initialize config: %w", err)
			}
			appConfig.Armor = armorFlag
			appConfig.Verbose = verbose

			kr, err = keyring.New(appConfig)
			if err != nil {
				return fmt.Errorf("initialize keyring: %w", err)
			}
			return nil
		},
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVar(&cfgHomeDir, "homedir", "", "set home directory (default: ~/.gpg-go)")
	root.PersistentFlags().BoolVarP(&armorFlag, "armor", "a", false, "create ASCII armored output")
	root.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "write output to file")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	root.AddCommand(
		newGenerateCmd(),
		newListKeysCmd(),
		newListSecretKeysCmd(),
		newEncryptCmd(),
		newDecryptCmd(),
		newSignCmd(),
		newVerifyCmd(),
		newImportCmd(),
		newExportCmd(),
		newDeleteCmd(),
		newFingerprintCmd(),
		newSearchKeysCmd(),
		newRecvKeysCmd(),
		newSendKeysCmd(),
	)

	return root
}

func Execute() {
	if err := NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func writeOutput(data []byte) error {
	if outputFile != "" {
		return os.WriteFile(outputFile, data, 0644)
	}
	_, err := os.Stdout.Write(data)
	return err
}
