package cli

import (
	"fmt"

	"github.com/hamalizer/gpg_go/internal/keyring"
	"github.com/hamalizer/gpg_go/internal/trustdb"
	"github.com/spf13/cobra"
)

var trustDB *trustdb.DB

func newEditTrustCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit-trust <key-id> <level>",
		Short: "Set owner trust for a key",
		Long: `Set the owner trust level for a key.

Trust levels: unknown, never, marginal, full, ultimate`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := initTrustDB(); err != nil {
				return err
			}

			entity := kr.FindPublicKey(args[0])
			if entity == nil {
				return fmt.Errorf("key not found: %s", args[0])
			}

			level, err := trustdb.ParseTrustLevel(args[1])
			if err != nil {
				return err
			}

			fp := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
			if err := trustDB.SetTrust(fp, level); err != nil {
				return fmt.Errorf("set trust: %w", err)
			}

			fmt.Printf("Trust for %s set to %s\n", keyring.PrimaryUID(entity), level)
			return nil
		},
	}
	return cmd
}

func newListTrustCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-trust",
		Short: "Show trust levels for all keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := initTrustDB(); err != nil {
				return err
			}

			keys := kr.PublicKeys()
			if len(keys) == 0 {
				fmt.Println("No keys in keyring.")
				return nil
			}

			for _, entity := range keys {
				fp := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
				level := trustDB.GetTrust(fp)
				uid := keyring.PrimaryUID(entity)
				fmt.Printf("[%-9s] %s  %s\n", level, entity.PrimaryKey.KeyIdString(), uid)
			}
			return nil
		},
	}
	return cmd
}

func initTrustDB() error {
	if trustDB != nil {
		return nil
	}
	if appConfig == nil {
		return fmt.Errorf("config not initialized")
	}
	var err error
	trustDB, err = trustdb.Open(appConfig.TrustDB)
	if err != nil {
		return fmt.Errorf("open trustdb: %w", err)
	}
	return nil
}
