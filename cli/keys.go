package cli

import (
	"fmt"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/hamalizer/gpg_go/internal/keyring"
	"github.com/spf13/cobra"
)

func newListKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list-keys [search]",
		Aliases: []string{"list", "ls", "-k"},
		Short:   "List public keys in keyring",
		RunE: func(cmd *cobra.Command, args []string) error {
			keys := kr.PublicKeys()
			if len(keys) == 0 {
				fmt.Println("No public keys found.")
				return nil
			}

			search := ""
			if len(args) > 0 {
				search = args[0]
			}

			// Count matching keys for accurate header
			var matching []string
			for _, entity := range keys {
				info := keyring.KeyInfo(entity)
				if search == "" || strings.Contains(strings.ToLower(info), strings.ToLower(search)) {
					matching = append(matching, info)
				}
			}

			fmt.Printf("Public keyring: %d key(s)\n\n", len(matching))
			for _, info := range matching {
				fmt.Println(info)
				fmt.Println()
			}
			return nil
		},
	}
}

func newListSecretKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list-secret-keys [search]",
		Aliases: []string{"list-secret", "-K"},
		Short:   "List secret keys in keyring",
		RunE: func(cmd *cobra.Command, args []string) error {
			keys := kr.SecretKeys()
			if len(keys) == 0 {
				fmt.Println("No secret keys found.")
				return nil
			}

			search := ""
			if len(args) > 0 {
				search = args[0]
			}

			var matching []string
			for _, entity := range keys {
				info := keyring.KeyInfo(entity)
				if search == "" || strings.Contains(strings.ToLower(info), strings.ToLower(search)) {
					matching = append(matching, info)
				}
			}

			fmt.Printf("Secret keyring: %d key(s)\n\n", len(matching))
			for _, info := range matching {
				fmt.Println(info)
				fmt.Println()
			}
			return nil
		},
	}
}

func newFingerprintCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "fingerprint [key-id]",
		Short: "Show key fingerprints",
		RunE: func(cmd *cobra.Command, args []string) error {
			keys := kr.PublicKeys()
			if len(keys) == 0 {
				fmt.Println("No keys found.")
				return nil
			}

			search := ""
			if len(args) > 0 {
				search = args[0]
			}

			if search != "" {
				// Find the specific key once, not per iteration (O(n) not O(n^2))
				found := kr.FindPublicKey(search)
				if found == nil {
					return fmt.Errorf("key not found: %s", search)
				}
				printFingerprint(found)
				return nil
			}

			for _, entity := range keys {
				printFingerprint(entity)
			}
			return nil
		},
	}
}

func printFingerprint(entity *openpgp.Entity) {
	fp := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
	formatted := formatFingerprint(fp)

	// Use sorted UIDs for deterministic output
	for _, uid := range keyring.SortedUIDs(entity) {
		fmt.Printf("%s\n", uid)
	}
	fmt.Printf("  Key ID: %s\n", entity.PrimaryKey.KeyIdString())
	fmt.Printf("  Fingerprint: %s\n\n", formatted)
}

func newDeleteCmd() *cobra.Command {
	var deleteSecret bool

	cmd := &cobra.Command{
		Use:   "delete <key-id>",
		Short: "Delete a key from the keyring",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			keyID := args[0]

			if deleteSecret {
				if err := kr.DeleteSecretKey(keyID); err != nil {
					return fmt.Errorf("delete secret key: %w", err)
				}
				fmt.Printf("Secret key %s deleted.\n", keyID)
			}

			if err := kr.DeletePublicKey(keyID); err != nil {
				if !deleteSecret {
					return fmt.Errorf("delete public key: %w", err)
				}
				// Secret-only delete: public key not found is not fatal
			} else {
				fmt.Printf("Public key %s deleted.\n", keyID)
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&deleteSecret, "secret", false, "also delete the secret key")
	return cmd
}

func formatFingerprint(fp string) string {
	var parts []string
	for i := 0; i < len(fp); i += 4 {
		end := i + 4
		if end > len(fp) {
			end = len(fp)
		}
		parts = append(parts, fp[i:end])
	}

	if len(parts) > 5 {
		left := strings.Join(parts[:5], " ")
		right := strings.Join(parts[5:], " ")
		return left + "  " + right
	}
	return strings.Join(parts, " ")
}
