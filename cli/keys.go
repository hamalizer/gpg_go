package cli

import (
	"fmt"

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

			fmt.Printf("Public keyring: %d key(s)\n\n", len(keys))
			for _, entity := range keys {
				info := keyring.KeyInfo(entity)
				if search == "" || containsCI(info, search) {
					fmt.Println(info)
					fmt.Println()
				}
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

			fmt.Printf("Secret keyring: %d key(s)\n\n", len(keys))
			for _, entity := range keys {
				info := keyring.KeyInfo(entity)
				if search == "" || containsCI(info, search) {
					fmt.Println(info)
					fmt.Println()
				}
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

			for _, entity := range keys {
				if search != "" {
					found := kr.FindPublicKey(search)
					if found == nil || found != entity {
						continue
					}
				}

				fp := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
				formatted := formatFingerprint(fp)

				for _, id := range entity.Identities {
					fmt.Printf("%s\n", id.Name)
				}
				fmt.Printf("  Key ID: %s\n", entity.PrimaryKey.KeyIdString())
				fmt.Printf("  Fingerprint: %s\n\n", formatted)
			}
			return nil
		},
	}
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
		left := joinStr(parts[:5], " ")
		right := joinStr(parts[5:], " ")
		return left + "  " + right
	}
	return joinStr(parts, " ")
}

func joinStr(parts []string, sep string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += sep
		}
		result += p
	}
	return result
}

func containsCI(s, substr string) bool {
	return len(s) >= len(substr) &&
		fmt.Sprintf("%s", s) != "" &&
		(func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if equalFoldBytes(s[i:i+len(substr)], substr) {
					return true
				}
			}
			return false
		})()
}

func equalFoldBytes(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
