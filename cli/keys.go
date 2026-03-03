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

			search := ""
			if len(args) > 0 {
				search = args[0]
			}

			var matched []*openpgp.Entity
			for _, entity := range keys {
				if search == "" || strings.Contains(strings.ToLower(keyring.KeyInfo(entity)), strings.ToLower(search)) {
					matched = append(matched, entity)
				}
			}

			if jsonOutput {
				jkeys := make([]KeyJSON, 0, len(matched))
				for _, e := range matched {
					jkeys = append(jkeys, entityToJSON(e))
				}
				return printJSON(jkeys)
			}

			if len(matched) == 0 {
				fmt.Println("No public keys found.")
				return nil
			}

			fmt.Printf("Public keyring: %d key(s)\n\n", len(matched))
			for _, entity := range matched {
				fmt.Println(keyring.KeyInfo(entity))
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

			search := ""
			if len(args) > 0 {
				search = args[0]
			}

			var matched []*openpgp.Entity
			for _, entity := range keys {
				if search == "" || strings.Contains(strings.ToLower(keyring.KeyInfo(entity)), strings.ToLower(search)) {
					matched = append(matched, entity)
				}
			}

			if jsonOutput {
				jkeys := make([]KeyJSON, 0, len(matched))
				for _, e := range matched {
					jkeys = append(jkeys, entityToJSON(e))
				}
				return printJSON(jkeys)
			}

			if len(matched) == 0 {
				fmt.Println("No secret keys found.")
				return nil
			}

			fmt.Printf("Secret keyring: %d key(s)\n\n", len(matched))
			for _, entity := range matched {
				fmt.Println(keyring.KeyInfo(entity))
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

			search := ""
			if len(args) > 0 {
				search = args[0]
			}

			var targets []*openpgp.Entity
			if search != "" {
				found := kr.FindPublicKey(search)
				if found == nil {
					return fmt.Errorf("key not found: %s", search)
				}
				targets = []*openpgp.Entity{found}
			} else {
				targets = keys
			}

			if jsonOutput {
				type fpJSON struct {
					KeyID       string   `json:"key_id"`
					Fingerprint string   `json:"fingerprint"`
					UIDs        []string `json:"uids"`
				}
				out := make([]fpJSON, 0, len(targets))
				for _, e := range targets {
					out = append(out, fpJSON{
						KeyID:       e.PrimaryKey.KeyIdString(),
						Fingerprint: fmt.Sprintf("%X", e.PrimaryKey.Fingerprint),
						UIDs:        keyring.SortedUIDs(e),
					})
				}
				return printJSON(out)
			}

			if len(targets) == 0 {
				fmt.Println("No keys found.")
				return nil
			}

			for _, entity := range targets {
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
