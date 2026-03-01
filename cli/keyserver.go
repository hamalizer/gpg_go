package cli

import (
	"fmt"

	"github.com/hamalizer/gpg_go/internal/keyring"
	"github.com/hamalizer/gpg_go/internal/keyserver"
	"github.com/spf13/cobra"
)

var keyserverURL string

func newSearchKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search-keys <query>",
		Short: "Search for keys on a keyserver",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			server := getKeyserver()
			client := keyserver.NewClient(server)

			fmt.Printf("Searching %s for \"%s\"...\n", server, args[0])

			results, err := client.SearchKeys(args[0])
			if err != nil {
				return fmt.Errorf("search failed: %w", err)
			}

			if len(results) == 0 {
				fmt.Println("No keys found.")
				return nil
			}

			fmt.Printf("\nFound %d key(s):\n\n", len(results))
			for _, r := range results {
				fmt.Printf("  %s  %s\n", r.KeyID, r.Algorithm)
				for _, uid := range r.UIDs {
					fmt.Printf("    uid: %s\n", uid)
				}
				if r.Created != "" {
					fmt.Printf("    created: %s\n", r.Created)
				}
				fmt.Println()
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&keyserverURL, "keyserver", "", "keyserver URL")
	return cmd
}

func newRecvKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recv-keys <key-id>...",
		Short: "Import keys from a keyserver",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			server := getKeyserver()
			client := keyserver.NewClient(server)

			for _, keyID := range args {
				fmt.Printf("Fetching key %s from %s...\n", keyID, server)

				entities, err := client.FetchKey(keyID)
				if err != nil {
					fmt.Printf("  Error: %v\n", err)
					continue
				}

				for _, entity := range entities {
					if err := kr.AddEntity(entity); err != nil {
						fmt.Printf("  Error saving key: %v\n", err)
						continue
					}
					fmt.Printf("  Imported: %s\n", keyring.KeyInfo(entity))
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&keyserverURL, "keyserver", "", "keyserver URL")
	return cmd
}

func newSendKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "send-keys <key-id>...",
		Short: "Send keys to a keyserver",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			server := getKeyserver()
			client := keyserver.NewClient(server)

			for _, keyID := range args {
				data, err := kr.ExportPublicKey(keyID, true)
				if err != nil {
					fmt.Printf("Error exporting key %s: %v\n", keyID, err)
					continue
				}

				fmt.Printf("Sending key %s to %s...\n", keyID, server)
				if err := client.UploadKey(string(data)); err != nil {
					fmt.Printf("  Error: %v\n", err)
					continue
				}
				fmt.Printf("  Key %s sent successfully.\n", keyID)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&keyserverURL, "keyserver", "", "keyserver URL")
	return cmd
}

func getKeyserver() string {
	if keyserverURL != "" {
		return keyserverURL
	}
	if appConfig != nil && appConfig.Keyserver != "" {
		return appConfig.Keyserver
	}
	return "hkps://keys.openpgp.org"
}
