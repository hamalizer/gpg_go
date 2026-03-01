package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/hamalizer/gpg_go/internal/crypto"
	"github.com/hamalizer/gpg_go/internal/keyring"
	"github.com/spf13/cobra"
)

func newGenerateCmd() *cobra.Command {
	var (
		name    string
		email   string
		comment string
		algo    string
		quick   bool
	)

	cmd := &cobra.Command{
		Use:     "generate",
		Aliases: []string{"gen", "gen-key"},
		Short:   "Generate a new key pair",
		Long:    "Generate a new OpenPGP key pair with the specified algorithm and identity.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !quick {
				reader := bufio.NewReader(os.Stdin)

				if name == "" {
					fmt.Fprint(os.Stderr, "Real name: ")
					var err error
					name, err = reader.ReadString('\n')
					if err != nil {
						return fmt.Errorf("read name: %w", err)
					}
					name = strings.TrimSpace(name)
				}
				if email == "" {
					fmt.Fprint(os.Stderr, "Email address: ")
					var err error
					email, err = reader.ReadString('\n')
					if err != nil {
						return fmt.Errorf("read email: %w", err)
					}
					email = strings.TrimSpace(email)
				}
				if comment == "" {
					fmt.Fprint(os.Stderr, "Comment (optional): ")
					comment, _ = reader.ReadString('\n')
					comment = strings.TrimSpace(comment)
				}
				if algo == "" {
					fmt.Fprintln(os.Stderr, "\nAlgorithm options:")
					fmt.Fprintln(os.Stderr, "  1) Ed25519 (recommended, fast, modern)")
					fmt.Fprintln(os.Stderr, "  2) RSA-4096 (traditional, widely compatible)")
					fmt.Fprintln(os.Stderr, "  3) RSA-3072")
					fmt.Fprintln(os.Stderr, "  4) RSA-2048")
					fmt.Fprint(os.Stderr, "Your selection (default: 1): ")
					choice, _ := reader.ReadString('\n')
					choice = strings.TrimSpace(choice)
					switch choice {
					case "", "1":
						algo = "ed25519"
					case "2":
						algo = "rsa4096"
					case "3":
						algo = "rsa3072"
					case "4":
						algo = "rsa2048"
					default:
						algo = "ed25519"
					}
				}
			}

			// Default algo when --quick and no --algo specified
			if algo == "" {
				algo = "ed25519"
			}

			if name == "" || email == "" {
				return fmt.Errorf("name and email are required")
			}

			algorithm := parseAlgorithm(algo)

			fmt.Printf("Generating %s key for %s <%s>...\n", algorithm, name, email)

			entity, err := crypto.GenerateKey(crypto.KeyGenParams{
				Name:      name,
				Comment:   comment,
				Email:     email,
				Algorithm: algorithm,
			})
			if err != nil {
				return fmt.Errorf("key generation failed: %w", err)
			}

			if err := kr.AddEntity(entity); err != nil {
				return fmt.Errorf("save key: %w", err)
			}

			fmt.Println("\nKey generated successfully!")
			fmt.Println(keyring.KeyInfo(entity))
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "real name for the key")
	cmd.Flags().StringVar(&email, "email", "", "email address for the key")
	cmd.Flags().StringVar(&comment, "comment", "", "comment for the key")
	// No default -- empty means "prompt in interactive mode" or "default to ed25519 in quick mode"
	cmd.Flags().StringVar(&algo, "algo", "", "algorithm: ed25519, rsa4096, rsa3072, rsa2048")
	cmd.Flags().BoolVar(&quick, "quick", false, "skip interactive prompts (requires --name and --email)")

	return cmd
}

func parseAlgorithm(algo string) crypto.KeyAlgorithm {
	switch strings.ToLower(algo) {
	case "rsa2048", "rsa-2048":
		return crypto.AlgoRSA2048
	case "rsa3072", "rsa-3072":
		return crypto.AlgoRSA3072
	case "rsa4096", "rsa-4096":
		return crypto.AlgoRSA4096
	case "ed25519", "eddsa":
		return crypto.AlgoEd25519
	default:
		return crypto.AlgoEd25519
	}
}
