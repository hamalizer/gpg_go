package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hamalizer/gpg_go/internal/crypto"
	"github.com/hamalizer/gpg_go/internal/keyring"
	"github.com/hamalizer/gpg_go/internal/trustdb"
	"github.com/spf13/cobra"
)

func newGenerateCmd() *cobra.Command {
	var (
		name    string
		email   string
		comment string
		algo    string
		quick   bool
		expire  string
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

			// Prompt for passphrase to protect the private key
			fmt.Fprint(os.Stderr, "Passphrase (empty for no passphrase): ")
			passphrase, err := readPassphrase()
			if err != nil {
				return fmt.Errorf("read passphrase: %w", err)
			}
			fmt.Fprintln(os.Stderr)

			if len(passphrase) > 0 {
				fmt.Fprint(os.Stderr, "Repeat passphrase: ")
				passphrase2, err := readPassphrase()
				if err != nil {
					return fmt.Errorf("read passphrase: %w", err)
				}
				fmt.Fprintln(os.Stderr)
				if !bytes.Equal(passphrase, passphrase2) {
					zeroBytes(passphrase)
					zeroBytes(passphrase2)
					return fmt.Errorf("passphrases do not match")
				}
				zeroBytes(passphrase2)
			}
			defer zeroBytes(passphrase)

			fmt.Printf("Generating %s key for %s <%s>...\n", algorithm, name, email)

			var lifetime time.Duration
			if expire != "" {
				d, pErr := time.ParseDuration(expire)
				if pErr != nil {
					return fmt.Errorf("invalid --expire duration (e.g. 8760h for 1 year): %w", pErr)
				}
				lifetime = d
			}

			entity, err := crypto.GenerateKey(crypto.KeyGenParams{
				Name:       name,
				Comment:    comment,
				Email:      email,
				Algorithm:  algorithm,
				Passphrase: passphrase,
				Lifetime:   lifetime,
			})
			if err != nil {
				return fmt.Errorf("key generation failed: %w", err)
			}

			if err := kr.AddEntity(entity); err != nil {
				return fmt.Errorf("save key: %w", err)
			}

			// Mark own key as ultimate trust
			if err := initTrustDB(); err == nil {
				fp := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
				_ = trustDB.SetTrust(fp, trustdb.TrustUltimate)
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
	cmd.Flags().StringVar(&expire, "expire", "", "key lifetime (e.g. 8760h for 1 year, 17520h for 2 years)")

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
