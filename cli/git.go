package cli

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/hamalizer/gpg_go/internal/keyring"
	"github.com/spf13/cobra"
)

func newGitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "git",
		Short: "Git commit-signing integration",
		Long: `Configure git to use gpg-go for commit and tag signing.

  gpg-go git configure    Set gpg.program and select a signing key
  gpg-go git status       Show current git signing configuration`,
	}

	cmd.AddCommand(newGitConfigureCmd(), newGitStatusCmd())
	return cmd
}

func newGitConfigureCmd() *cobra.Command {
	var keyID string

	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Configure git to use gpg-go for signing",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Find the gpg-go binary path
			binPath, err := exec.LookPath("gpg-go")
			if err != nil {
				// Fall back to the current executable name
				binPath = "gpg-go"
			}

			// Resolve signing key
			var signingKey string
			if keyID != "" {
				entity := kr.FindSecretKey(keyID)
				if entity == nil {
					return fmt.Errorf("secret key not found: %s", keyID)
				}
				signingKey = entity.PrimaryKey.KeyIdString()
			} else {
				// Use the most recently created secret key (same logic as sign)
				secKeys := kr.SecretKeys()
				if len(secKeys) == 0 {
					return fmt.Errorf("no secret keys available; generate one first with: gpg-go generate")
				}
				best := secKeys[0]
				for _, k := range secKeys[1:] {
					if k.PrimaryKey.CreationTime.After(best.PrimaryKey.CreationTime) {
						best = k
					}
				}
				signingKey = best.PrimaryKey.KeyIdString()
				fmt.Fprintf(cmd.ErrOrStderr(), "Using key: %s (%s)\n", signingKey, keyring.PrimaryUID(best))
			}

			// Set git config (global)
			cmds := []struct {
				args []string
				desc string
			}{
				{[]string{"config", "--global", "gpg.program", binPath}, "gpg.program"},
				{[]string{"config", "--global", "user.signingkey", signingKey}, "user.signingkey"},
				{[]string{"config", "--global", "commit.gpgsign", "true"}, "commit.gpgsign"},
				{[]string{"config", "--global", "tag.gpgsign", "true"}, "tag.gpgsign"},
			}

			for _, c := range cmds {
				gitCmd := exec.Command("git", c.args...)
				if out, err := gitCmd.CombinedOutput(); err != nil {
					return fmt.Errorf("git config %s: %s (%w)", c.desc, strings.TrimSpace(string(out)), err)
				}
				fmt.Printf("  %s = %s\n", c.desc, c.args[len(c.args)-1])
			}

			fmt.Println("\nGit is now configured to sign commits and tags with gpg-go.")
			return nil
		},
	}

	cmd.Flags().StringVarP(&keyID, "key", "k", "", "signing key ID (default: most recent secret key)")
	return cmd
}

func newGitStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show current git signing configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			settings := []string{
				"gpg.program",
				"user.signingkey",
				"commit.gpgsign",
				"tag.gpgsign",
			}

			fmt.Println("Git signing configuration:")
			for _, key := range settings {
				gitCmd := exec.Command("git", "config", "--global", "--get", key)
				out, err := gitCmd.Output()
				val := strings.TrimSpace(string(out))
				if err != nil || val == "" {
					val = "(not set)"
				}
				fmt.Printf("  %-20s %s\n", key, val)
			}

			if jsonOutput {
				m := make(map[string]string)
				for _, key := range settings {
					gitCmd := exec.Command("git", "config", "--global", "--get", key)
					out, _ := gitCmd.Output()
					m[key] = strings.TrimSpace(string(out))
				}
				return printJSON(m)
			}

			return nil
		},
	}
}
