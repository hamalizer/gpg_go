package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/hamalizer/gpg_go/internal/keyring"
	"github.com/spf13/cobra"
)

type auditFinding struct {
	Severity string `json:"severity"` // "critical", "warning", "info"
	KeyID    string `json:"key_id"`
	UID      string `json:"uid,omitempty"`
	Message  string `json:"message"`
}

type auditReport struct {
	TotalKeys    int            `json:"total_keys"`
	SecretKeys   int            `json:"secret_keys"`
	Findings     []auditFinding `json:"findings"`
	CriticalCount int           `json:"critical_count"`
	WarningCount  int           `json:"warning_count"`
	InfoCount     int           `json:"info_count"`
}

func newAuditCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "audit",
		Short: "Audit keyring for security issues",
		Long: `Check all keys for weak algorithms, short key lengths, expired or
expiring keys, missing trust, and insecure file permissions.

Like ssh-audit, but for your OpenPGP keyring.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := initTrustDB(); err != nil {
				return err
			}

			pubKeys := kr.PublicKeys()
			secKeys := kr.SecretKeys()

			report := auditReport{
				TotalKeys:  len(pubKeys),
				SecretKeys: len(secKeys),
			}

			// Build fingerprint set for secret keys
			secFPs := make(map[string]bool)
			for _, e := range secKeys {
				secFPs[fmt.Sprintf("%X", e.PrimaryKey.Fingerprint)] = true
			}

			// Audit each key
			for _, entity := range pubKeys {
				auditKey(entity, secFPs, &report)
			}

			// Audit file permissions
			auditPermissions(&report)

			// Count severities
			for _, f := range report.Findings {
				switch f.Severity {
				case "critical":
					report.CriticalCount++
				case "warning":
					report.WarningCount++
				case "info":
					report.InfoCount++
				}
			}

			if jsonOutput {
				return printJSON(report)
			}

			// Human-readable output
			fmt.Printf("Keyring audit: %d public keys, %d secret keys\n\n", report.TotalKeys, report.SecretKeys)

			if len(report.Findings) == 0 {
				fmt.Println("No issues found. Keyring looks healthy.")
				return nil
			}

			for _, f := range report.Findings {
				prefix := "  "
				switch f.Severity {
				case "critical":
					prefix = "  [CRITICAL]"
				case "warning":
					prefix = "  [WARNING] "
				case "info":
					prefix = "  [INFO]    "
				}
				if f.UID != "" {
					fmt.Printf("%s %s (%s): %s\n", prefix, f.KeyID, f.UID, f.Message)
				} else {
					fmt.Printf("%s %s: %s\n", prefix, f.KeyID, f.Message)
				}
			}

			fmt.Printf("\nSummary: %d critical, %d warnings, %d info\n",
				report.CriticalCount, report.WarningCount, report.InfoCount)
			return nil
		},
	}
}

func auditKey(entity *openpgp.Entity, secFPs map[string]bool, report *auditReport) {
	pk := entity.PrimaryKey
	keyID := pk.KeyIdString()
	uid := keyring.PrimaryUID(entity)
	fp := fmt.Sprintf("%X", pk.Fingerprint)

	// Check algorithm strength
	bitLen, _ := pk.BitLength()
	switch pk.PubKeyAlgo {
	case 1, 2, 3: // RSA
		if bitLen > 0 && bitLen < 2048 {
			report.Findings = append(report.Findings, auditFinding{
				Severity: "critical",
				KeyID:    keyID,
				UID:      uid,
				Message:  fmt.Sprintf("RSA key is only %d bits (minimum 2048 recommended)", bitLen),
			})
		} else if bitLen > 0 && bitLen < 3072 {
			report.Findings = append(report.Findings, auditFinding{
				Severity: "warning",
				KeyID:    keyID,
				UID:      uid,
				Message:  fmt.Sprintf("RSA key is %d bits (3072+ recommended for long-term security)", bitLen),
			})
		}
	case 17: // DSA
		report.Findings = append(report.Findings, auditFinding{
			Severity: "warning",
			KeyID:    keyID,
			UID:      uid,
			Message:  "DSA keys are deprecated; consider migrating to Ed25519 or RSA-4096",
		})
	}

	// Check expiry
	expiry := keyring.KeyExpiry(entity)
	if expiry.IsZero() {
		// No expiry set
		if secFPs[fp] {
			report.Findings = append(report.Findings, auditFinding{
				Severity: "warning",
				KeyID:    keyID,
				UID:      uid,
				Message:  "Secret key has no expiration date; consider setting one for key hygiene",
			})
		}
	} else if keyring.IsKeyExpired(entity) {
		report.Findings = append(report.Findings, auditFinding{
			Severity: "critical",
			KeyID:    keyID,
			UID:      uid,
			Message:  fmt.Sprintf("Key expired on %s", expiry.Format("2006-01-02")),
		})
	} else if time.Until(expiry) < 30*24*time.Hour {
		report.Findings = append(report.Findings, auditFinding{
			Severity: "warning",
			KeyID:    keyID,
			UID:      uid,
			Message:  fmt.Sprintf("Key expires in %d days (%s)", int(time.Until(expiry).Hours()/24), expiry.Format("2006-01-02")),
		})
	}

	// Check trust level
	trust := trustDB.GetTrust(fp)
	if trust == 0 && secFPs[fp] {
		report.Findings = append(report.Findings, auditFinding{
			Severity: "info",
			KeyID:    keyID,
			UID:      uid,
			Message:  "Own key has no trust set (should be 'ultimate')",
		})
	} else if trust == 0 {
		report.Findings = append(report.Findings, auditFinding{
			Severity: "info",
			KeyID:    keyID,
			UID:      uid,
			Message:  "No trust level assigned",
		})
	}

	// Check if secret key is unprotected
	if entity.PrivateKey != nil && !keyring.IsEntityKeyEncrypted(entity) {
		report.Findings = append(report.Findings, auditFinding{
			Severity: "warning",
			KeyID:    keyID,
			UID:      uid,
			Message:  "Secret key is not passphrase-protected",
		})
	}
}

func auditPermissions(report *auditReport) {
	if appConfig == nil {
		return
	}

	dirs := map[string]string{
		"home":   appConfig.HomeDir,
		"pubring": appConfig.PubRingDir,
		"secring": appConfig.SecRingDir,
	}

	for name, path := range dirs {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		mode := info.Mode().Perm()
		if mode&0077 != 0 {
			report.Findings = append(report.Findings, auditFinding{
				Severity: "warning",
				KeyID:    name,
				Message:  fmt.Sprintf("Directory %s has permissions %o (should be 0700)", path, mode),
			})
		}
	}

	// Check trustdb permissions
	if info, err := os.Stat(appConfig.TrustDB); err == nil {
		mode := info.Mode().Perm()
		if mode&0077 != 0 {
			report.Findings = append(report.Findings, auditFinding{
				Severity: "warning",
				KeyID:    "trustdb",
				Message:  fmt.Sprintf("Trust database %s has permissions %o (should be 0600)", appConfig.TrustDB, mode),
			})
		}
	}
}
