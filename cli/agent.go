package cli

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/hamalizer/gpg_go/internal/agent"
	"github.com/spf13/cobra"
)

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Passphrase caching daemon",
		Long: `gpg-go agent caches passphrases in memory so you don't have to
re-enter them for every sign or decrypt operation.

  gpg-go agent start     Start the agent (foreground)
  gpg-go agent stop      Stop a running agent
  gpg-go agent status    Check if the agent is running
  gpg-go agent clear     Clear all cached passphrases

The agent listens on a Unix socket at ~/.gpg-go/agent.sock with a
configurable TTL (default 10 minutes). Use with systemd, launchd,
or & to run in the background.`,
	}

	cmd.AddCommand(
		newAgentStartCmd(),
		newAgentStopCmd(),
		newAgentStatusCmd(),
		newAgentClearCmd(),
	)
	return cmd
}

func newAgentStartCmd() *cobra.Command {
	var ttlStr string

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the passphrase cache agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			ttl := agent.DefaultTTL
			if ttlStr != "" {
				d, err := time.ParseDuration(ttlStr)
				if err != nil {
					return fmt.Errorf("invalid --ttl (e.g. 10m, 1h): %w", err)
				}
				ttl = d
			}

			// Check if already running
			client := agent.NewClient(appConfig.HomeDir)
			if err := client.Ping(); err == nil {
				return fmt.Errorf("agent is already running (socket: %s)", agent.SocketPath(appConfig.HomeDir))
			}

			srv := agent.NewServer(appConfig.HomeDir, ttl)

			// Handle signals for clean shutdown
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigCh
				fmt.Fprintln(os.Stderr, "\nShutting down agent...")
				srv.Shutdown()
			}()

			fmt.Fprintf(os.Stderr, "gpg-go agent started (ttl=%s, socket=%s)\n", ttl, agent.SocketPath(appConfig.HomeDir))
			return srv.Start()
		},
	}

	cmd.Flags().StringVar(&ttlStr, "ttl", "", "passphrase cache TTL (default 10m, e.g. 30m, 1h)")
	return cmd
}

func newAgentStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the running agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := agent.NewClient(appConfig.HomeDir)
			if err := client.Shutdown(); err != nil {
				// Try killing by PID as fallback
				pidData, pErr := os.ReadFile(agent.PIDPath(appConfig.HomeDir))
				if pErr != nil {
					return fmt.Errorf("agent not running (no socket or PID file)")
				}
				pid, pErr := strconv.Atoi(string(pidData))
				if pErr != nil {
					return fmt.Errorf("invalid PID file")
				}
				proc, pErr := os.FindProcess(pid)
				if pErr != nil {
					return fmt.Errorf("process %d not found", pid)
				}
				proc.Signal(syscall.SIGTERM)
			}
			fmt.Println("Agent stopped.")
			return nil
		},
	}
}

func newAgentStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check if the agent is running",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := agent.NewClient(appConfig.HomeDir)
			if err := client.Ping(); err != nil {
				fmt.Println("Agent is not running.")
				if jsonOutput {
					return printJSON(map[string]any{"running": false})
				}
				return nil
			}
			fmt.Printf("Agent is running (socket: %s)\n", agent.SocketPath(appConfig.HomeDir))
			if jsonOutput {
				return printJSON(map[string]any{
					"running": true,
					"socket":  agent.SocketPath(appConfig.HomeDir),
				})
			}
			return nil
		},
	}
}

func newAgentClearCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clear",
		Short: "Clear all cached passphrases",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := agent.NewClient(appConfig.HomeDir)
			if err := client.Clear(); err != nil {
				return fmt.Errorf("clear cache: %w", err)
			}
			fmt.Println("Cache cleared.")
			return nil
		},
	}
}
