package agent

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Client connects to a running gpg-go agent.
type Client struct {
	sockPath string
}

// NewClient creates a new agent client.
func NewClient(homeDir string) *Client {
	return &Client{sockPath: SocketPath(homeDir)}
}

func (c *Client) send(req Request) (*Response, error) {
	conn, err := net.DialTimeout("unix", c.sockPath, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to agent: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return &resp, nil
}

// Ping checks if the agent is running.
func (c *Client) Ping() error {
	resp, err := c.send(Request{Action: "ping"})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("agent: %s", resp.Message)
	}
	return nil
}

// Get retrieves a cached passphrase for the given fingerprint.
// Returns nil if not cached or expired.
func (c *Client) Get(fingerprint string) ([]byte, error) {
	resp, err := c.send(Request{Action: "get", Fingerprint: fingerprint})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, nil // not cached, not an error
	}
	return resp.Passphrase, nil
}

// Put caches a passphrase for the given fingerprint.
func (c *Client) Put(fingerprint string, passphrase []byte) error {
	resp, err := c.send(Request{Action: "put", Fingerprint: fingerprint, Passphrase: passphrase})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("agent: %s", resp.Message)
	}
	return nil
}

// Clear removes all cached passphrases.
func (c *Client) Clear() error {
	resp, err := c.send(Request{Action: "clear"})
	if err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("agent: %s", resp.Message)
	}
	return nil
}

// Shutdown requests the agent to stop.
func (c *Client) Shutdown() error {
	_, err := c.send(Request{Action: "shutdown"})
	// Connection may close before we get a response, that's OK
	if err != nil {
		return nil // agent is shutting down
	}
	return nil
}
