// Package keyserver implements the HKP (HTTP Keyserver Protocol) client.
package keyserver

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewClient(serverURL string) *Client {
	if !strings.HasPrefix(serverURL, "http") {
		serverURL = "https://" + serverURL
	}
	// Normalize: strip trailing slash
	serverURL = strings.TrimRight(serverURL, "/")

	return &Client{
		BaseURL: serverURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SearchKeys searches for keys on the keyserver.
func (c *Client) SearchKeys(query string) ([]KeyResult, error) {
	u := fmt.Sprintf("%s/pks/lookup?op=index&options=mr&search=%s",
		c.BaseURL, url.QueryEscape(query))

	resp, err := c.HTTPClient.Get(u)
	if err != nil {
		return nil, fmt.Errorf("keyserver request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keyserver returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return parseMachineReadableIndex(string(body)), nil
}

// FetchKey retrieves a key from the keyserver by ID.
func (c *Client) FetchKey(keyID string) (openpgp.EntityList, error) {
	if !strings.HasPrefix(keyID, "0x") {
		keyID = "0x" + keyID
	}

	u := fmt.Sprintf("%s/pks/lookup?op=get&options=mr&search=%s",
		c.BaseURL, url.QueryEscape(keyID))

	resp, err := c.HTTPClient.Get(u)
	if err != nil {
		return nil, fmt.Errorf("keyserver request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("key %s not found on keyserver", keyID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keyserver returned status %d", resp.StatusCode)
	}

	entities, err := openpgp.ReadArmoredKeyRing(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read key from keyserver: %w", err)
	}

	return entities, nil
}

// UploadKey sends a public key to the keyserver.
func (c *Client) UploadKey(armoredKey string) error {
	u := fmt.Sprintf("%s/pks/add", c.BaseURL)

	form := url.Values{}
	form.Set("keytext", armoredKey)

	resp, err := c.HTTPClient.PostForm(u, form)
	if err != nil {
		return fmt.Errorf("keyserver upload: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("keyserver returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

type KeyResult struct {
	KeyID     string
	Algorithm string
	KeyLen    int
	Created   string
	Expires   string
	UIDs      []string
}

func parseMachineReadableIndex(body string) []KeyResult {
	var results []KeyResult
	var current *KeyResult

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "info:") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}

		switch parts[0] {
		case "pub":
			if current != nil {
				results = append(results, *current)
			}
			current = &KeyResult{}
			if len(parts) > 1 {
				current.KeyID = parts[1]
			}
			if len(parts) > 2 {
				switch parts[2] {
				case "1":
					current.Algorithm = "RSA"
				case "17":
					current.Algorithm = "DSA"
				case "22":
					current.Algorithm = "EdDSA"
				default:
					current.Algorithm = "algo:" + parts[2]
				}
			}
			if len(parts) > 4 {
				current.Created = parts[4]
			}
			if len(parts) > 5 {
				current.Expires = parts[5]
			}
		case "uid":
			if current != nil && len(parts) > 1 {
				uid, _ := url.QueryUnescape(parts[1])
				current.UIDs = append(current.UIDs, uid)
			}
		}
	}
	if current != nil {
		results = append(results, *current)
	}

	return results
}
