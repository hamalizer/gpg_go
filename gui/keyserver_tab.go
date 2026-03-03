package gui

import (
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/hamalizer/gpg_go/internal/keyring"
	"github.com/hamalizer/gpg_go/internal/keyserver"
)

func (a *App) buildKeyserverTab() fyne.CanvasObject {
	serverEntry := widget.NewEntry()
	serverEntry.SetText(a.cfg.Keyserver)

	// --- Search ---
	searchEntry := widget.NewEntry()
	searchEntry.SetPlaceHolder("Search by name, email, or key ID...")

	searchResults := widget.NewMultiLineEntry()
	searchResults.SetMinRowsVisible(10)
	searchResults.Disable()

	searchBtn := widget.NewButton("Search", func() {
		if searchEntry.Text == "" {
			return
		}
		if !isValidServerURL(serverEntry.Text) {
			dialog.ShowError(fmt.Errorf("invalid keyserver URL"), a.window)
			return
		}
		client := keyserver.NewClient(serverEntry.Text)

		progress := dialog.NewProgressInfinite("Searching", "Querying keyserver...", a.window)
		progress.Show()

		go func() {
			results, err := client.SearchKeys(searchEntry.Text)
			progress.Hide()

			if err != nil {
				dialog.ShowError(fmt.Errorf("search failed: %w", err), a.window)
				return
			}

			if len(results) == 0 {
				searchResults.Enable()
				searchResults.SetText("No keys found.")
				searchResults.Disable()
				return
			}

			var sb strings.Builder
			for _, r := range results {
				fmt.Fprintf(&sb, "Key ID: %s  (%s)\n", r.KeyID, r.Algorithm)
				for _, uid := range r.UIDs {
					fmt.Fprintf(&sb, "  uid: %s\n", uid)
				}
				sb.WriteString("\n")
			}
			searchResults.Enable()
			searchResults.SetText(sb.String())
			searchResults.Disable()
		}()
	})

	// --- Receive ---
	recvEntry := widget.NewEntry()
	recvEntry.SetPlaceHolder("Key ID to fetch (e.g., ABCD1234)")

	recvBtn := widget.NewButton("Receive Key", func() {
		if recvEntry.Text == "" {
			return
		}
		if !isValidServerURL(serverEntry.Text) {
			dialog.ShowError(fmt.Errorf("invalid keyserver URL"), a.window)
			return
		}
		client := keyserver.NewClient(serverEntry.Text)

		progress := dialog.NewProgressInfinite("Fetching", "Downloading key...", a.window)
		progress.Show()

		go func() {
			entities, err := client.FetchKey(recvEntry.Text)
			progress.Hide()

			if err != nil {
				dialog.ShowError(fmt.Errorf("fetch failed: %w", err), a.window)
				return
			}

			for _, entity := range entities {
				if err := a.kr.AddEntity(entity); err != nil {
					dialog.ShowError(err, a.window)
					return
				}
			}
			a.refreshKeyWidgets()
			dialog.ShowInformation("Success",
				fmt.Sprintf("Imported %d key(s) from keyserver", len(entities)),
				a.window)
		}()
	})

	// --- Send ---
	sendSelect := widget.NewSelect(a.getKeyOptions(), nil)
	a.sendSelect = sendSelect // R2-L-04: Store reference for cross-tab refresh
	if len(a.kr.PublicKeys()) > 0 {
		sendSelect.SetSelectedIndex(0)
	}

	sendBtn := widget.NewButton("Send Key", func() {
		if sendSelect.Selected == "" {
			return
		}
		if !isValidServerURL(serverEntry.Text) {
			dialog.ShowError(fmt.Errorf("invalid keyserver URL"), a.window)
			return
		}
		keyID := extractKeyID(sendSelect.Selected)
		data, err := a.kr.ExportPublicKey(keyID, true)
		if err != nil {
			dialog.ShowError(err, a.window)
			return
		}

		client := keyserver.NewClient(serverEntry.Text)

		progress := dialog.NewProgressInfinite("Uploading", "Sending key to keyserver...", a.window)
		progress.Show()

		go func() {
			err := client.UploadKey(string(data))
			progress.Hide()

			if err != nil {
				dialog.ShowError(fmt.Errorf("upload failed: %w", err), a.window)
				return
			}
			dialog.ShowInformation("Success",
				fmt.Sprintf("Key %s uploaded to %s",
					keyID, serverEntry.Text),
				a.window)
		}()
	})

	// --- Refresh keyring ---
	refreshBtn := widget.NewButton("Refresh Keys from Server", func() {
		if !isValidServerURL(serverEntry.Text) {
			dialog.ShowError(fmt.Errorf("invalid keyserver URL"), a.window)
			return
		}
		client := keyserver.NewClient(serverEntry.Text)
		progress := dialog.NewProgressInfinite("Refreshing", "Updating keys from keyserver...", a.window)
		progress.Show()

		go func() {
			updated := 0
			pubKeys := a.kr.PublicKeys()
			for i, entity := range pubKeys {
				keyID := entity.PrimaryKey.KeyIdString()
				entities, err := client.FetchKey(keyID)
				if err != nil {
					continue
				}
				for _, e := range entities {
					if err := a.kr.AddEntity(e); err == nil {
						updated++
					}
				}
				// R2-L-02: Rate-limit requests to avoid triggering keyserver
				// IP blocking. Skip the sleep after the last key.
				if i < len(pubKeys)-1 {
					time.Sleep(200 * time.Millisecond)
				}
			}

			progress.Hide()
			dialog.ShowInformation("Refresh Complete",
				fmt.Sprintf("Updated %d key(s)", updated),
				a.window)
		}()
	})

	// --- Key details on receive ---
	keyDetailLabel := widget.NewLabel("")

	recvEntry.OnChanged = func(s string) {
		if len(s) >= 8 {
			entity := a.kr.FindPublicKey(s)
			if entity != nil {
				keyDetailLabel.SetText("Already in keyring: " + keyring.KeyInfo(entity))
			} else {
				keyDetailLabel.SetText("")
			}
		} else {
			keyDetailLabel.SetText("")
		}
	}

	return container.NewVScroll(container.NewVBox(
		widget.NewLabelWithStyle("Keyserver", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Server URL:"),
		serverEntry,
		widget.NewSeparator(),

		widget.NewLabelWithStyle("Search Keys", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, searchBtn, searchEntry),
		searchResults,
		widget.NewSeparator(),

		widget.NewLabelWithStyle("Receive Key", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewBorder(nil, nil, nil, recvBtn, recvEntry),
		keyDetailLabel,
		widget.NewSeparator(),

		widget.NewLabelWithStyle("Send Key", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		container.NewHBox(sendSelect, sendBtn),
		widget.NewSeparator(),

		refreshBtn,
	))
}

// isValidServerURL checks that the server URL looks reasonable.
func isValidServerURL(url string) bool {
	url = strings.TrimSpace(url)
	if url == "" {
		return false
	}
	return strings.HasPrefix(url, "hkp://") ||
		strings.HasPrefix(url, "hkps://") ||
		strings.HasPrefix(url, "http://") ||
		strings.HasPrefix(url, "https://")
}
