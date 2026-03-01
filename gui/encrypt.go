package gui

import (
	"bytes"
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/hamalizer/gpg_go/internal/crypto"
)

func (a *App) buildEncryptTab() fyne.CanvasObject {
	// --- Encrypt section ---
	inputEntry := widget.NewMultiLineEntry()
	inputEntry.SetPlaceHolder("Enter plaintext to encrypt...")
	inputEntry.SetMinRowsVisible(8)

	outputEntry := widget.NewMultiLineEntry()
	outputEntry.SetPlaceHolder("Encrypted output will appear here...")
	outputEntry.SetMinRowsVisible(8)

	recipientSelect := widget.NewCheckGroup(a.getKeyOptions(), nil)

	armorCheck := widget.NewCheck("ASCII Armor", nil)
	armorCheck.SetChecked(true)

	encryptBtn := widget.NewButton("Encrypt", func() {
		if inputEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("enter text to encrypt"), a.window)
			return
		}
		if len(recipientSelect.Selected) == 0 {
			dialog.ShowError(fmt.Errorf("select at least one recipient"), a.window)
			return
		}

		var recipients []*openpgp.Entity
		for _, sel := range recipientSelect.Selected {
			keyID := extractKeyID(sel)
			entity := a.kr.FindPublicKey(keyID)
			if entity != nil {
				recipients = append(recipients, entity)
			}
		}

		result, err := crypto.Encrypt(strings.NewReader(inputEntry.Text), crypto.EncryptParams{
			Recipients: recipients,
			Armor:      armorCheck.Checked,
		})
		if err != nil {
			dialog.ShowError(fmt.Errorf("encryption failed: %w", err), a.window)
			return
		}
		outputEntry.SetText(string(result))
	})

	symmetricPassEntry := widget.NewPasswordEntry()
	symmetricPassEntry.SetPlaceHolder("Passphrase for symmetric encryption")

	symmetricBtn := widget.NewButton("Encrypt (Symmetric)", func() {
		if inputEntry.Text == "" || symmetricPassEntry.Text == "" {
			dialog.ShowError(fmt.Errorf("enter text and passphrase"), a.window)
			return
		}

		result, err := crypto.EncryptSymmetric(
			strings.NewReader(inputEntry.Text),
			[]byte(symmetricPassEntry.Text),
			armorCheck.Checked,
		)
		if err != nil {
			dialog.ShowError(fmt.Errorf("encryption failed: %w", err), a.window)
			return
		}
		outputEntry.SetText(string(result))
	})

	encryptSection := container.NewVBox(
		widget.NewLabelWithStyle("Encrypt", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Recipients:"),
		recipientSelect,
		armorCheck,
		inputEntry,
		container.NewHBox(encryptBtn, symmetricBtn),
		symmetricPassEntry,
		outputEntry,
	)

	// --- Decrypt section ---
	decInput := widget.NewMultiLineEntry()
	decInput.SetPlaceHolder("Paste encrypted message here...")
	decInput.SetMinRowsVisible(8)

	decOutput := widget.NewMultiLineEntry()
	decOutput.SetPlaceHolder("Decrypted output will appear here...")
	decOutput.SetMinRowsVisible(8)
	decOutput.Disable()

	decPassEntry := widget.NewPasswordEntry()
	decPassEntry.SetPlaceHolder("Passphrase (if needed)")

	statusLabel := widget.NewLabel("")

	decryptBtn := widget.NewButton("Decrypt", func() {
		if decInput.Text == "" {
			dialog.ShowError(fmt.Errorf("paste encrypted message"), a.window)
			return
		}

		allKeys := a.kr.AllKeys()
		var passphrase []byte
		if decPassEntry.Text != "" {
			passphrase = []byte(decPassEntry.Text)
		}

		result, err := crypto.Decrypt(bytes.NewReader([]byte(decInput.Text)), allKeys, passphrase)
		if err != nil {
			dialog.ShowError(fmt.Errorf("decryption failed: %w", err), a.window)
			return
		}

		decOutput.Enable()
		decOutput.SetText(string(result.Plaintext))
		decOutput.Disable()

		if result.IsSigned {
			if result.SignatureOK {
				statusLabel.SetText("Signature: VALID")
			} else {
				statusLabel.SetText("Signature: INVALID")
			}
		} else {
			statusLabel.SetText("Message was not signed.")
		}
	})

	decryptSection := container.NewVBox(
		widget.NewLabelWithStyle("Decrypt", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		decInput,
		decPassEntry,
		decryptBtn,
		statusLabel,
		decOutput,
	)

	return container.NewVScroll(container.NewVBox(
		encryptSection,
		widget.NewSeparator(),
		decryptSection,
	))
}

func (a *App) getKeyOptions() []string {
	var options []string
	seen := make(map[string]bool)

	for _, e := range a.kr.PublicKeys() {
		id := e.PrimaryKey.KeyIdString()
		if seen[id] {
			continue
		}
		seen[id] = true
		var uid string
		for _, identity := range e.Identities {
			uid = identity.Name
			break
		}
		options = append(options, fmt.Sprintf("%s [%s]", uid, e.PrimaryKey.KeyIdShortString()))
	}
	return options
}

func extractKeyID(option string) string {
	start := strings.LastIndex(option, "[")
	end := strings.LastIndex(option, "]")
	if start >= 0 && end > start {
		return option[start+1 : end]
	}
	return option
}
