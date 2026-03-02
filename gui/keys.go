package gui

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/hamalizer/gpg_go/internal/crypto"
	"github.com/hamalizer/gpg_go/internal/keyring"
)

func (a *App) buildKeysTab() fyne.CanvasObject {
	keyList := widget.NewList(
		func() int {
			return len(a.getAllKeys())
		},
		func() fyne.CanvasObject {
			return container.NewVBox(
				widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
				widget.NewLabel(""),
			)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			c := o.(*fyne.Container)
			titleLabel := c.Objects[0].(*widget.Label)
			detailLabel := c.Objects[1].(*widget.Label)

			allKeys := a.getAllKeys()
			if i >= len(allKeys) {
				return
			}
			entity := allKeys[i]

			uid := keyring.PrimaryUID(entity)
			keyType := "pub"
			if entity.PrivateKey != nil {
				keyType = "sec"
			}

			titleLabel.SetText(fmt.Sprintf("[%s] %s", keyType, uid))
			detailLabel.SetText(fmt.Sprintf("ID: %s | Created: %s",
				entity.PrimaryKey.KeyIdString(),
				entity.PrimaryKey.CreationTime.Format("2006-01-02")))
		},
	)

	detailBox := widget.NewMultiLineEntry()
	detailBox.Wrapping = fyne.TextWrapWord
	detailBox.Disable()

	keyList.OnSelected = func(id widget.ListItemID) {
		allKeys := a.getAllKeys()
		if id >= len(allKeys) {
			return
		}
		detailBox.SetText(keyring.KeyInfo(allKeys[id]))
	}

	generateBtn := widget.NewButton("Generate Key", func() {
		a.showGenerateDialog(keyList)
	})

	importBtn := widget.NewButton("Import Key", func() {
		a.showImportDialog(keyList)
	})

	exportBtn := widget.NewButton("Export Key", func() {
		allKeys := a.getAllKeys()
		if len(allKeys) == 0 {
			dialog.ShowInformation("Export", "No keys to export.", a.window)
			return
		}
		a.showExportDialog()
	})

	deleteBtn := widget.NewButton("Delete Key", func() {
		allKeys := a.getAllKeys()
		if len(allKeys) == 0 {
			return
		}
		a.showDeleteDialog(keyList)
	})

	toolbar := container.NewHBox(generateBtn, importBtn, exportBtn, deleteBtn, layout.NewSpacer())
	detail := container.NewVScroll(detailBox)
	detail.SetMinSize(fyne.NewSize(400, 200))

	split := container.NewHSplit(
		container.NewBorder(nil, nil, nil, nil, keyList),
		detail,
	)
	split.SetOffset(0.4)

	return container.NewBorder(toolbar, nil, nil, nil, split)
}

func (a *App) getAllKeys() []*openpgp.Entity {
	var all []*openpgp.Entity
	seen := make(map[string]bool)

	for _, e := range a.kr.SecretKeys() {
		fp := fmt.Sprintf("%X", e.PrimaryKey.Fingerprint)
		if !seen[fp] {
			all = append(all, e)
			seen[fp] = true
		}
	}
	for _, e := range a.kr.PublicKeys() {
		fp := fmt.Sprintf("%X", e.PrimaryKey.Fingerprint)
		if !seen[fp] {
			all = append(all, e)
			seen[fp] = true
		}
	}
	return all
}

// keyOptionStrings builds display strings for a list of keys.
func keyOptionStrings(keys []*openpgp.Entity) []string {
	options := make([]string, 0, len(keys))
	for _, e := range keys {
		uid := keyring.PrimaryUID(e)
		options = append(options, fmt.Sprintf("%s [%s]", uid, e.PrimaryKey.KeyIdString()))
	}
	return options
}

func (a *App) showGenerateDialog(keyList *widget.List) {
	nameEntry := widget.NewEntry()
	nameEntry.SetPlaceHolder("John Doe")
	emailEntry := widget.NewEntry()
	emailEntry.SetPlaceHolder("john@example.com")
	commentEntry := widget.NewEntry()
	commentEntry.SetPlaceHolder("(optional)")
	passphraseEntry := widget.NewPasswordEntry()
	passphraseEntry.SetPlaceHolder("Passphrase to protect key (optional)")
	passphraseConfirm := widget.NewPasswordEntry()
	passphraseConfirm.SetPlaceHolder("Repeat passphrase")
	algoSelect := widget.NewSelect(
		[]string{"Ed25519 (recommended)", "RSA-4096", "RSA-3072", "RSA-2048"},
		nil,
	)
	algoSelect.SetSelectedIndex(0)

	form := dialog.NewForm("Generate New Key Pair", "Generate", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Name", nameEntry),
			widget.NewFormItem("Email", emailEntry),
			widget.NewFormItem("Comment", commentEntry),
			widget.NewFormItem("Passphrase", passphraseEntry),
			widget.NewFormItem("Confirm", passphraseConfirm),
			widget.NewFormItem("Algorithm", algoSelect),
		},
		func(ok bool) {
			if !ok {
				return
			}

			// Capture widget values before launching goroutine
			name := strings.TrimSpace(nameEntry.Text)
			email := strings.TrimSpace(emailEntry.Text)
			comment := strings.TrimSpace(commentEntry.Text)
			passphrase := []byte(passphraseEntry.Text)
			passConfirm := []byte(passphraseConfirm.Text)
			algoIdx := algoSelect.SelectedIndex()

			// Clear passphrase fields from UI
			passphraseEntry.SetText("")
			passphraseConfirm.SetText("")

			if name == "" || email == "" {
				dialog.ShowError(fmt.Errorf("name and email are required"), a.window)
				return
			}
			if !strings.Contains(email, "@") {
				dialog.ShowError(fmt.Errorf("invalid email address"), a.window)
				return
			}
			if len(passphrase) > 0 && string(passphrase) != string(passConfirm) {
				for i := range passphrase {
					passphrase[i] = 0
				}
				for i := range passConfirm {
					passConfirm[i] = 0
				}
				dialog.ShowError(fmt.Errorf("passphrases do not match"), a.window)
				return
			}
			for i := range passConfirm {
				passConfirm[i] = 0
			}

			algo := crypto.AlgoEd25519
			switch algoIdx {
			case 1:
				algo = crypto.AlgoRSA4096
			case 2:
				algo = crypto.AlgoRSA3072
			case 3:
				algo = crypto.AlgoRSA2048
			}

			progress := dialog.NewProgressInfinite("Generating", "Generating key pair...", a.window)
			progress.Show()

			go func() {
				defer func() {
					for i := range passphrase {
						passphrase[i] = 0
					}
				}()

				entity, err := crypto.GenerateKey(crypto.KeyGenParams{
					Name:       name,
					Comment:    comment,
					Email:      email,
					Algorithm:  algo,
					Passphrase: passphrase,
				})
				progress.Hide()

				if err != nil {
					dialog.ShowError(fmt.Errorf("key generation failed: %w", err), a.window)
					return
				}

				if err := a.kr.AddEntity(entity); err != nil {
					dialog.ShowError(fmt.Errorf("save key: %w", err), a.window)
					return
				}

				keyList.Refresh()
				dialog.ShowInformation("Success",
					fmt.Sprintf("Key generated!\n\n%s", keyring.KeyInfo(entity)),
					a.window)
			}()
		},
		a.window,
	)
	form.Resize(fyne.NewSize(450, 400))
	form.Show()
}

func (a *App) showImportDialog(keyList *widget.List) {
	entry := widget.NewMultiLineEntry()
	entry.SetPlaceHolder("Paste armored key here (-----BEGIN PGP PUBLIC KEY BLOCK-----)")
	entry.SetMinRowsVisible(10)

	d := dialog.NewForm("Import Key", "Import", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Key Data", entry),
		},
		func(ok bool) {
			if !ok || entry.Text == "" {
				return
			}

			imported, err := a.kr.ImportKey(strings.NewReader(entry.Text))
			if err != nil {
				dialog.ShowError(fmt.Errorf("import failed: %w", err), a.window)
				return
			}

			keyList.Refresh()
			dialog.ShowInformation("Imported",
				fmt.Sprintf("Imported %d key(s)", len(imported)),
				a.window)
		},
		a.window,
	)
	d.Resize(fyne.NewSize(500, 400))
	d.Show()
}

func (a *App) showExportDialog() {
	// Take a fresh snapshot of keys at dialog open time
	allKeys := a.getAllKeys()
	options := keyOptionStrings(allKeys)

	sel := widget.NewSelect(options, nil)
	sel.SetSelectedIndex(0)

	d := dialog.NewForm("Export Key", "Export", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Key", sel),
		},
		func(ok bool) {
			if !ok {
				return
			}
			idx := sel.SelectedIndex()
			if idx < 0 || idx >= len(allKeys) {
				return
			}

			entity := allKeys[idx]
			// Use fingerprint for reliable lookup
			identifier := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
			data, err := a.kr.ExportPublicKey(identifier, true)
			if err != nil {
				dialog.ShowError(err, a.window)
				return
			}

			result := widget.NewMultiLineEntry()
			result.SetText(string(data))
			result.Wrapping = fyne.TextWrapBreak

			exportDialog := dialog.NewCustom("Exported Key", "Close",
				container.NewScroll(result), a.window)
			exportDialog.Resize(fyne.NewSize(500, 400))
			exportDialog.Show()
		},
		a.window,
	)
	d.Resize(fyne.NewSize(400, 200))
	d.Show()
}

func (a *App) showDeleteDialog(keyList *widget.List) {
	// Take a fresh snapshot of keys at dialog open time
	allKeys := a.getAllKeys()
	options := keyOptionStrings(allKeys)

	sel := widget.NewSelect(options, nil)
	sel.SetSelectedIndex(0)

	d := dialog.NewForm("Delete Key", "Delete", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Key", sel),
		},
		func(ok bool) {
			if !ok {
				return
			}
			idx := sel.SelectedIndex()
			if idx < 0 || idx >= len(allKeys) {
				return
			}

			entity := allKeys[idx]
			keyID := entity.PrimaryKey.KeyIdString()

			dialog.ShowConfirm("Confirm Delete",
				fmt.Sprintf("Delete key %s?", keyID),
				func(confirmed bool) {
					if !confirmed {
						return
					}
					var errs []string
					if err := a.kr.DeletePublicKey(keyID); err != nil {
						errs = append(errs, fmt.Sprintf("public: %v", err))
					}
					if err := a.kr.DeleteSecretKey(keyID); err != nil {
						errs = append(errs, fmt.Sprintf("secret: %v", err))
					}
					if len(errs) > 0 {
						dialog.ShowError(fmt.Errorf("delete errors: %s", strings.Join(errs, "; ")), a.window)
					}
					keyList.Refresh()
				},
				a.window,
			)
		},
		a.window,
	)
	d.Show()
}
