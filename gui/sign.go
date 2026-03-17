package gui

import (
	"bytes"
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/hamalizer/gpg_go/internal/crypto"
	"github.com/hamalizer/gpg_go/internal/keyring"
)

func (a *App) buildSignTab() fyne.CanvasObject {
	// --- Sign section ---
	signInput := widget.NewMultiLineEntry()
	signInput.SetPlaceHolder("Enter message to sign...")
	signInput.SetMinRowsVisible(8)

	signOutput := widget.NewMultiLineEntry()
	signOutput.SetPlaceHolder("Signature will appear here...")
	signOutput.SetMinRowsVisible(8)

	signerSelect := widget.NewSelect(a.getSecretKeyOptions(), nil)
	a.signerSelect = signerSelect // R2-L-04: Store reference for cross-tab refresh
	if len(a.kr.SecretKeys()) > 0 {
		signerSelect.SetSelectedIndex(0)
	}

	signTypeSelect := widget.NewSelect(
		[]string{"Detached (armored)", "Clear-signed", "Inline (armored)"},
		nil,
	)
	signTypeSelect.SetSelectedIndex(0)

	signBtn := widget.NewButton("Sign", func() {
		if signInput.Text == "" {
			dialog.ShowError(fmt.Errorf("enter message to sign"), a.window)
			return
		}

		keyID := extractKeyID(signerSelect.Selected)
		signer := a.kr.FindSecretKey(keyID)
		if signer == nil {
			secKeys := a.kr.SecretKeys()
			if len(secKeys) > 0 {
				signer = secKeys[0]
			} else {
				dialog.ShowError(fmt.Errorf("no signing key available"), a.window)
				return
			}
		}

		doSign := func() {
			params := crypto.SignParams{
				Signer: signer,
				Armor:  true,
			}

			switch signTypeSelect.SelectedIndex() {
			case 0:
				params.Detached = true
			case 1:
				params.Cleartext = true
			case 2:
				// inline
			}

			result, err := crypto.Sign(strings.NewReader(signInput.Text), params)
			if err != nil {
				dialog.ShowError(fmt.Errorf("signing failed: %w", err), a.window)
				return
			}
			signOutput.SetText(string(result))
		}

		// If the signing key is passphrase-protected, prompt for it
		if keyring.IsEntityKeyEncrypted(signer) {
			passEntry := widget.NewPasswordEntry()
			passEntry.SetPlaceHolder("Enter passphrase to unlock signing key")
			dialog.ShowForm("Passphrase Required", "Unlock", "Cancel",
				[]*widget.FormItem{widget.NewFormItem("Passphrase", passEntry)},
				func(ok bool) {
					if !ok {
						return
					}
					pass := []byte(passEntry.Text)
					defer func() {
						for i := range pass {
							pass[i] = 0
						}
					}()
					if err := keyring.DecryptEntityKeys(signer, pass); err != nil {
						dialog.ShowError(fmt.Errorf("wrong passphrase: %w", err), a.window)
						return
					}
					doSign()
				}, a.window)
			return
		}

		doSign()
	})

	signSection := container.NewVBox(
		widget.NewLabelWithStyle("Sign", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Signing Key:"),
		signerSelect,
		widget.NewLabel("Signature Type:"),
		signTypeSelect,
		signInput,
		signBtn,
		signOutput,
	)

	// --- Verify section ---
	verifyMsg := widget.NewMultiLineEntry()
	verifyMsg.SetPlaceHolder("Paste the original message (for detached sig verification)...")
	verifyMsg.SetMinRowsVisible(5)

	verifySig := widget.NewMultiLineEntry()
	verifySig.SetPlaceHolder("Paste signature or signed message here...")
	verifySig.SetMinRowsVisible(5)

	verifyResult := widget.NewLabel("")

	verifyDetachedBtn := widget.NewButton("Verify (Detached)", func() {
		if verifyMsg.Text == "" || verifySig.Text == "" {
			dialog.ShowError(fmt.Errorf("paste both message and signature"), a.window)
			return
		}

		result, err := crypto.VerifyDetached(
			strings.NewReader(verifyMsg.Text),
			strings.NewReader(verifySig.Text),
			a.kr.PublicKeys(),
		)
		if err != nil {
			dialog.ShowError(err, a.window)
			return
		}

		if result.Valid {
			verifyResult.SetText("VALID: " + result.Message)
		} else {
			verifyResult.SetText("INVALID: " + result.Message)
		}
	})

	verifyInlineBtn := widget.NewButton("Verify (Inline)", func() {
		if verifySig.Text == "" {
			dialog.ShowError(fmt.Errorf("paste signed message"), a.window)
			return
		}

		result, plaintext, err := crypto.VerifyInline(
			bytes.NewReader([]byte(verifySig.Text)),
			a.kr.PublicKeys(),
		)
		if err != nil {
			dialog.ShowError(err, a.window)
			return
		}

		if result.Valid {
			verifyResult.SetText("VALID: " + result.Message)
		} else {
			verifyResult.SetText("INVALID: " + result.Message)
		}

		if len(plaintext) > 0 {
			verifyMsg.SetText(string(plaintext))
		}
	})

	verifySection := container.NewVBox(
		widget.NewLabelWithStyle("Verify", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Original message (for detached):"),
		verifyMsg,
		widget.NewLabel("Signature / Signed message:"),
		verifySig,
		container.NewHBox(verifyDetachedBtn, verifyInlineBtn),
		verifyResult,
	)

	return container.NewVScroll(container.NewVBox(
		signSection,
		widget.NewSeparator(),
		verifySection,
	))
}

func (a *App) getSecretKeyOptions() []string {
	var options []string
	for _, e := range a.kr.SecretKeys() {
		uid := keyring.PrimaryUID(e)
		options = append(options, fmt.Sprintf("%s [%s]", uid, e.PrimaryKey.KeyIdString()))
	}
	return options
}
