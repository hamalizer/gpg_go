// Package gui implements the Fyne-based graphical user interface.
package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/hamalizer/gpg_go/internal/config"
	"github.com/hamalizer/gpg_go/internal/keyring"
)

type App struct {
	fyneApp fyne.App
	window  fyne.Window
	cfg     *config.Config
	kr      *keyring.Keyring

	// R2-L-04: References to widgets that need refreshing after key operations.
	keyList        *widget.List
	recipientCheck *widget.CheckGroup
	signerSelect   *widget.Select
	sendSelect     *widget.Select
}

func Run(cfg *config.Config, kr *keyring.Keyring) {
	a := &App{
		fyneApp: app.NewWithID("io.gpg-go.gui"),
		cfg:     cfg,
		kr:      kr,
	}

	a.fyneApp.Settings().SetTheme(theme.DefaultTheme())
	a.window = a.fyneApp.NewWindow("gpg-go - OpenPGP Suite")
	a.window.Resize(fyne.NewSize(900, 650))

	tabs := container.NewAppTabs(
		container.NewTabItem("Keys", a.buildKeysTab()),
		container.NewTabItem("Encrypt / Decrypt", a.buildEncryptTab()),
		container.NewTabItem("Sign / Verify", a.buildSignTab()),
		container.NewTabItem("Keyserver", a.buildKeyserverTab()),
		container.NewTabItem("Settings", a.buildSettingsTab()),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	a.window.SetContent(tabs)
	a.window.ShowAndRun()
}

// refreshKeyWidgets updates all widgets that display key lists (R2-L-04).
// Call this after generating, importing, deleting, or receiving keys.
func (a *App) refreshKeyWidgets() {
	if a.keyList != nil {
		a.keyList.Refresh()
	}
	if a.recipientCheck != nil {
		a.recipientCheck.Options = a.getKeyOptions()
		a.recipientCheck.Refresh()
	}
	if a.signerSelect != nil {
		a.signerSelect.Options = a.getSecretKeyOptions()
		a.signerSelect.Refresh()
	}
	if a.sendSelect != nil {
		a.sendSelect.Options = a.getKeyOptions()
		a.sendSelect.Refresh()
	}
}
