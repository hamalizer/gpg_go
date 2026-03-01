package gui

import (
	"fmt"
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/hamalizer/gpg_go/internal/config"
)

func (a *App) buildSettingsTab() fyne.CanvasObject {
	homeDirLabel := widget.NewLabel(a.cfg.HomeDir)
	pubRingLabel := widget.NewLabel(a.cfg.PubRingDir)
	secRingLabel := widget.NewLabel(a.cfg.SecRingDir)

	keyserverEntry := widget.NewEntry()
	keyserverEntry.SetText(a.cfg.Keyserver)

	pubCount := len(a.kr.PublicKeys())
	secCount := len(a.kr.SecretKeys())
	statsLabel := widget.NewLabel(fmt.Sprintf("Public keys: %d | Secret keys: %d", pubCount, secCount))

	themeSelect := widget.NewSelect([]string{"System Default", "Light", "Dark"}, func(s string) {
		switch s {
		case "Light":
			a.fyneApp.Settings().SetTheme(&variantTheme{variant: theme.VariantLight})
		case "Dark":
			a.fyneApp.Settings().SetTheme(&variantTheme{variant: theme.VariantDark})
		default:
			a.fyneApp.Settings().SetTheme(theme.DefaultTheme())
		}
	})
	themeSelect.SetSelectedIndex(0)

	saveBtn := widget.NewButton("Save Settings", func() {
		a.cfg.Keyserver = keyserverEntry.Text
		// Update stats on save
		statsLabel.SetText(fmt.Sprintf("Public keys: %d | Secret keys: %d",
			len(a.kr.PublicKeys()), len(a.kr.SecretKeys())))
		dialog.ShowInformation("Settings", "Settings applied for this session.", a.window)
	})

	versionLabel := widget.NewLabel(fmt.Sprintf("gpg-go v%s", config.AppVersion))

	return container.NewVBox(
		widget.NewLabelWithStyle("Settings", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewSeparator(),

		widget.NewLabelWithStyle("Paths", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewForm(
			widget.NewFormItem("Home Directory", homeDirLabel),
			widget.NewFormItem("Public Keyring", pubRingLabel),
			widget.NewFormItem("Secret Keyring", secRingLabel),
		),
		widget.NewSeparator(),

		widget.NewLabelWithStyle("Keyserver", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewForm(
			widget.NewFormItem("Default Server", keyserverEntry),
		),
		widget.NewSeparator(),

		widget.NewLabelWithStyle("Appearance", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewForm(
			widget.NewFormItem("Theme", themeSelect),
		),
		widget.NewSeparator(),

		widget.NewLabelWithStyle("Statistics", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		statsLabel,
		widget.NewSeparator(),

		saveBtn,
		versionLabel,
	)
}

// variantTheme wraps the default theme with a forced variant.
type variantTheme struct {
	variant fyne.ThemeVariant
}

func (t *variantTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	return theme.DefaultTheme().Color(name, t.variant)
}

func (t *variantTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (t *variantTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (t *variantTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}
