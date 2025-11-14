package gui

import (
	"aes-encryption-modes/aesModes"
	"crypto/aes"
	"errors"
	"fmt"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

type App struct {
	app    fyne.App
	window fyne.Window

	modeDropdown *widget.SelectEntry

	dataFileLabel        *widget.Label
	dataFileButton       *widget.Button
	selectedDataFilePath *string

	keyInputText   *widget.Entry
	generateKeyBtn *widget.Button
	key            []byte

	nonceInputText   *widget.Entry
	generateNonceBtn *widget.Button
	nonce            []byte

	loader     *widget.ProgressBarInfinite
	encryptBtn *widget.Button
	decryptBtn *widget.Button
}

func (mApp *App) onKeyInputChange(val string) error {
	key := []byte(val)
	if len(key) != aes.BlockSize {
		mApp.nonce = nil
		mApp.updateEncryptBtnState()
		return fmt.Errorf("invalid key length")
	}

	mApp.updateEncryptBtnState()
	mApp.key = key
	return nil
}

func (mApp *App) onNonceInputChange(val string) error {
	nonce := []byte(val)
	if len(nonce) != aes.BlockSize {
		mApp.nonce = nil
		mApp.updateEncryptBtnState()
		return fmt.Errorf("invalid nonce length")
	}

	mApp.updateEncryptBtnState()
	mApp.nonce = nonce
	return nil
}

func (mApp *App) updateEncryptBtnState() {
	if mApp.key == nil || mApp.selectedDataFilePath == nil {
		mApp.encryptBtn.Disable()
		mApp.decryptBtn.Disable()
		return
	}

	mApp.encryptBtn.Enable()
	mApp.decryptBtn.Enable()
}

func (mApp *App) setSelectedDataFilePath(val *string) {
	mApp.selectedDataFilePath = val
	mApp.updateEncryptBtnState()

	if mApp.selectedDataFilePath == nil {
		mApp.dataFileLabel.SetText("No file selected")
		return
	}

	mApp.dataFileButton.SetText(*mApp.selectedDataFilePath)
}

func (mApp *App) createGenerateBtns() {
	mApp.generateNonceBtn = widget.NewButton("Generate", func() {
		nonceStr := aesModes.GenerateIv()
		mApp.nonceInputText.SetText(nonceStr)
	})

	mApp.generateKeyBtn = widget.NewButton("Generate", func() {
		keyStr := aesModes.GenerateKey()
		mApp.keyInputText.SetText(keyStr)
	})
}

func (mApp *App) setLoading(finished bool) {
	if finished {
		mApp.encryptBtn.Enable()
		mApp.decryptBtn.Enable()
		mApp.keyInputText.Enable()
		mApp.nonceInputText.Enable()
		mApp.dataFileButton.Enable()
		mApp.loader.Hide()
		return
	}

	mApp.loader.Show()
	mApp.encryptBtn.Disable()
	mApp.decryptBtn.Disable()
	mApp.keyInputText.Disable()
	mApp.nonceInputText.Disable()
	mApp.dataFileButton.Disable()
}

func (mApp *App) Init() {
	mApp.app = app.NewWithID("AesModes")
	mApp.window = mApp.app.NewWindow("AesModes")

	mApp.modeDropdown = widget.NewSelectEntry([]string{"ECB", "CBC", "CTR", "CCM"})
	mApp.modeDropdown.SetText("ECB")

	mApp.keyInputText = widget.NewEntry()
	mApp.keyInputText.Validator = mApp.onKeyInputChange
	mApp.keyInputText.AlwaysShowValidationError = true

	mApp.nonceInputText = widget.NewEntry()
	mApp.nonceInputText.Validator = mApp.onNonceInputChange
	mApp.nonceInputText.AlwaysShowValidationError = true

	mApp.dataFileLabel = widget.NewLabel("No file selected")
	mApp.selectedDataFilePath = nil
	mApp.dataFileButton = widget.NewButton("Select data file", func() {
		d := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, mApp.window)
				mApp.setSelectedDataFilePath(nil)
				return
			}
			if reader == nil {
				mApp.setSelectedDataFilePath(nil)
				dialog.ShowError(errors.New("error occured selecting file"), mApp.window)
				return
			}

			path := reader.URI().Path()
			mApp.setSelectedDataFilePath(&path)

			defer reader.Close()
		}, mApp.window)
		d.Show()
	})

	mApp.loader = widget.NewProgressBarInfinite()
	mApp.loader.Hide()
	mApp.encryptBtn = widget.NewButton("Encrypt", func() {
		//encryptedSuffix := ".enc"
		//decrypting := strings.HasSuffix(*mApp.selectedDataFilePath, encryptedSuffix)
		//
		//var outFile string
		//if decrypting {
		//	outFile = strings.TrimSuffix(*mApp.selectedDataFilePath, encryptedSuffix)
		//} else {
		//	outFile = *mApp.selectedDataFilePath + encryptedSuffix
		//}
		//
		//mApp.setLoading(false)
		//go func() {
		//	//TODO encryption logic!!
		//}()
	})

	mApp.decryptBtn = widget.NewButton("Decrypt", func() {
		//encryptedSuffix := ".enc"
		//decrypting := strings.HasSuffix(*mApp.selectedDataFilePath, encryptedSuffix)
		//
		//var outFile string
		//if decrypting {
		//	outFile = strings.TrimSuffix(*mApp.selectedDataFilePath, encryptedSuffix)
		//} else {
		//	outFile = *mApp.selectedDataFilePath + encryptedSuffix
		//}
		//
		//mApp.setLoading(false)
		//go func() {
		//	//TODO decryption logic!!
		//}()
	})
	mApp.encryptBtn.Disable()

	mApp.createGenerateBtns()
}

func (mApp *App) ShowAndRun() {

	mainContent := container.NewVBox(
		&widget.Form{
			Items: []*widget.FormItem{
				{
					Text:   "Mode",
					Widget: mApp.modeDropdown,
				},
				{
					Text: "Key",
					Widget: container.NewVBox(
						mApp.keyInputText,
						mApp.generateKeyBtn,
					),
				},
				{
					Text: "Nonce",
					Widget: container.NewVBox(
						mApp.nonceInputText,
						mApp.generateNonceBtn,
					),
				},
			},
		},
		mApp.dataFileLabel,
		mApp.dataFileButton,
		mApp.encryptBtn,
	)

	mApp.window.SetContent(container.NewStack(
		mainContent,
		mApp.loader,
	))

	mApp.window.ShowAndRun()
}

func ShowGui() {
	myApp := App{}
	myApp.Init()
	myApp.ShowAndRun()
}
