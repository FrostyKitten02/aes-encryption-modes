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
	"io"
	"os"
	"path/filepath"
	"strings"
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

func (mApp *App) readFile(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return data, nil
}

func (mApp *App) writeFile(filePath string, data []byte) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func (mApp *App) getOutputFilePath(inputPath string, prefix string) string {
	dir := filepath.Dir(inputPath)
	filename := filepath.Base(inputPath)
	return filepath.Join(dir, prefix+filename)
}

func (mApp *App) encryptData(data []byte, mode string) ([]byte, error) {
	switch strings.ToUpper(mode) {
	case "ECB":
		return aesModes.EncryptECB(data, mApp.key)
	case "CBC":
		if mApp.nonce == nil {
			return nil, errors.New("nonce is required for CBC mode")
		}
		return aesModes.EncryptCBC(data, mApp.key, mApp.nonce)
	case "CTR":
		if mApp.nonce == nil {
			return nil, errors.New("nonce is required for CTR mode")
		}
		return aesModes.EncryptCTR(data, mApp.key, mApp.nonce)
	case "CCM":
		if mApp.nonce == nil {
			return nil, errors.New("nonce is required for CCM mode")
		}
		return aesModes.EncryptCCM(data, mApp.key, mApp.nonce, []byte{})
	default:
		return nil, fmt.Errorf("unsupported encryption mode: %s", mode)
	}
}

func (mApp *App) decryptData(data []byte, mode string) ([]byte, error) {
	switch strings.ToUpper(mode) {
	case "ECB":
		return aesModes.DecryptECB(data, mApp.key)
	case "CBC":
		if mApp.nonce == nil {
			return nil, errors.New("nonce is required for CBC mode")
		}
		return aesModes.DecryptCBC(data, mApp.key, mApp.nonce)
	case "CTR":
		if mApp.nonce == nil {
			return nil, errors.New("nonce is required for CTR mode")
		}
		return aesModes.DecryptCTR(data, mApp.key, mApp.nonce)
	case "CCM":
		if mApp.nonce == nil {
			return nil, errors.New("nonce is required for CCM mode")
		}

		return aesModes.DecryptCCM(data, mApp.key, mApp.nonce, []byte{})
	default:
		return nil, fmt.Errorf("unsupported decryption mode: %s", mode)
	}
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
	if mApp.modeDropdown.Text == "CCM" {
		if len(nonce) > 13 || len(nonce) < 7 {
			return fmt.Errorf("invalid nonce length")
		}

		mApp.updateEncryptBtnState()
		mApp.nonce = nonce
		return nil
	}

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
		if mApp.modeDropdown.Text == "CCM" {
			nonceStr = nonceStr[3:]
		}
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
		if mApp.selectedDataFilePath == nil {
			dialog.ShowError(errors.New("no file selected"), mApp.window)
			return
		}

		selectedMode := mApp.modeDropdown.Text
		if selectedMode == "" {
			dialog.ShowError(errors.New("no encryption mode selected"), mApp.window)
			return
		}

		outFile := mApp.getOutputFilePath(*mApp.selectedDataFilePath, "encrypted_")

		mApp.setLoading(false)
		go func() {
			defer mApp.setLoading(true)

			data, err := mApp.readFile(*mApp.selectedDataFilePath)
			if err != nil {
				dialog.ShowError(fmt.Errorf("failed to read file: %w", err), mApp.window)
				return
			}

			encryptedData, err2 := mApp.encryptData(data, selectedMode)
			if err2 != nil {
				dialog.ShowError(fmt.Errorf("encryption failed: %w", err2), mApp.window)
				return
			}

			err3 := mApp.writeFile(outFile, encryptedData)
			if err3 != nil {
				dialog.ShowError(fmt.Errorf("failed to write encrypted file: %w", err3), mApp.window)
				return
			}

			dialog.ShowInformation("Success", fmt.Sprintf("File encrypted successfully!\nOutput: %s", outFile), mApp.window)
		}()
	})

	mApp.decryptBtn = widget.NewButton("Decrypt", func() {
		if mApp.selectedDataFilePath == nil {
			dialog.ShowError(errors.New("no file selected"), mApp.window)
			return
		}

		selectedMode := mApp.modeDropdown.Text
		if selectedMode == "" {
			dialog.ShowError(errors.New("no decryption mode selected"), mApp.window)
			return
		}

		outFile := mApp.getOutputFilePath(*mApp.selectedDataFilePath, "decrypted_")

		mApp.setLoading(false)
		go func() {
			defer mApp.setLoading(true)

			data, err := mApp.readFile(*mApp.selectedDataFilePath)
			if err != nil {
				dialog.ShowError(fmt.Errorf("failed to read file: %w", err), mApp.window)
				return
			}

			decryptedData, err2 := mApp.decryptData(data, selectedMode)
			if err2 != nil {
				dialog.ShowError(fmt.Errorf("decryption failed: %w", err2), mApp.window)
				return
			}

			err3 := mApp.writeFile(outFile, decryptedData)
			if err3 != nil {
				dialog.ShowError(fmt.Errorf("failed to write decrypted file: %w", err3), mApp.window)
				return
			}

			dialog.ShowInformation("Success", fmt.Sprintf("File decrypted successfully!\nOutput: %s", outFile), mApp.window)
		}()
	})
	mApp.encryptBtn.Disable()
	mApp.decryptBtn.Disable()

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
		mApp.decryptBtn,
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
