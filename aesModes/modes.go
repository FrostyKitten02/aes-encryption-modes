package aesModes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs7: data is empty")
	}
	padding := int(data[length-1])
	if padding > length || padding > aes.BlockSize {
		return nil, errors.New("pkcs7: invalid padding")
	}
	for i := 0; i < padding; i++ {
		if data[length-1-i] != byte(padding) {
			return nil, errors.New("pkcs7: invalid padding")
		}
	}
	return data[:length-padding], nil
}

func xorBytes(dst, a, b []byte) {
	for i := 0; i < len(dst); i++ {
		dst[i] = a[i] ^ b[i]
	}
}

func EncryptECB(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	plaintext = pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	blockSize := block.BlockSize()

	for i := 0; i < len(plaintext); i += blockSize {
		block.Encrypt(ciphertext[i:i+blockSize], plaintext[i:i+blockSize])
	}

	return ciphertext, nil
}

func DecryptECB(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	plaintext := make([]byte, len(ciphertext))
	blockSize := block.BlockSize()

	for i := 0; i < len(ciphertext); i += blockSize {
		block.Decrypt(plaintext[i:i+blockSize], ciphertext[i:i+blockSize])
	}

	plaintext, err = pkcs7Unpad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to unpad: %w", err)
	}

	return plaintext, nil
}

func EncryptCBC(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV length must be %d bytes", aes.BlockSize)
	}

	plaintext = pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(plaintext))
	blockSize := block.BlockSize()

	prevBlock := iv
	tempBlock := make([]byte, blockSize)

	for i := 0; i < len(plaintext); i += blockSize {
		xorBytes(tempBlock, plaintext[i:i+blockSize], prevBlock)
		block.Encrypt(ciphertext[i:i+blockSize], tempBlock)
		prevBlock = ciphertext[i : i+blockSize]
	}

	return ciphertext, nil
}

func DecryptCBC(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV length must be %d bytes", aes.BlockSize)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	plaintext := make([]byte, len(ciphertext))
	blockSize := block.BlockSize()

	prevBlock := iv
	tempBlock := make([]byte, blockSize)

	for i := 0; i < len(ciphertext); i += blockSize {
		block.Decrypt(tempBlock, ciphertext[i:i+blockSize])
		xorBytes(plaintext[i:i+blockSize], tempBlock, prevBlock)
		prevBlock = ciphertext[i : i+blockSize]
	}

	plaintext, err = pkcs7Unpad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to unpad: %w", err)
	}

	return plaintext, nil
}

func EncryptCTR(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV length must be %d bytes", aes.BlockSize)
	}

	ciphertext := make([]byte, len(plaintext))
	blockSize := block.BlockSize()

	counter := make([]byte, blockSize)
	copy(counter, iv)

	keyStream := make([]byte, blockSize)

	for i := 0; i < len(plaintext); i += blockSize {
		block.Encrypt(keyStream, counter)

		end := i + blockSize
		if end > len(plaintext) {
			end = len(plaintext)
		}

		xorBytes(ciphertext[i:end], plaintext[i:end], keyStream[:end-i])

		incrementCounter(counter)
	}

	return ciphertext, nil
}

func DecryptCTR(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	return EncryptCTR(ciphertext, key, iv)
}

func incrementCounter(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
}

func EncryptCCM(plaintext []byte, key []byte, nonce []byte, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(nonce) < 7 || len(nonce) > 13 {
		return nil, errors.New("nonce length must be between 7 and 13 bytes")
	}

	tagLen := 16
	L := 15 - len(nonce)

	tag, err2 := computeCCMTag(block, nonce, plaintext, additionalData, tagLen, L)
	if err2 != nil {
		return nil, err2
	}

	encrypted := encryptCCMCTR(block, nonce, plaintext, L)

	encryptedTag := make([]byte, tagLen)
	ctrBlock := buildCCMCTRBlock(nonce, 0, L)
	keyStream := make([]byte, aes.BlockSize)
	block.Encrypt(keyStream, ctrBlock)
	xorBytes(encryptedTag, tag, keyStream[:tagLen])

	result := make([]byte, len(encrypted)+tagLen)
	copy(result, encrypted)
	copy(result[len(encrypted):], encryptedTag)

	return result, nil
}

func DecryptCCM(ciphertext []byte, key []byte, nonce []byte, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(nonce) < 7 || len(nonce) > 13 {
		return nil, errors.New("nonce length must be between 7 and 13 bytes")
	}

	tagLen := 16
	L := 15 - len(nonce)

	if len(ciphertext) < tagLen {
		return nil, errors.New("ciphertext too short")
	}

	encryptedData := ciphertext[:len(ciphertext)-tagLen]
	encryptedTag := ciphertext[len(ciphertext)-tagLen:]

	ctrBlock := buildCCMCTRBlock(nonce, 0, L)
	keyStream := make([]byte, aes.BlockSize)
	block.Encrypt(keyStream, ctrBlock)

	receivedTag := make([]byte, tagLen)
	xorBytes(receivedTag, encryptedTag, keyStream[:tagLen])

	plaintext := encryptCCMCTR(block, nonce, encryptedData, L)

	expectedTag, err := computeCCMTag(block, nonce, plaintext, additionalData, tagLen, L)
	if err != nil {
		return nil, err
	}

	for i := 0; i < tagLen; i++ {
		if receivedTag[i] != expectedTag[i] {
			return nil, errors.New("authentication failed")
		}
	}

	return plaintext, nil
}

func computeCCMTag(block cipher.Block, nonce, plaintext, additionalData []byte, tagLen, L int) ([]byte, error) {
	b0 := make([]byte, aes.BlockSize)

	flags := byte(0)
	if len(additionalData) > 0 {
		flags |= 0x40
	}
	flags |= byte((tagLen-2)/2) << 3
	flags |= byte(L - 1)

	b0[0] = flags
	copy(b0[1:], nonce)

	msgLen := len(plaintext)
	for i := 0; i < L; i++ {
		b0[aes.BlockSize-1-i] = byte(msgLen >> (8 * i))
	}

	mac := make([]byte, aes.BlockSize)
	block.Encrypt(mac, b0)

	if len(additionalData) > 0 {
		aadBlock := make([]byte, aes.BlockSize)
		binary.BigEndian.PutUint16(aadBlock[0:2], uint16(len(additionalData)))

		aadData := append(aadBlock[:2], additionalData...)
		if len(aadData)%aes.BlockSize != 0 {
			padding := aes.BlockSize - (len(aadData) % aes.BlockSize)
			aadData = append(aadData, make([]byte, padding)...)
		}

		tempBlock := make([]byte, aes.BlockSize)
		for i := 0; i < len(aadData); i += aes.BlockSize {
			xorBytes(tempBlock, mac, aadData[i:i+aes.BlockSize])
			block.Encrypt(mac, tempBlock)
		}
	}

	paddedPlaintext := plaintext
	if len(plaintext)%aes.BlockSize != 0 {
		padding := aes.BlockSize - (len(plaintext) % aes.BlockSize)
		paddedPlaintext = make([]byte, len(plaintext)+padding)
		copy(paddedPlaintext, plaintext)
	}

	tempBlock := make([]byte, aes.BlockSize)
	for i := 0; i < len(paddedPlaintext); i += aes.BlockSize {
		xorBytes(tempBlock, mac, paddedPlaintext[i:i+aes.BlockSize])
		block.Encrypt(mac, tempBlock)
	}

	return mac[:tagLen], nil
}

func encryptCCMCTR(block cipher.Block, nonce, data []byte, L int) []byte {
	result := make([]byte, len(data))
	counter := 1

	keyStream := make([]byte, aes.BlockSize)

	for i := 0; i < len(data); i += aes.BlockSize {
		ctrBlock := buildCCMCTRBlock(nonce, counter, L)
		block.Encrypt(keyStream, ctrBlock)

		end := i + aes.BlockSize
		if end > len(data) {
			end = len(data)
		}

		xorBytes(result[i:end], data[i:end], keyStream[:end-i])
		counter++
	}

	return result
}

func buildCCMCTRBlock(nonce []byte, counter, L int) []byte {
	block := make([]byte, aes.BlockSize)
	block[0] = byte(L - 1)
	copy(block[1:], nonce)

	for i := 0; i < L; i++ {
		block[aes.BlockSize-1-i] = byte(counter >> (8 * i))
	}

	return block
}
