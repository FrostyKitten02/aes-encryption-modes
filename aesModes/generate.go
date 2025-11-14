package aesModes

import (
	"crypto/aes"
	"math/rand"
)

func GenerateIv() string {
	return generateRandomBytesString(aes.BlockSize)
}

func GenerateKey() string {
	return generateRandomBytesString(aes.BlockSize)
}

func generateRandomBytesString(length int) string {
	charset := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+<>/?")

	result := make([]rune, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}
