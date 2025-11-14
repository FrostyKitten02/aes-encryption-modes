package modes

import (
	"crypto/aes"
	"crypto/cipher"
	"math"
)

// []byte("1234567890123456")
func AesEncryptECB(data []byte, key []byte) []byte {
	ciph, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	dataLen := len(data)
	blockSize := aes.BlockSize
	blocks := int(math.Ceil(float64(dataLen) / float64(blockSize))) //TODO fix, this is too much
	dst := make([]byte, blocks*blockSize)                           //not same as datalen since we have to pad it
	for i := 0; i < blocks; i++ {

	}
}
