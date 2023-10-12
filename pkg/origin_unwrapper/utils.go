package origin_unwrapper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
)

const CIPHER_TAG = "<CipherKey>"
const BASE64_16_LEN = 24

var DLF_KEY = []byte{
	65, 50, 114, 45, 208, 130, 239, 176, 220, 100, 87, 197, 118, 104, 202, 9,
}

var IV = make([]byte, 16)

func AESEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func AESDecrypt(key []byte, iv []byte, buf []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(iv) != aes.BlockSize {
		return nil, err
	}

	if len(buf) < aes.BlockSize {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(buf, buf)

	return buf, nil
}

func AESDecryptBase64(keyBase64 string, iv []byte, buf []byte) error {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return fmt.Errorf("Error: invalid base64 key\n")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	if len(iv) != aes.BlockSize {
		return fmt.Errorf("Error: invalid IV size\n")
	}

	if len(buf) < aes.BlockSize {
		return fmt.Errorf("Error: invalid buffer size\n")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(buf, buf)

	return nil
}

func DecryptDLF(data []byte) ([]byte, error) {
	decrypted, err := AESDecrypt(DLF_KEY, data[0x41:], []byte{0})
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func GetDLFAuto(contentID string) ([]byte, error) {
	paths := []string{
		contentID + ".dlf",
		contentID + "_cached.dlf",
	}

	for _, path := range paths {
		data, err := readFile(path)
		if err == nil {
			return DecryptDLF(data)
		}
	}

	return nil, fmt.Errorf("Error: DLF file not found\n")
}

func DecodeCipherTag(dlf []byte) ([]byte, error) {
	stringData := string(dlf)
	pos := strings.Index(stringData, CIPHER_TAG)
	if pos == -1 {
		return nil, fmt.Errorf("Error: Cipher tag not found\n")
	}

	pos += len(CIPHER_TAG)
	base64Data := stringData[pos : pos+BASE64_16_LEN]
	decoded, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, err
	}

	if len(decoded) > 16 {
		decoded = decoded[:16]
	}

	return decoded, nil
}

func readFile(filename string) ([]byte, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return file, nil
}
