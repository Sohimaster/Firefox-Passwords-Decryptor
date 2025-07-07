package browser

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// Encryption constants
const (
	gcmIVLength  = 12 // AES-GCM uses 12-byte IV
	desBlockSize = 8  // 3DES block size
)

// hashSalt creates SHA1 hash of global salt for PBKDF2
func hashSalt(globalSalt []byte) []byte {
	hash := sha1.New()
	hash.Write(globalSalt)
	hash.Write([]byte{})
	return hash.Sum(nil)
}

// deriveKey generates PBKDF2 key from parameters
func deriveKey(hashedSalt []byte, params pbkdf2Parameters) []byte {
	return pbkdf2.Key(
		hashedSalt,
		params.Salt,
		params.IterationCount,
		params.KeyLength,
		sha256.New,
	)
}

// decryptAESCBC decrypts data using AES-CBC mode
func decryptAESCBC(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return removePadding(plaintext), nil
}

// decryptAESGCM decrypts data using AES-GCM mode (modern Firefox)
func decryptAESGCM(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("GCM decryption failed: %w", err)
	}

	return plaintext, nil
}

// decrypt3DESCBC decrypts data using 3DES-CBC mode (legacy Firefox)
func decrypt3DESCBC(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create 3DES cipher: %w", err)
	}

	if len(ciphertext)%desBlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return removePadding(plaintext), nil
}

// decryptPBES2 decrypts data using PBES2 scheme (NSS master key)
func decryptPBES2(data encryptedData, globalSalt []byte) ([]byte, error) {
	if !equalSlices(data.Algorithm.Algorithm, pkcs5AlgorithmID) {
		return nil, fmt.Errorf("unsupported encryption algorithm")
	}

	params := data.Algorithm.Parameters.KeyDerivation.Parameters
	hashedSalt := hashSalt(globalSalt)
	key := deriveKey(hashedSalt, params)

	// Construct IV with magic bytes (NSS specific)
	iv := append([]byte{0x04, 0x0e}, data.Algorithm.Parameters.Encryption.IV...)

	return decryptAESCBC(data.Ciphertext, key, iv)
}

// equalSlices compares two slices of integers
func equalSlices(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
