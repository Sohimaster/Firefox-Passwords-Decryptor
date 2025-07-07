package browser

import (
	"bytes"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

// Constants for Firefox password encryption
var (
	// CKA_ID for Firefox NSS database identification
	ckaID = []byte{248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	// PKCS5 algorithm identifier for PBES2
	pkcs5AlgorithmID = []int{1, 2, 840, 113549, 1, 5, 13}
	// Magic bytes for new Firefox format (v58+)
	newFormatMagic = "v10"
)

// ExtractPasswords extracts all passwords from a Firefox profile
func ExtractPasswords(profilePath string) ([]*Credential, error) {
	// Load login data from logins.json
	logins, err := loadLoginData(profilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load login data: %w", err)
	}

	// Extract master key from NSS database
	keyDBPath := filepath.Join(profilePath, "key4.db")
	masterKey, err := extractMasterKey(keyDBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to extract master key: %w", err)
	}

	// Decrypt all credentials
	var credentials []*Credential
	for i, login := range logins {
		cred, err := decryptCredential(login, masterKey)
		if err != nil {
			fmt.Printf("Warning: failed to decrypt login %d (%s): %v\n", i, login.Hostname, err)
			continue
		}
		credentials = append(credentials, cred)
	}

	return credentials, nil
}

// loadLoginData reads and parses the logins.json file
func loadLoginData(profilePath string) ([]login, error) {
	filePath := filepath.Join(profilePath, "logins.json")

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open logins file: %w", err)
	}
	defer file.Close()

	var data loginData
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to parse logins JSON: %w", err)
	}

	return data.Logins, nil
}

// extractMasterKey retrieves the master decryption key from NSS database
func extractMasterKey(dbPath string) ([]byte, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open NSS database: %w", err)
	}
	defer db.Close()

	// Get global salt
	var globalSalt []byte
	query := "SELECT item1 FROM metadata WHERE id = 'password'"
	if err := db.QueryRow(query).Scan(&globalSalt); err != nil {
		return nil, fmt.Errorf("failed to retrieve global salt: %w", err)
	}

	// Get encrypted private key
	var privateKeyData, keyID []byte
	query = "SELECT a11, a102 FROM nssPrivate WHERE a11 IS NOT NULL LIMIT 1"
	if err := db.QueryRow(query).Scan(&privateKeyData, &keyID); err != nil {
		return nil, fmt.Errorf("failed to retrieve private key: %w", err)
	}

	// Verify key ID
	if !bytes.Equal(keyID, ckaID) {
		return nil, fmt.Errorf("unsupported key algorithm")
	}

	// Decrypt private key
	var encData encryptedData
	if _, err := asn1.Unmarshal(privateKeyData, &encData); err != nil {
		return nil, fmt.Errorf("failed to parse private key ASN.1: %w", err)
	}

	masterKey, err := decryptPBES2(encData, globalSalt)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt master key: %w", err)
	}

	// Return first 24 bytes (3DES key length)
	if len(masterKey) < 24 {
		return nil, fmt.Errorf("master key too short")
	}

	return masterKey[:24], nil
}

// decryptCredential decrypts both username and password for a login entry
func decryptCredential(l login, masterKey []byte) (*Credential, error) {
	// Decrypt username
	keyID, iv, ciphertext, err := parseLoginField(l.EncryptedUsername)
	if err != nil {
		return nil, fmt.Errorf("failed to parse username: %w", err)
	}

	username, err := decryptLoginField(keyID, iv, ciphertext, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt username: %w", err)
	}

	// Decrypt password
	keyID, iv, ciphertext, err = parseLoginField(l.EncryptedPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to parse password: %w", err)
	}

	password, err := decryptLoginField(keyID, iv, ciphertext, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt password: %w", err)
	}

	return &Credential{
		Username: string(username),
		Password: string(password),
		URL:      l.Hostname,
	}, nil
}

// parseLoginField decodes base64 login field and extracts encryption parameters
func parseLoginField(data string) (keyID, iv, ciphertext []byte, err error) {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Check for new format (Firefox 58+)
	if len(decoded) >= 3 && string(decoded[:3]) == newFormatMagic {
		return parseNewFormat(decoded)
	}

	// Parse old ASN.1 format
	return parseASN1Format(decoded)
}

// parseNewFormat handles the new Firefox encryption format (v58+)
func parseNewFormat(data []byte) (keyID, iv, ciphertext []byte, err error) {
	minLength := 3 + 16 + 12 // magic + keyID + IV
	if len(data) < minLength {
		return nil, nil, nil, fmt.Errorf("invalid new format data length")
	}

	keyID = data[3:19]     // 16 bytes
	iv = data[19:31]       // 12 bytes for AES-GCM
	ciphertext = data[31:] // remaining bytes

	return keyID, iv, ciphertext, nil
}

// parseASN1Format handles the old ASN.1 Firefox encryption format
func parseASN1Format(data []byte) (keyID, iv, ciphertext []byte, err error) {
	var asn1Data loginASN1
	if _, err := asn1.Unmarshal(data, &asn1Data); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse ASN.1: %w", err)
	}

	return asn1Data.KeyID, asn1Data.Encryption.IV, asn1Data.Ciphertext, nil
}

// decryptLoginField decrypts a single login field (username or password)
func decryptLoginField(keyID, iv, ciphertext, masterKey []byte) ([]byte, error) {
	if !bytes.Equal(keyID, ckaID) {
		return nil, fmt.Errorf("key ID mismatch")
	}

	// Use AES-GCM for new format (12-byte IV)
	if len(iv) == gcmIVLength {
		return decryptAESGCM(ciphertext, masterKey, iv)
	}

	// Use 3DES-CBC for old format
	return decrypt3DESCBC(ciphertext, masterKey, iv)
}
