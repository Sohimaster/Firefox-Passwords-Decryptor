package browser

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/pbkdf2"
)

var ckaId = []byte{248, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
var pkcs5Id = []int{1, 2, 840, 113549, 1, 5, 13}

type OID = asn1.ObjectIdentifier

type EncryptedData struct {
	EncryptionAlgo Algo
	Encrypted      []byte
}

type Algo struct {
	AlgoID OID
	Params PKCS5Params
}

type PKCS5Params struct {
	KDF    KDF
	Cipher CipherParams
}

type KDF struct {
	AlgoID OID
	Params PBKDF2Params
}

type PBKDF2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int `asn1:"optional"`
	PRF            asn1.RawValue
}

type CipherParams struct {
	Algo OID
	IV   []byte
}

func getHashedSalt(globalSalt []byte) []byte {
	hash := sha1.New()
	hash.Write(globalSalt)
	hash.Write([]byte{})
	return hash.Sum(nil)
}

func generatePBKDF2Key(hashedSalt []byte, params PBKDF2Params) []byte {
	return pbkdf2.Key(
		hashedSalt,
		params.Salt,
		int(params.IterationCount),
		int(params.KeyLength),
		sha256.New,
	)
}

func decryptAES(encryptedText, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	decryptedText := make([]byte, len(encryptedText))
	blockMode.CryptBlocks(decryptedText, encryptedText)
	return removePadding(decryptedText), nil
}

func decryptPBE(decodedItem EncryptedData, globalSalt []byte) ([]byte, error) {
	if Equal(decodedItem.EncryptionAlgo.AlgoID, pkcs5Id) {
		params := decodedItem.EncryptionAlgo.Params.KDF.Params
		hashedSalt := getHashedSalt(globalSalt)

		key := generatePBKDF2Key(hashedSalt, params)
		iv := append([]byte{0x04, 0x0e}, decodedItem.EncryptionAlgo.Params.Cipher.IV...)

		decryptedText, err := decryptAES(decodedItem.Encrypted, key, iv)
		if err != nil {
			return nil, err
		}

		return decryptedText, nil
	}

	return nil, errors.New("decryptPBE: unsupported algorithm")
}

func getDecryptionKey(dbPath string) ([]byte, error) {
	fmt.Println("Db path: ", dbPath)

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, errors.Wrap(err, "getDecryptionKey: cannot open db")
	}
	defer db.Close()

	var globalSalt []byte
	err = db.QueryRow("SELECT item1 FROM metadata WHERE id = 'password';").Scan(&globalSalt)
	if err != nil {
		return nil, errors.Wrap(err, "getDecryptionKey: cannot get global salt")
	}

	var a11, ckaIdValue []byte
	if err = db.QueryRow("SELECT a11,a102 FROM nssPrivate WHERE a11 IS NOT NULL LIMIT 1;").Scan(&a11, &ckaIdValue); err != nil {
		return nil, err
	}

	if !bytes.Equal(ckaIdValue, ckaId) {
		return nil, errors.New("getDecryptionKey: unsupported algorythm")
	}

	var decodedA11 EncryptedData
	if _, err := asn1.Unmarshal(a11, &decodedA11); err != nil {
		return nil, err
	}

	clearText, err := decryptPBE(decodedA11, globalSalt)
	if err != nil {
		return nil, err
	}
	return clearText[:24], nil
}

type jsonData struct {
	NextID int         `json:"nextId"`
	Logins []jsonLogin `json:"logins"`
}

type jsonLogin struct {
	ID                  int     `json:"id"`
	Hostname            string  `json:"hostname"`
	HttpRealm           *string `json:"httpRealm"`
	FormSubmitURL       *string `json:"formSubmitURL"`
	UsernameField       string  `json:"usernameField"`
	PasswordField       string  `json:"passwordField"`
	EncryptedUsername   string  `json:"encryptedUsername"`
	EncryptedPassword   string  `json:"encryptedPassword"`
	GUID                string  `json:"guid"`
	EncType             int     `json:"encType"`
	TimeCreated         int64   `json:"timeCreated"`
	TimeLastUsed        int64   `json:"timeLastUsed"`
	TimePasswordChanged int64   `json:"timePasswordChanged"`
	TimesUsed           int     `json:"timesUsed"`
}

type Login struct {
	encryptedUsername string
	encryptedPassword string
	Username          string
	Password          string
	URL               string
}

func getLoginsData(profile ProfilePath) ([]*Login, error) {
	filePath := filepath.Join(string(profile), "logins.json")
	file, err := os.Open(filePath)
	if err != nil {
		return nil, errors.Wrap(err, "getLoginsData: cannot open the file")
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, errors.Wrap(err, "getLoginsData: file does not exist")
	}

	fileContent := make([]byte, fileInfo.Size())

	if _, err = file.Read(fileContent); err != nil {
		return nil, errors.Wrap(err, "getLoginsData: error reading file")
	}

	var data jsonData
	if err = json.Unmarshal(fileContent, &data); err != nil {
		return nil, errors.Wrap(err, "getLoginsData: error unmarshaling JSON")
	}

	var logins []*Login
	for _, jLogin := range data.Logins {
		login := &Login{
			encryptedUsername: jLogin.EncryptedUsername,
			encryptedPassword: jLogin.EncryptedPassword,
			URL:               jLogin.Hostname,
		}
		logins = append(logins, login)
	}

	return logins, nil
}

func decodeLoginData(data string) (keyID, iv, ciphertext []byte, err error) {
	decodedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, nil, nil, err
	}

	var asn1Data struct {
		KeyID      []byte       `asn1:""`
		Cypher     CipherParams `asn1:""`
		Ciphertext []byte       `asn1:""`
	}

	_, err = asn1.Unmarshal(decodedData, &asn1Data)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "decodeLoginData: failed to unmarshal ASN.1 data")
	}

	return asn1Data.KeyID, asn1Data.Cypher.IV, asn1Data.Ciphertext, nil
}

func decryptData(keyId, iv, ciphertext []byte, key []byte) ([]byte, error) {
	if !bytes.Equal(keyId, ckaId) {
		return nil, errors.New("decryptData: key ID does not match ckaId")
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, "decryptData: error creating DES block")
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(decrypted, ciphertext)
	return decrypted, nil

}

func decryptCredentials(key []byte, login *Login) (*Login, error) {
	keyId, iv, ciphertext, err := decodeLoginData(login.encryptedUsername)
	if err != nil {
		return nil, errors.Wrap(err, "decryptCredentials: error decoding username")
	}

	decryptedUsername, err := decryptData(keyId, iv, ciphertext, key)
	if err != nil {
		return nil, errors.Wrap(err, "decryptCredentials: error decrypting username")
	}

	keyId, iv, ciphertext, err = decodeLoginData(login.encryptedPassword)
	if err != nil {
		return nil, errors.Wrap(err, "decryptCredentials: error decoding password")
	}

	decryptedPassword, err := decryptData(keyId, iv, ciphertext, key)
	if err != nil {
		return nil, errors.Wrap(err, "decryptCredentials: error decrypting password")
	}

	login.Username = string(removePadding(decryptedUsername))
	login.Password = string(removePadding(decryptedPassword))

	return login, nil
}

func GetPasswords(profile ProfilePath) ([]*Login, error) {
	logins, err := getLoginsData(profile)
	if err != nil {
		return nil, errors.Wrap(err, "GetPasswords: error getting logins")
	}

	keyDBPath := filepath.Join(string(profile), "key4.db")
	key, err := getDecryptionKey(keyDBPath)
	if err != nil {
		return nil, errors.Wrap(err, "GetPasswords: error getting key")
	}

	for i, login := range logins {
		login, err = decryptCredentials(key, login)
		if err != nil {
			return nil, errors.Wrap(err, "GetPasswords: error decrypting")
		}
		logins[i] = login
	}
	return logins, nil
}
