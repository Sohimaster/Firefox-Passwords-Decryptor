package browser

import "encoding/asn1"

// Credential represents a decrypted login entry
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
}

// NSS database structures for PKCS#5 encryption
type (
	encryptedData struct {
		Algorithm  algorithmIdentifier
		Ciphertext []byte
	}

	algorithmIdentifier struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters pkcs5Parameters
	}

	pkcs5Parameters struct {
		KeyDerivation keyDerivationFunc
		Encryption    encryptionScheme
	}

	keyDerivationFunc struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters pbkdf2Parameters
	}

	pbkdf2Parameters struct {
		Salt           []byte
		IterationCount int
		KeyLength      int `asn1:"optional"`
		PRF            asn1.RawValue
	}

	encryptionScheme struct {
		Algorithm asn1.ObjectIdentifier
		IV        []byte
	}
)

// Firefox login JSON structures
type (
	loginData struct {
		NextID int     `json:"nextId"`
		Logins []login `json:"logins"`
	}

	login struct {
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
)

// ASN.1 structure for old Firefox login encryption format
type loginASN1 struct {
	KeyID      []byte           `asn1:""`
	Encryption encryptionScheme `asn1:""`
	Ciphertext []byte           `asn1:""`
}
