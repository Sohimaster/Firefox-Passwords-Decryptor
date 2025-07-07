package browser

import (
	"crypto/des"
	"encoding/hex"
	"fmt"
	"strings"
)

// ASN.1 type mapping for debugging
var asn1Types = map[byte]string{
	0x30: "SEQUENCE",
	0x06: "OID",
	0x04: "OCTET STRING",
	0x05: "NULL",
	0x02: "INTEGER",
}

// Known OID values for debugging
var oidValues = map[string]string{
	"2a864886f70d010c050103": "1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC",
	"2a864886f70d0307":       "1.2.840.113549.3.7 des-ede3-cbc",
	"2a864886f70d010101":     "1.2.840.113549.1.1.1 pkcs-1",
	"2a864886f70d01050d":     "1.2.840.113549.1.5.13 pkcs5 pbes2",
	"2a864886f70d01050c":     "1.2.840.113549.1.5.12 pkcs5 PBKDF2",
	"2a864886f70d0209":       "1.2.840.113549.2.9 hmacWithSHA256",
	"60864801650304012a":     "2.16.840.1.101.3.4.1.42 aes256-CBC",
}

// removePadding removes PKCS#7 padding from decrypted data
func removePadding(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	length := len(data)
	padding := int(data[length-1])

	// Validate padding
	if padding < 1 || padding > des.BlockSize || padding > length {
		return nil
	}

	// Check if all padding bytes are correct
	for i := 0; i < padding; i++ {
		if data[length-1-i] != byte(padding) {
			return nil
		}
	}

	return data[:length-padding]
}

// printASN1 prints ASN.1 structure in human-readable format (for debugging)
func printASN1(data []byte, maxLen, recursionLevel int) int {
	if len(data) < 2 {
		return 0
	}

	tag := data[0]
	length := data[1]

	var skip int
	if length&0x80 > 0 {
		length = data[2]
		skip = 1
	} else {
		skip = 0
	}

	indent := strings.Repeat("  ", recursionLevel)
	fmt.Printf("%s%s ", indent, asn1Types[tag])

	switch tag {
	case 0x30: // SEQUENCE
		fmt.Println("{")
		seqLen := int(length)
		readLen := 0
		for seqLen > 0 && readLen < len(data)-2-skip {
			consumedLen := printASN1(data[2+skip+readLen:], seqLen, recursionLevel+1)
			if consumedLen == 0 {
				break
			}
			seqLen -= consumedLen
			readLen += consumedLen
		}
		fmt.Printf("%s}\n", indent)
		return int(length) + 2 + skip

	case 0x06: // OID
		if 2+skip+int(length) > len(data) {
			return 0
		}
		oidHex := hex.EncodeToString(data[2+skip : 2+skip+int(length)])
		if value, exists := oidValues[oidHex]; exists {
			fmt.Println(value)
		} else {
			fmt.Printf("OID: %s\n", oidHex)
		}
		return int(length) + 2 + skip

	case 0x04: // OCTET STRING
		if 2+skip+int(length) > len(data) {
			return 0
		}
		fmt.Println(hex.EncodeToString(data[2+skip : 2+skip+int(length)]))
		return int(length) + 2 + skip

	case 0x05: // NULL
		fmt.Println("NULL")
		return int(length) + 2 + skip

	case 0x02: // INTEGER
		if 2+skip+int(length) > len(data) {
			return 0
		}
		fmt.Println(hex.EncodeToString(data[2+skip : 2+skip+int(length)]))
		return int(length) + 2 + skip

	default:
		// Handle unknown types
		if int(length) == maxLen-2 {
			return printASN1(data[2:], int(length), recursionLevel+1)
		}
	}

	return 0
}
