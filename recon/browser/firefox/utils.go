package browser

import (
	"crypto/des"
	"encoding/hex"
	"fmt"
	"strings"
)

var asn1Types = map[byte]string{
	0x30: "SEQUENCE",
	0x06: "OID",
	0x04: "OCTETSTRING",
	0x05: "NULL",
	0x02: "INTEGER",
}

var oidValues = map[string]string{
	"2a864886f70d010c050103": "1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC",
	"2a864886f70d0307":       "1.2.840.113549.3.7 des-ede3-cbc",
	"2a864886f70d010101":     "1.2.840.113549.1.1.1 pkcs-1",
	"2a864886f70d01050d":     "1.2.840.113549.1.5.13 pkcs5 pbes2",
	"2a864886f70d01050c":     "1.2.840.113549.1.5.12 pkcs5 PBKDF2",
	"2a864886f70d0209":       "1.2.840.113549.2.9 hmacWithSHA256",
	"60864801650304012a":     "2.16.840.1.101.3.4.1.42 aes256-CBC",
}

func Equal(a, b []int) bool {
	// Compares two slices of ints
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

func printASN1(d []byte, l, rl int) int {
	// Decoded bytes into human readable ASN.1 structure.

	typ := d[0]
	length := d[1]

	var skip int
	if length&0x80 > 0 {
		length = d[2]
		skip = 1
	} else {
		skip = 0
	}

	fmt.Printf("%s%s ", strings.Repeat("  ", rl), asn1Types[typ])

	switch typ {
	case 0x30:
		fmt.Println("{")
		seqLen := int(length)
		readLen := 0
		for seqLen > 0 {
			len2 := printASN1(d[2+skip+readLen:], seqLen, rl+1)
			seqLen -= len2
			readLen += len2
		}
		fmt.Printf("%s}\n", strings.Repeat("  ", rl))
		return int(length) + 2
	case 0x06:
		oidVal := hex.EncodeToString(d[2 : 2+length])
		if value, ok := oidValues[oidVal]; ok {
			fmt.Println(value)
		} else {
			fmt.Printf("oid? %s\n", oidVal)
		}
		return int(length) + 2
	case 0x04:
		fmt.Println(hex.EncodeToString(d[2 : 2+length]))
		return int(length) + 2
	case 0x05:
		fmt.Println(0)
		return int(length) + 2
	case 0x02:
		fmt.Println(hex.EncodeToString(d[2 : 2+length]))
		return int(length) + 2
	default:
		if int(length) == l-2 {
			printASN1(d[2:], int(length), rl+1)
			return int(length)
		}
	}

	return 0
}

func removePadding(data []byte) []byte {
	// Gets rid of extra bytes in a decrypted bite slice
	length := len(data)
	padding := int(data[length-1])

	if padding < 1 || padding > des.BlockSize {
		return nil
	}

	for i := 0; i < padding; i++ {
		if data[length-1-i] != byte(padding) {
			return nil
		}
	}

	return data[:length-padding]
}
